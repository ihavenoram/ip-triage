<#
    IP-Triage - public IP and domain lookup tool (WinForms, PS 5.1)
    -------------------------------------------------------------------
    Paste a public IP (from an alert, a log, a firewall entry - anywhere) and
    identify the business /
    network behind it (customer, our own range, or an outside source), plus what
    services answer on it for our own troubleshooting.

      * Passive lookups run by default (reverse DNS, ASN, RDAP, geo, reverse-IP,
        domain registration). All keyless.
      * Active service probing is opt-in, read-only, and limited to common
        service ports - it reads the banner/headers/certificate a service already
        offers, then closes. Only probe IPs you own or are authorised to test.

    Launch via Launch-IP-Triage.cmd (forces -STA, required for WinForms).
    No admin required.
#>
[CmdletBinding()]
param(
    [string]$Ip = '',
    [switch]$AutoRun,
    [switch]$Probe,
    [switch]$NoClipboard,
    [string]$KnownRanges = '',
    [string]$ExpectedCountries = '',
    [string]$SelfTestPng = '',
    [string]$SelfTestTab = '',
    [string]$SelfTestDnsDomain = ''
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
# Both of these are process-wide one-shots. Running the script a second time in
# the SAME PowerShell session (rather than via Launch-IP-Triage.cmd, which starts a
# fresh process) throws "SetCompatibleTextRenderingDefault must be called before
# the first IWin32Window object is created". They only affect text rendering, so
# a failure on the second run is harmless - swallow it rather than refusing to
# start.
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch {}
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}

# ---------------------------------------------------------------------------
# Resolve script-relative paths in the body ([CmdletBinding] empties
# $PSScriptRoot inside param defaults on PS 5.1).
# ---------------------------------------------------------------------------
$ScriptDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($ScriptDir)) { $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

$HelpersPath = Join-Path $ScriptDir 'IP-Triage.Helpers.ps1'
if (-not (Test-Path -LiteralPath $HelpersPath)) {
    [void][System.Windows.Forms.MessageBox]::Show(
        ('Cannot find {0}.' + [Environment]::NewLine + [Environment]::NewLine +
         'It must sit in the same folder as IP-Triage.ps1.') -f $HelpersPath,
        'IP Triage', 'OK', 'Error')
    return
}
$HelpersSource = Get-Content -LiteralPath $HelpersPath -Raw

# The DNS / mail checks live in their own file (the helpers file is already
# large). Both are concatenated into the one source string that gets dot-sourced
# into the UI thread and injected into every runspace, so there is still a single
# definition of everything and no worker signature changes.
$DnsPath = Join-Path $ScriptDir 'IP-Triage.Dns.ps1'
if (Test-Path -LiteralPath $DnsPath) {
    $HelpersSource = $HelpersSource + [Environment]::NewLine + (Get-Content -LiteralPath $DnsPath -Raw)
} else {
    [void][System.Windows.Forms.MessageBox]::Show(
        ('Cannot find {0}. The DNS / MX tab will not work.' -f $DnsPath),
        'IP Triage', 'OK', 'Warning')
}
. ([scriptblock]::Create($HelpersSource))

# Our own customer / owned ranges, and the countries we expect to see. Both are
# overridable from the command line. The API key is NOT read from here - see
# Get-AbuseIpdbKey (env var or %APPDATA%), because the script folder may be synced or shared.
$script:knownRangesPath = $KnownRanges
if (-not $script:knownRangesPath) { $script:knownRangesPath = Join-Path $ScriptDir 'KnownRanges.csv' }
# NOTE the name: it must NOT be $script:expectedCountries. PowerShell variable
# names are case-insensitive, so that would be the same variable as the
# [string]$ExpectedCountries parameter above - and its type constraint would
# quietly coerce this array back into one space-joined string ("AU NZ PH"),
# after which no country ever matches. Test-IPTriage.ps1 gates against this.
$script:expectedCountryList = @($ExpectedCountries -split '[,;]' | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ })

# ---------------------------------------------------------------------------
# Background worker - all lookups run off the UI thread and report through a
# synchronized hashtable ($Shared).
# ---------------------------------------------------------------------------
$WorkerScript = {
    param($Shared, $HelpersSource, $TargetIp, $DoOnline, $DoProbe, $InputHost,
          $KnownRangesPath, $AbuseKey, $ExpectedCountries)

    . ([scriptblock]::Create($HelpersSource))
    function WriteLog($m) { [void]$Shared.Log.Add(('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $m)) }
    function Stopping { return [bool]$Shared.Cancel }
    # Records a candidate name with the source it came from (first source wins).
    function AddName($TheName, $Source) {
        if ([string]::IsNullOrWhiteSpace($TheName)) { return }
        $key = $TheName.Trim().ToLower()
        [void]$candidateNames.Add($key)
        if (-not $nameSource.ContainsKey($key)) { $nameSource[$key] = $Source }
    }

    try {
        try {
            [System.Net.ServicePointManager]::SecurityProtocol =
                [System.Net.SecurityProtocolType]::Tls12 -bor
                [System.Net.SecurityProtocolType]::Tls11 -bor
                [System.Net.SecurityProtocolType]::Tls
        } catch {}
        # Deliberately NO process-wide ServerCertificateValidationCallback here. It used
        # to be set to { $true }, which (1) disabled certificate checks for every HTTPS
        # lookup - including the one carrying the AbuseIPDB key - and (2) left a
        # scriptblock bound to this runspace as an AppDomain-wide callback, so any HTTPS
        # call made on the UI thread after a lookup (the API key dialog's Test button)
        # failed with "no response". The service probe accepts any certificate through
        # its own per-connection SslStream callbacks, which is all it needs.

        $evidence = [System.Collections.Generic.List[object]]::new()
        $candidateNames = [System.Collections.Generic.List[string]]::new()
        $nameSource = @{}

        # ---- 1. Classify input ------------------------------------------------
        $Shared.Status = 'Classifying address...'; $Shared.Progress = 3
        $ipClass = Get-IpClass $TargetIp
        $Shared.IpClass = $ipClass.Class
        WriteLog ('Target {0} classified as {1}' -f $TargetIp, $ipClass.Class)
        # A hostname was typed instead of an IP - keep it as a domain candidate
        # so it gets resolved, registered-domain reduced and WHOIS'd like any
        # other name found on the address.
        if ($InputHost) {
            AddName $InputHost 'Input'
            WriteLog ('Input hostname {0} resolved to {1}' -f $InputHost, $TargetIp)
        }

        # ---- 1b. Our own known ranges (offline, before any lookup) ------------
        $known = Get-KnownRangeMatch -Ip $TargetIp -CsvPath $KnownRangesPath
        $Shared.KnownMatch = $known
        if ($known.Matched) {
            WriteLog ('KNOWN RANGE: {0} - {1} (matched {2})' -f $known.Type, $known.Label, $known.Range)
        } elseif ($known.Error) {
            WriteLog ('Known ranges: {0}' -f $known.Error)
        }
        if (-not $ipClass.IsPublic) {
            WriteLog ('{0} is not a public address - online lookups skipped.' -f $ipClass.Class)
        }

        # Compare against our own public IP (best effort).
        if ($DoOnline -and $ipClass.IsPublic) {
            $mine = Get-PublicIp
            if ($mine) {
                $Shared.OwnPublicIp = $mine
                if ($mine -eq $TargetIp) { WriteLog 'NOTE: this is THIS machine''s own public IP.' }
            }
        }

        # ---- 2. Reverse DNS ---------------------------------------------------
        if (Stopping) { $Shared.Cancel = $true; return }
        $Shared.Status = 'Reverse DNS...'; $Shared.Progress = 10
        $ptr = @(Get-PtrRecord $TargetIp)
        $Shared.Ptr = $ptr
        if (@($ptr).Count -gt 0) {
            WriteLog ('PTR: {0}' -f ($ptr -join ', '))
            foreach ($p in $ptr) {
                AddName $p 'PTR'
                $generic = Test-GenericPtr $p $TargetIp
                if (-not $generic) { [void]$evidence.Add([pscustomobject]@{ Field='cert'; Value=$p; Port='' }) }
                $Shared.PtrGeneric = $generic
            }
        } else { WriteLog 'PTR: none' }

        if ($DoOnline -and $ipClass.IsPublic) {
            # ---- 3. ASN (Team Cymru) -----------------------------------------
            if (Stopping) { $Shared.Cancel = $true; return }
            $Shared.Status = 'ASN (Team Cymru)...'; $Shared.Progress = 18
            $asn = Get-AsnInfo $TargetIp
            $Shared.Asn = $asn
            if ($asn.Asn) { WriteLog ('ASN: AS{0} {1} ({2}, {3})' -f $asn.Asn, $asn.AsName, $asn.Prefix, $asn.Country) }

            # ---- 4. RDAP IP ---------------------------------------------------
            if (Stopping) { $Shared.Cancel = $true; return }
            $Shared.Status = 'RDAP (network owner)...'; $Shared.Progress = 28
            $rdap = Get-RdapIp $TargetIp
            $Shared.Rdap = $rdap
            if ($rdap.Name) { WriteLog ('RDAP netname: {0} [{1} - {2}]' -f $rdap.Name, $rdap.StartAddress, $rdap.EndAddress) }

            # ---- 5. Geo / org -------------------------------------------------
            if (Stopping) { $Shared.Cancel = $true; return }
            $Shared.Status = 'Geolocation...'; $Shared.Progress = 34
            $geo = Get-IpGeo $TargetIp
            $Shared.Geo = $geo
            if ($geo.Org) { WriteLog ('Geo: {0} - {1}, {2} {3}' -f $geo.Org, $geo.City, $geo.Region, $geo.Country) }
            if ($geo.Limited) { WriteLog 'ipinfo.io rate-limited (429) - geo partial.' }

            $Shared.NetworkReady = $true

            # ---- 6. Shodan InternetDB (passive) ------------------------------
            if (Stopping) { $Shared.Cancel = $true; return }
            $Shared.Status = 'Shodan InternetDB (passive)...'; $Shared.Progress = 40
            $idb = Get-InternetDb $TargetIp
            $Shared.InternetDb = $idb
            if ($idb.Found) {
                WriteLog ('InternetDB: ports {0}; tags {1}' -f (@($idb.Ports) -join ','), (@($idb.Tags) -join ','))
                foreach ($h in @($idb.Hostnames)) { AddName $h 'Shodan' }
                foreach ($t in @($idb.Tags)) { [void]$evidence.Add([pscustomobject]@{ Field='tag'; Value=$t; Port='' }) }
                foreach ($c in @($idb.Cpes)) { [void]$evidence.Add([pscustomobject]@{ Field='cert'; Value=$c; Port='' }) }
            }

            # ---- 7. Tor exit check -------------------------------------------
            if (Stopping) { $Shared.Cancel = $true; return }
            $Shared.Status = 'Reputation (Tor)...'; $Shared.Progress = 44
            try {
                $tor = Get-TorExitList
                $Shared.IsTorExit = $tor.Contains($TargetIp)
                if ($Shared.IsTorExit) { WriteLog 'REPUTATION: listed as a Tor exit node.' }
            } catch {}

            # ---- 7b. AbuseIPDB reputation (only when a key is configured) ----
            if (Stopping) { $Shared.Cancel = $true; return }
            if ($AbuseKey) {
                $Shared.Status = 'Reputation (AbuseIPDB)...'; $Shared.Progress = 47
                $abuse = Get-AbuseIpdb -Ip $TargetIp -ApiKey $AbuseKey
                $Shared.Abuse = $abuse
                if ($abuse.Available) {
                    WriteLog ('AbuseIPDB: confidence {0}%, {1} report(s), usage "{2}"' -f $abuse.Score, $abuse.TotalReports, $abuse.UsageType)
                } else {
                    WriteLog ('AbuseIPDB: not available ({0})' -f $abuse.Error)
                }
            } else {
                $Shared.Abuse = [pscustomobject]@{
                    Available = $false; Score = 0; TotalReports = 0; LastReported = ''
                    UsageType = ''; IsTor = $false; IsWhitelisted = $false; Error = 'no key configured'
                }
                WriteLog 'AbuseIPDB: skipped (no API key configured).'
            }

            # ---- 8. Reverse IP (hosted domains) ------------------------------
            if (Stopping) { $Shared.Cancel = $true; return }
            $Shared.Status = 'Reverse-IP (hosted domains)...'; $Shared.Progress = 50
            $rip = Get-ReverseIpDomains $TargetIp
            $Shared.ReverseIp = $rip
            if ($rip.Limited) { WriteLog ('Reverse-IP: rate-limited - {0}' -f $rip.Note) }
            elseif (@($rip.Names).Count -gt 0) {
                WriteLog ('Reverse-IP: {0} name(s)' -f @($rip.Names).Count)
                foreach ($n in @($rip.Names)) { AddName $n 'Reverse-IP' }
            }
        }

        # ---- 9. Active probe (opt-in) ----------------------------------------
        $probeResults = [System.Collections.Generic.List[object]]::new()
        $certResults = [System.Collections.Generic.List[object]]::new()
        if ($DoProbe -and $ipClass.IsPublic) {
            $Shared.Status = 'Probing services...'; $Shared.Progress = 55
            $portDefs = @(Get-ProbePortDefs)
            # Fold in any extra ports InternetDB already reported.
            $known = @($portDefs | ForEach-Object { $_.Port })
            if ($Shared.InternetDb -and $Shared.InternetDb.Found) {
                foreach ($ep in @($Shared.InternetDb.Ports)) {
                    if ($known -notcontains [int]$ep) {
                        $portDefs += [pscustomobject]@{ Port=[int]$ep; Name=('Port ' + $ep); Kind='banner' }
                    }
                }
            }
            $total = @($portDefs).Count
            $done = 0
            foreach ($pd in $portDefs) {
                if (Stopping) { $Shared.Cancel = $true; break }
                $done++
                $Shared.Status = ('Probing {0}/{1}: port {2} ({3})...' -f $done, $total, $pd.Port, $pd.Name)
                $Shared.Progress = 55 + [int](30 * $done / $total)
                $st = Test-TcpPortState -ComputerName $TargetIp -Port $pd.Port -TimeoutMs 3000
                $row = [pscustomobject]@{
                    Port = $pd.Port; Service = $pd.Name; State = $st.State; LatencyMs = $st.LatencyMs
                    Banner = ''; Server = ''; Title = ''; Detail = ''
                }
                if ($st.State -eq 'Open') {
                    [void]$evidence.Add([pscustomobject]@{ Field='port'; Value=[string]$pd.Port; Port=$pd.Port })
                    switch ($pd.Kind) {
                        'banner' {
                            $b = Read-TcpBanner -ComputerName $TargetIp -Port $pd.Port
                            $row.Banner = Get-Truncated $b 200
                            if ($b) { [void]$evidence.Add([pscustomobject]@{ Field='banner'; Value=$b; Port=$pd.Port }) }
                        }
                        'http' {
                            $h = Invoke-HttpProbe -ComputerName $TargetIp -Port $pd.Port -UseTls $false
                            $row.Server = $h.Server; $row.Title = Get-Truncated $h.Title 120
                            $row.Detail = $h.Headers
                            if ($h.Location) { AddName (Get-HostFromUrl $h.Location) 'Redirect' }
                            if ($h.Server) { [void]$evidence.Add([pscustomobject]@{ Field='server'; Value=$h.Server; Port=$pd.Port }) }
                            if ($h.Title)  { [void]$evidence.Add([pscustomobject]@{ Field='title';  Value=$h.Title;  Port=$pd.Port }) }
                        }
                        { $_ -eq 'https' -or $_ -eq 'tls' } {
                            $cert = Get-TlsCertInfo -ComputerName $TargetIp -Port $pd.Port
                            if ($cert) {
                                [void]$certResults.Add([pscustomobject]@{
                                    Port=$pd.Port; Subject=$cert.Subject; Sans=$cert.Sans; Issuer=$cert.Issuer
                                    NotAfter=$cert.NotAfter; SelfSigned=$cert.SelfSigned; Protocol=$cert.Protocol
                                })
                                $row.Detail = ('Subject: {0}{1}Issuer: {2}{1}SANs: {3}{1}TLS: {4}  SelfSigned: {5}' -f `
                                    $cert.Subject, [Environment]::NewLine, $cert.Issuer, $cert.Sans, $cert.Protocol, $cert.SelfSigned)
                                [void]$evidence.Add([pscustomobject]@{ Field='cert'; Value=($cert.Subject + ' ' + $cert.Issuer); Port=$pd.Port })
                                foreach ($cn in (Get-NamesFromCert $cert)) { AddName $cn 'Certificate' }
                            }
                            if ($_ -eq 'https') {
                                $h = Invoke-HttpProbe -ComputerName $TargetIp -Port $pd.Port -UseTls $true
                                if ($h.Ok) {
                                    $row.Server = $h.Server; $row.Title = Get-Truncated $h.Title 120
                                    if ($row.Detail) { $row.Detail = $row.Detail + [Environment]::NewLine + [Environment]::NewLine + $h.Headers } else { $row.Detail = $h.Headers }
                                    if ($h.Server) { [void]$evidence.Add([pscustomobject]@{ Field='server'; Value=$h.Server; Port=$pd.Port }) }
                                    if ($h.Title)  { [void]$evidence.Add([pscustomobject]@{ Field='title';  Value=$h.Title;  Port=$pd.Port }) }
                                }
                            }
                        }
                        'rdp' {
                            $cert = Get-TlsCertInfo -ComputerName $TargetIp -Port $pd.Port
                            if ($cert) {
                                [void]$certResults.Add([pscustomobject]@{
                                    Port=$pd.Port; Subject=$cert.Subject; Sans=$cert.Sans; Issuer=$cert.Issuer
                                    NotAfter=$cert.NotAfter; SelfSigned=$cert.SelfSigned; Protocol=$cert.Protocol
                                })
                                $row.Detail = ('RDP cert subject: {0} (usually the host name){1}TLS: {2}' -f $cert.Subject, [Environment]::NewLine, $cert.Protocol)
                                foreach ($cn in (Get-NamesFromCert $cert)) { AddName $cn 'Certificate' }
                            }
                        }
                        default { }
                    }
                }
                [void]$probeResults.Add($row)
                $Shared.Probe = @($probeResults.ToArray())
                $Shared.Certs = @($certResults.ToArray())
                $Shared.ProbeVersion = [int]$Shared.ProbeVersion + 1
                $Shared.ProbeReady = $true
            }
            $openCount = @($probeResults | Where-Object { $_.State -eq 'Open' }).Count
            WriteLog ('Probe complete: {0} open of {1} port(s) tested.' -f $openCount, $total)
        }

        # ---- 10. Domain registration -----------------------------------------
        if (Stopping) { $Shared.Cancel = $true; return }
        $Shared.Status = 'Domain registration...'; $Shared.Progress = 88
        $names = @($candidateNames.ToArray() | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLower() } | Select-Object -Unique)
        if (@($names).Count -gt 30) { $names = @($names)[0..29] }
        $domainRows = [System.Collections.Generic.List[object]]::new()
        $regDomains = [System.Collections.Generic.List[string]]::new()
        foreach ($nm in $names) {
            $reg = Get-RegisteredDomain $nm
            $pointsHere = $false; $resolvesTo = ''
            try {
                $addrs = [System.Net.Dns]::GetHostAddresses($nm) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
                if ($addrs) { $resolvesTo = (@($addrs) | ForEach-Object { $_.IPAddressToString }) -join ', '; if ($resolvesTo -match [regex]::Escape($TargetIp)) { $pointsHere = $true } }
            } catch {}
            $src = ''; if ($nameSource.ContainsKey($nm)) { $src = $nameSource[$nm] }
            [void]$domainRows.Add([pscustomobject]@{
                Name = $nm; Source = $src; RegDomain = $reg; ResolvesTo = $resolvesTo; PointsHere = $pointsHere
            })
            if ($reg -and $regDomains -notcontains $reg) { [void]$regDomains.Add($reg) }
        }
        $Shared.Domains = @($domainRows.ToArray())
        $Shared.DomainsReady = $true

        # Registration lookups (org-level), capped.
        $regRows = [System.Collections.Generic.List[object]]::new()
        $regList = @($regDomains.ToArray())
        if (@($regList).Count -gt 10) { $regList = @($regList)[0..9] }
        if ($DoOnline) {
            $rd = 0
            foreach ($dom in $regList) {
                if (Stopping) { $Shared.Cancel = $true; break }
                $rd++
                $Shared.Status = ('Registration {0}/{1}: {2}...' -f $rd, @($regList).Count, $dom)
                $reg = Get-DomainRegistration $dom
                [void]$regRows.Add($reg)
                if ($reg.RegistrantOrg) { WriteLog ('{0}: registrant {1}' -f $dom, $reg.RegistrantOrg) }
                $Shared.Registrations = @($regRows.ToArray())
                $Shared.RegistrationsReady = $true
            }
        }
        # Attach registrant org back onto the domain rows.
        $regMap = @{}
        foreach ($r in @($regRows.ToArray())) { $regMap[$r.Domain] = $r }
        $enriched = [System.Collections.Generic.List[object]]::new()
        foreach ($drow in @($domainRows.ToArray())) {
            $org = ''; $registrar = ''
            if ($drow.RegDomain -and $regMap.ContainsKey($drow.RegDomain)) {
                $org = $regMap[$drow.RegDomain].RegistrantOrg
                $registrar = $regMap[$drow.RegDomain].Registrar
            }
            [void]$enriched.Add([pscustomobject]@{
                Name=$drow.Name; Source=$drow.Source; RegDomain=$drow.RegDomain; ResolvesTo=$drow.ResolvesTo
                PointsHere=$drow.PointsHere; RegistrantOrg=$org; Registrar=$registrar
            })
        }
        $Shared.Domains = @($enriched.ToArray())
        $Shared.DomainsVersion = [int]$Shared.DomainsVersion + 1

        # ---- 11. Fingerprint + summary ---------------------------------------
        if (Stopping) { $Shared.Cancel = $true; return }
        $Shared.Status = 'Fingerprinting...'; $Shared.Progress = 95
        $fp = Invoke-Fingerprint -Evidence @($evidence.ToArray()) -Signatures (Get-SignatureTable)
        $Shared.Fingerprint = $fp
        $Shared.EvidenceReady = $true

        # ---- 11b. Country / network kind / risk -------------------------------
        $regCountry = ''
        if ($Shared.Rdap -and $Shared.Rdap.Country) { $regCountry = $Shared.Rdap.Country }
        elseif ($Shared.Asn -and $Shared.Asn.Country) { $regCountry = $Shared.Asn.Country }
        $geoCountry = ''
        if ($Shared.Geo -and $Shared.Geo.Country) { $geoCountry = $Shared.Geo.Country }
        # An empty list means "not configured": Get-CountryVerdict then shows the
        # country without judging it. -ExpectedCountries turns the check on.
        $expected = @($ExpectedCountries | Where-Object { $_ })
        if (@($expected).Count -eq 0) { $expected = @() }
        $countryVerdict = Get-CountryVerdict -RegistryCountry $regCountry -GeoCountry $geoCountry -Expected $expected
        $Shared.CountryVerdict = $countryVerdict
        if ($countryVerdict.Country) {
            WriteLog ('Country: {0} ({1}) - {2}' -f $countryVerdict.Country, $countryVerdict.Source,
                $(if ($countryVerdict.IsExpected) { 'expected' } else { 'OUTSIDE expected set' }))
        }

        $asName = ''; if ($Shared.Asn) { $asName = $Shared.Asn.AsName }
        $netName = ''; if ($Shared.Rdap) { $netName = $Shared.Rdap.Name }
        $usage = ''; if ($Shared.Abuse -and $Shared.Abuse.Available) { $usage = $Shared.Abuse.UsageType }
        $netKind = Get-NetworkKind -AsName $asName -NetName $netName -UsageType $usage
        $Shared.NetworkKind = $netKind
        WriteLog ('Network kind: {0}' -f $netKind.Kind)

        $risk = Get-RiskVerdict -KnownMatch $Shared.KnownMatch -Abuse $Shared.Abuse `
            -CountryVerdict $countryVerdict -NetworkKind $netKind.Kind -IsTorExit ([bool]$Shared.IsTorExit)
        $Shared.Risk = $risk
        WriteLog ('Risk: {0}' -f $risk.Level)

        $Shared.Summary = (Build-Summary -Ip $TargetIp -Shared $Shared -Fp $fp)
        $Shared.SummaryReady = $true
        $Shared.Progress = 100
    } catch {
        $Shared.Error = $_.Exception.Message
        WriteLog ('ERROR: {0}' -f $_.Exception.Message)
    } finally {
        $Shared.Done = $true
    }
}

# Helpers used inside the worker that must ALSO be in $HelpersSource so the
# runspace sees them. They are defined there; these are here only for the UI
# thread's own use / clarity (already loaded via dot-source above).

# ---------------------------------------------------------------------------
# Small helpers that need only string work - kept in the helpers file too.
# ---------------------------------------------------------------------------

# ===========================================================================
# UI
# ===========================================================================
$Theme = @{
    Bg     = [System.Drawing.Color]::FromArgb(245, 246, 248)
    Accent = [System.Drawing.Color]::FromArgb(0, 90, 158)
    Good   = [System.Drawing.Color]::FromArgb(20, 120, 40)
    Warn   = [System.Drawing.Color]::FromArgb(180, 95, 0)
    Bad    = [System.Drawing.Color]::FromArgb(170, 30, 30)
}

$script:shared = $null
$script:ps = $null
$script:rs = $null
$script:async = $null
$script:scanActive = $false
$script:logIndex = 0
$script:networkRendered = $false
$script:domainsVersionRendered = -1
$script:probeVersionRendered = -1
$script:evidenceRendered = $false
$script:summaryRendered = $false
$script:lastReport = ''

$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = 'IP Triage - IP and domain lookup'
$script:form.Size = New-Object System.Drawing.Size(1120, 780)
$script:form.MinimumSize = New-Object System.Drawing.Size(900, 620)
$script:form.StartPosition = 'CenterScreen'
$script:form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$tlp = New-Object System.Windows.Forms.TableLayoutPanel
$tlp.Dock = 'Fill'
$tlp.ColumnCount = 1
$tlp.RowCount = 4
[void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
# Row 0 is the risk banner - collapsed to zero height until there is something
# to warn about.
[void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 0)))
[void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 92)))
[void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$tlp.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 28)))
$script:form.Controls.Add($tlp)

# ---- Risk banner (row 0) ----
$script:panelBanner = New-Object System.Windows.Forms.Panel
$script:panelBanner.Dock = 'Fill'
$script:panelBanner.Visible = $false
$script:panelBanner.BackColor = $Theme.Bad
$script:panelBanner.Cursor = [System.Windows.Forms.Cursors]::Hand

$script:lblBannerHead = New-Object System.Windows.Forms.Label
$script:lblBannerHead.Dock = 'Top'
$script:lblBannerHead.Height = 26
$script:lblBannerHead.TextAlign = 'MiddleLeft'
$script:lblBannerHead.ForeColor = [System.Drawing.Color]::White
$script:lblBannerHead.Font = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$script:lblBannerHead.Padding = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)

$script:lblBannerDetail = New-Object System.Windows.Forms.Label
$script:lblBannerDetail.Dock = 'Fill'
$script:lblBannerDetail.TextAlign = 'TopLeft'
$script:lblBannerDetail.ForeColor = [System.Drawing.Color]::White
$script:lblBannerDetail.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$script:lblBannerDetail.Padding = New-Object System.Windows.Forms.Padding(12, 0, 6, 4)

# Added detail-first so Dock='Fill' sits below the Dock='Top' headline.
$script:panelBanner.Controls.Add($script:lblBannerDetail)
$script:panelBanner.Controls.Add($script:lblBannerHead)
$tlp.Controls.Add($script:panelBanner, 0, 0)

# ---- Top panel ----
$panelTop = New-Object System.Windows.Forms.Panel
$panelTop.Dock = 'Fill'

$lblIp = New-Object System.Windows.Forms.Label
$lblIp.Text = 'Target:'
$lblIp.Location = New-Object System.Drawing.Point(8, 12)
$lblIp.Size = New-Object System.Drawing.Size(56, 22)

$script:txtIp = New-Object System.Windows.Forms.TextBox
$script:txtIp.Location = New-Object System.Drawing.Point(66, 9)
$script:txtIp.Size = New-Object System.Drawing.Size(360, 26)
$script:txtIp.Font = New-Object System.Drawing.Font('Consolas', 10)
try { $script:txtIp.PlaceholderText = 'IP, hostname, URL, or paste a whole log or alert line' } catch {}

$script:btnLookup = New-Object System.Windows.Forms.Button
$script:btnLookup.Text = 'Look up'
$script:btnLookup.Location = New-Object System.Drawing.Point(434, 8)
$script:btnLookup.Size = New-Object System.Drawing.Size(96, 28)

$script:btnStop = New-Object System.Windows.Forms.Button
$script:btnStop.Text = 'Stop'
$script:btnStop.Location = New-Object System.Drawing.Point(536, 8)
$script:btnStop.Size = New-Object System.Drawing.Size(70, 28)
$script:btnStop.Enabled = $false

$script:btnCopy = New-Object System.Windows.Forms.Button
$script:btnCopy.Text = 'Copy report'
$script:btnCopy.Location = New-Object System.Drawing.Point(614, 8)
$script:btnCopy.Size = New-Object System.Drawing.Size(96, 28)

$script:btnSave = New-Object System.Windows.Forms.Button
$script:btnSave.Text = 'Save report'
$script:btnSave.Location = New-Object System.Drawing.Point(716, 8)
$script:btnSave.Size = New-Object System.Drawing.Size(96, 28)

$script:btnClear = New-Object System.Windows.Forms.Button
$script:btnClear.Text = 'Clear'
$script:btnClear.Location = New-Object System.Drawing.Point(818, 8)
$script:btnClear.Size = New-Object System.Drawing.Size(70, 28)

$script:btnApiKey = New-Object System.Windows.Forms.Button
$script:btnApiKey.Text = 'API key'
$script:btnApiKey.Location = New-Object System.Drawing.Point(894, 8)
$script:btnApiKey.Size = New-Object System.Drawing.Size(86, 28)

# Hands the address to Cisco Talos in the default browser - a second opinion on
# reputation from outside this tool.
$script:btnTalos = New-Object System.Windows.Forms.Button
$script:btnTalos.Text = 'Talos'
$script:btnTalos.Location = New-Object System.Drawing.Point(988, 8)
$script:btnTalos.Size = New-Object System.Drawing.Size(76, 28)

$script:chkOnline = New-Object System.Windows.Forms.CheckBox
$script:chkOnline.Text = 'Online lookups (RDAP, ASN, geo, reputation, reverse-IP)'
$script:chkOnline.Location = New-Object System.Drawing.Point(66, 44)
$script:chkOnline.Size = New-Object System.Drawing.Size(400, 22)
$script:chkOnline.Checked = $true

$script:chkProbe = New-Object System.Windows.Forms.CheckBox
$script:chkProbe.Text = 'Probe the IP''s services (active - only IPs you are authorised to test)'
$script:chkProbe.Location = New-Object System.Drawing.Point(66, 66)
$script:chkProbe.Size = New-Object System.Drawing.Size(470, 22)

# Shows "hostname -> address" when a name was typed instead of an IP.
$script:lblResolved = New-Object System.Windows.Forms.Label
$script:lblResolved.Location = New-Object System.Drawing.Point(548, 68)
$script:lblResolved.Size = New-Object System.Drawing.Size(360, 20)
$script:lblResolved.ForeColor = $Theme.Accent
$script:lblResolved.Text = ''

$panelTop.Controls.AddRange(@(
    $lblIp, $script:txtIp, $script:btnLookup, $script:btnStop, $script:btnCopy,
    $script:btnSave, $script:btnClear, $script:btnApiKey, $script:btnTalos,
    $script:chkOnline, $script:chkProbe, $script:lblResolved))
$tlp.Controls.Add($panelTop, 0, 1)

# ---- Grid factory ----
function New-Grid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.RowHeadersVisible = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = $false
    $g.AutoSizeColumnsMode = 'Fill'
    $g.BackgroundColor = [System.Drawing.Color]::White
    $g.BorderStyle = 'None'
    $g.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $g.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    return $g
}

# ---- Tabs ----
$script:tabs = New-Object System.Windows.Forms.TabControl
$script:tabs.Dock = 'Fill'

# Summary
$tabSummary = New-Object System.Windows.Forms.TabPage
$tabSummary.Text = 'Summary'
$script:txtSummary = New-Object System.Windows.Forms.TextBox
$script:txtSummary.Dock = 'Fill'
$script:txtSummary.Multiline = $true
$script:txtSummary.ReadOnly = $true
$script:txtSummary.ScrollBars = 'Both'
$script:txtSummary.WordWrap = $false
$script:txtSummary.Font = New-Object System.Drawing.Font('Consolas', 10)
$script:txtSummary.BackColor = [System.Drawing.Color]::White
$tabSummary.Controls.Add($script:txtSummary)

# Security - reputation and exposure detail. The Risk headline stays on the
# Summary so the at-a-glance answer is never hidden behind a tab.
$tabSecurity = New-Object System.Windows.Forms.TabPage
$tabSecurity.Text = 'Security'
$script:txtSecurity = New-Object System.Windows.Forms.TextBox
$script:txtSecurity.Dock = 'Fill'
$script:txtSecurity.Multiline = $true
$script:txtSecurity.ReadOnly = $true
$script:txtSecurity.ScrollBars = 'Both'
$script:txtSecurity.WordWrap = $false
$script:txtSecurity.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtSecurity.BackColor = [System.Drawing.Color]::White
$tabSecurity.Controls.Add($script:txtSecurity)

# Network
$tabNetwork = New-Object System.Windows.Forms.TabPage
$tabNetwork.Text = 'Network'
$script:txtNetwork = New-Object System.Windows.Forms.TextBox
$script:txtNetwork.Dock = 'Fill'
$script:txtNetwork.Multiline = $true
$script:txtNetwork.ReadOnly = $true
$script:txtNetwork.ScrollBars = 'Both'
$script:txtNetwork.WordWrap = $false
$script:txtNetwork.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtNetwork.BackColor = [System.Drawing.Color]::White
$tabNetwork.Controls.Add($script:txtNetwork)

# Services (grid + detail)
$tabServices = New-Object System.Windows.Forms.TabPage
$tabServices.Text = 'Services'
$splitSvc = New-Object System.Windows.Forms.SplitContainer
$splitSvc.Dock = 'Fill'
$splitSvc.Orientation = 'Horizontal'
$script:gridServices = New-Grid
$script:gridServices.Columns.Add('svcPort', 'Port') | Out-Null
$script:gridServices.Columns.Add('svcName', 'Service') | Out-Null
$script:gridServices.Columns.Add('svcState', 'State') | Out-Null
$script:gridServices.Columns.Add('svcServer', 'Server/Banner') | Out-Null
$script:gridServices.Columns.Add('svcTitle', 'Title') | Out-Null
$script:gridServices.Columns['svcPort'].FillWeight = 12
$script:gridServices.Columns['svcName'].FillWeight = 20
$script:gridServices.Columns['svcState'].FillWeight = 14
$script:gridServices.Columns['svcServer'].FillWeight = 27
$script:gridServices.Columns['svcTitle'].FillWeight = 27
$script:txtSvcDetail = New-Object System.Windows.Forms.TextBox
$script:txtSvcDetail.Dock = 'Fill'
$script:txtSvcDetail.Multiline = $true
$script:txtSvcDetail.ReadOnly = $true
$script:txtSvcDetail.ScrollBars = 'Both'
$script:txtSvcDetail.WordWrap = $false
$script:txtSvcDetail.Font = New-Object System.Drawing.Font('Consolas', 9)
$splitSvc.Panel1.Controls.Add($script:gridServices)
$splitSvc.Panel2.Controls.Add($script:txtSvcDetail)
$tabServices.Controls.Add($splitSvc)

# Certificates
$tabCerts = New-Object System.Windows.Forms.TabPage
$tabCerts.Text = 'Certificates'
$script:gridCerts = New-Grid
$script:gridCerts.Columns.Add('cPort', 'Port') | Out-Null
$script:gridCerts.Columns.Add('cSubject', 'Subject') | Out-Null
$script:gridCerts.Columns.Add('cIssuer', 'Issuer') | Out-Null
$script:gridCerts.Columns.Add('cSelf', 'Self-signed') | Out-Null
$script:gridCerts.Columns.Add('cProto', 'TLS') | Out-Null
$script:gridCerts.Columns.Add('cExpiry', 'Expires') | Out-Null
$script:gridCerts.Columns['cPort'].FillWeight = 8
$script:gridCerts.Columns['cSubject'].FillWeight = 30
$script:gridCerts.Columns['cIssuer'].FillWeight = 30
$script:gridCerts.Columns['cSelf'].FillWeight = 12
$script:gridCerts.Columns['cProto'].FillWeight = 10
$script:gridCerts.Columns['cExpiry'].FillWeight = 16
$tabCerts.Controls.Add($script:gridCerts)

# Domains
$tabDomains = New-Object System.Windows.Forms.TabPage
$tabDomains.Text = 'Domains'
$script:gridDomains = New-Grid
$script:gridDomains.Columns.Add('dName', 'Name') | Out-Null
$script:gridDomains.Columns.Add('dSource', 'Source') | Out-Null
$script:gridDomains.Columns.Add('dPoints', 'Points here') | Out-Null
$script:gridDomains.Columns.Add('dResolves', 'Resolves to') | Out-Null
$script:gridDomains.Columns.Add('dReg', 'Registered domain') | Out-Null
$script:gridDomains.Columns.Add('dOrg', 'Registrant org') | Out-Null
$script:gridDomains.Columns.Add('dRegistrar', 'Registrar') | Out-Null
$script:gridDomains.Columns['dName'].FillWeight = 20
$script:gridDomains.Columns['dSource'].FillWeight = 11
$script:gridDomains.Columns['dPoints'].FillWeight = 9
$script:gridDomains.Columns['dResolves'].FillWeight = 15
$script:gridDomains.Columns['dReg'].FillWeight = 15
$script:gridDomains.Columns['dOrg'].FillWeight = 20
$script:gridDomains.Columns['dRegistrar'].FillWeight = 12
$tabDomains.Controls.Add($script:gridDomains)

# DNS / MX - on-demand domain checks (SPF/DMARC/DKIM/records/propagation)
$tabDns = New-Object System.Windows.Forms.TabPage
$tabDns.Text = 'DNS / MX'

$dnsLayout = New-Object System.Windows.Forms.TableLayoutPanel
$dnsLayout.Dock = 'Fill'
$dnsLayout.ColumnCount = 1
$dnsLayout.RowCount = 3
[void]$dnsLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$dnsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 64)))
[void]$dnsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 26)))
[void]$dnsLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))

$dnsTop = New-Object System.Windows.Forms.Panel
$dnsTop.Dock = 'Fill'

$lblDnsDomain = New-Object System.Windows.Forms.Label
$lblDnsDomain.Text = 'Domain:'
$lblDnsDomain.Location = New-Object System.Drawing.Point(6, 9)
$lblDnsDomain.Size = New-Object System.Drawing.Size(54, 20)

$script:txtDnsDomain = New-Object System.Windows.Forms.TextBox
$script:txtDnsDomain.Location = New-Object System.Drawing.Point(62, 6)
$script:txtDnsDomain.Size = New-Object System.Drawing.Size(230, 24)
$script:txtDnsDomain.Font = New-Object System.Drawing.Font('Consolas', 9)

$lblDnsSel = New-Object System.Windows.Forms.Label
$lblDnsSel.Text = 'DKIM selectors:'
$lblDnsSel.Location = New-Object System.Drawing.Point(300, 9)
$lblDnsSel.Size = New-Object System.Drawing.Size(92, 20)

$script:txtDnsSelectors = New-Object System.Windows.Forms.TextBox
$script:txtDnsSelectors.Location = New-Object System.Drawing.Point(394, 6)
$script:txtDnsSelectors.Size = New-Object System.Drawing.Size(170, 24)
$script:txtDnsSelectors.Font = New-Object System.Drawing.Font('Consolas', 9)
try { $script:txtDnsSelectors.PlaceholderText = 'optional, comma separated' } catch {}

$lblDnsResolver = New-Object System.Windows.Forms.Label
$lblDnsResolver.Text = 'Resolver:'
$lblDnsResolver.Location = New-Object System.Drawing.Point(572, 9)
$lblDnsResolver.Size = New-Object System.Drawing.Size(60, 20)

$script:cboResolver = New-Object System.Windows.Forms.ComboBox
$script:cboResolver.Location = New-Object System.Drawing.Point(634, 6)
$script:cboResolver.Size = New-Object System.Drawing.Size(230, 24)
$script:cboResolver.DropDownStyle = 'DropDownList'
# Public first and selected by default: this PC's DNS gives the internal
# split-horizon view inside a customer network, where an AD zone of the same
# name usually has no MX/TXT and the report would wrongly read "nothing set up".
[void]$script:cboResolver.Items.Add('Public - Cloudflare 1.1.1.1')
[void]$script:cboResolver.Items.Add('Public - Google 8.8.8.8')
[void]$script:cboResolver.Items.Add('Public - Quad9 9.9.9.9')
[void]$script:cboResolver.Items.Add("This PC's DNS (internal view)")
$script:cboResolver.SelectedIndex = 0

$script:btnDnsCheck = New-Object System.Windows.Forms.Button
$script:btnDnsCheck.Text = 'Check DNS'
$script:btnDnsCheck.Location = New-Object System.Drawing.Point(62, 34)
$script:btnDnsCheck.Size = New-Object System.Drawing.Size(100, 26)

$lblProp = New-Object System.Windows.Forms.Label
$lblProp.Text = 'Propagation:'
$lblProp.Location = New-Object System.Drawing.Point(176, 38)
$lblProp.Size = New-Object System.Drawing.Size(76, 20)

$script:cboPropType = New-Object System.Windows.Forms.ComboBox
$script:cboPropType.Location = New-Object System.Drawing.Point(254, 35)
$script:cboPropType.Size = New-Object System.Drawing.Size(90, 24)
$script:cboPropType.DropDownStyle = 'DropDownList'
foreach ($rt in @('A', 'AAAA', 'MX', 'CNAME', 'NS', 'TXT', 'DMARC', 'DKIM', 'SOA')) { [void]$script:cboPropType.Items.Add($rt) }
$script:cboPropType.SelectedIndex = 0

$script:btnDnsProp = New-Object System.Windows.Forms.Button
$script:btnDnsProp.Text = 'Check across 8 resolvers'
$script:btnDnsProp.Location = New-Object System.Drawing.Point(352, 34)
$script:btnDnsProp.Size = New-Object System.Drawing.Size(170, 26)

$script:btnDnsStop = New-Object System.Windows.Forms.Button
$script:btnDnsStop.Text = 'Stop'
$script:btnDnsStop.Location = New-Object System.Drawing.Point(530, 34)
$script:btnDnsStop.Size = New-Object System.Drawing.Size(70, 26)
$script:btnDnsStop.Enabled = $false

$script:btnDnsCopy = New-Object System.Windows.Forms.Button
$script:btnDnsCopy.Text = 'Copy'
$script:btnDnsCopy.Location = New-Object System.Drawing.Point(608, 34)
$script:btnDnsCopy.Size = New-Object System.Drawing.Size(70, 26)

$script:lblDnsStatus = New-Object System.Windows.Forms.Label
$script:lblDnsStatus.Location = New-Object System.Drawing.Point(686, 38)
$script:lblDnsStatus.Size = New-Object System.Drawing.Size(380, 20)
$script:lblDnsStatus.Text = ''

# Certificate-transparency lookups for the domain, opened in the default browser.
# CT logs are the quickest way to see every subdomain a certificate was ever
# issued for - including ones that no longer resolve.
$script:btnCrtSh = New-Object System.Windows.Forms.Button
$script:btnCrtSh.Text = 'crt.sh'
$script:btnCrtSh.Location = New-Object System.Drawing.Point(872, 5)
$script:btnCrtSh.Size = New-Object System.Drawing.Size(72, 26)

$script:btnCtLogs = New-Object System.Windows.Forms.Button
$script:btnCtLogs.Text = 'ctlogs.dev'
$script:btnCtLogs.Location = New-Object System.Drawing.Point(950, 5)
$script:btnCtLogs.Size = New-Object System.Drawing.Size(86, 26)

$dnsTop.Controls.AddRange(@(
    $lblDnsDomain, $script:txtDnsDomain, $lblDnsSel, $script:txtDnsSelectors,
    $lblDnsResolver, $script:cboResolver, $script:btnDnsCheck, $lblProp,
    $script:cboPropType, $script:btnDnsProp, $script:btnDnsStop, $script:btnDnsCopy,
    $script:btnCrtSh, $script:btnCtLogs, $script:lblDnsStatus))
$dnsLayout.Controls.Add($dnsTop, 0, 0)

# Findings strip - one coloured label per area, so a FAIL is visible at a glance.
$script:panelDnsFindings = New-Object System.Windows.Forms.FlowLayoutPanel
$script:panelDnsFindings.Dock = 'Fill'
$script:panelDnsFindings.FlowDirection = 'LeftToRight'
$script:panelDnsFindings.WrapContents = $false
$script:panelDnsFindings.Padding = New-Object System.Windows.Forms.Padding(6, 2, 0, 0)
$dnsLayout.Controls.Add($script:panelDnsFindings, 0, 1)

$script:txtDns = New-Object System.Windows.Forms.TextBox
$script:txtDns.Dock = 'Fill'
$script:txtDns.Multiline = $true
$script:txtDns.ReadOnly = $true
$script:txtDns.ScrollBars = 'Both'
$script:txtDns.WordWrap = $false
$script:txtDns.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtDns.BackColor = [System.Drawing.Color]::White
$dnsLayout.Controls.Add($script:txtDns, 0, 2)

$tabDns.Controls.Add($dnsLayout)

# Evidence
$tabEvidence = New-Object System.Windows.Forms.TabPage
$tabEvidence.Text = 'Evidence'
$script:gridEvidence = New-Grid
$script:gridEvidence.Columns.Add('eVendor', 'Suggests') | Out-Null
$script:gridEvidence.Columns.Add('eClass', 'Class') | Out-Null
$script:gridEvidence.Columns.Add('eWeight', 'Weight') | Out-Null
$script:gridEvidence.Columns.Add('ePort', 'Port') | Out-Null
$script:gridEvidence.Columns.Add('eField', 'From') | Out-Null
$script:gridEvidence.Columns.Add('eEvidence', 'Evidence') | Out-Null
$script:gridEvidence.Columns['eVendor'].FillWeight = 20
$script:gridEvidence.Columns['eClass'].FillWeight = 12
$script:gridEvidence.Columns['eWeight'].FillWeight = 8
$script:gridEvidence.Columns['ePort'].FillWeight = 8
$script:gridEvidence.Columns['eField'].FillWeight = 12
$script:gridEvidence.Columns['eEvidence'].FillWeight = 40
$tabEvidence.Controls.Add($script:gridEvidence)

# Log
$tabLog = New-Object System.Windows.Forms.TabPage
$tabLog.Text = 'Log'
$script:txtLog = New-Object System.Windows.Forms.TextBox
$script:txtLog.Dock = 'Fill'
$script:txtLog.Multiline = $true
$script:txtLog.ReadOnly = $true
$script:txtLog.ScrollBars = 'Both'
$script:txtLog.WordWrap = $false
$script:txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
$tabLog.Controls.Add($script:txtLog)

$script:tabs.TabPages.AddRange(@($tabSummary, $tabSecurity, $tabNetwork, $tabServices, $tabCerts, $tabDomains, $tabDns, $tabEvidence, $tabLog))
$tlp.Controls.Add($script:tabs, 0, 2)

# Clicking a tab focuses its first control, and a multiline TextBox selects all
# of its text on focus - which looks like the pane is highlighted blue. Drop the
# selection so the read-only panes just read as text.
foreach ($readOnlyPane in @($script:txtSummary, $script:txtSecurity, $script:txtNetwork, $script:txtLog, $script:txtSvcDetail)) {
    # Enter fires before the control's own select-all, and BeginInvoke defers the
    # deselect until after it, so the caret lands at the top with nothing selected.
    $readOnlyPane.Add_Enter({
        param($sender, $e)
        $ctl = $sender
        [void]$ctl.BeginInvoke(([Action] { $ctl.Select(0, 0) }.GetNewClosure()))
    })
}

# ---- Status strip ----
$panelStatus = New-Object System.Windows.Forms.Panel
$panelStatus.Dock = 'Fill'
$script:progress = New-Object System.Windows.Forms.ProgressBar
$script:progress.Location = New-Object System.Drawing.Point(8, 4)
$script:progress.Size = New-Object System.Drawing.Size(240, 18)
$script:lblStatus = New-Object System.Windows.Forms.Label
$script:lblStatus.Location = New-Object System.Drawing.Point(256, 6)
$script:lblStatus.Size = New-Object System.Drawing.Size(820, 18)
$script:lblStatus.Text = 'Ready. Enter an IP or hostname and click Look up.'
$panelStatus.Controls.AddRange(@($script:progress, $script:lblStatus))
$tlp.Controls.Add($panelStatus, 0, 3)

# ---------------------------------------------------------------------------
# Renderers (UI thread only)
# ---------------------------------------------------------------------------
function Set-Busy {
    param([bool]$Busy)
    $script:btnLookup.Enabled = -not $Busy
    $script:btnClear.Enabled = -not $Busy
    $script:txtIp.Enabled = -not $Busy
    $script:chkOnline.Enabled = -not $Busy
    $script:chkProbe.Enabled = -not $Busy
    $script:btnStop.Enabled = $Busy
}

function Render-Network {
    param($sh)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=== Network owner (RDAP) ===')
    if ($sh.Rdap -and $sh.Rdap.Name) {
        [void]$sb.AppendLine(('Netname : {0}' -f $sh.Rdap.Name))
        [void]$sb.AppendLine(('Range   : {0} - {1}' -f $sh.Rdap.StartAddress, $sh.Rdap.EndAddress))
        [void]$sb.AppendLine(('Country : {0}' -f $sh.Rdap.Country))
        foreach ($e in @($sh.Rdap.Entities)) {
            $who = $e.Org; if (-not $who) { $who = $e.Name }
            [void]$sb.AppendLine(('Entity  : [{0}] {1}' -f $e.Roles, $who))
        }
        foreach ($rm in @($sh.Rdap.Remarks)) { if ($rm) { [void]$sb.AppendLine(('Remark  : {0}' -f $rm)) } }
    } else { [void]$sb.AppendLine('(no RDAP data)') }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== ASN (Team Cymru) ===')
    if ($sh.Asn -and $sh.Asn.Asn) {
        [void]$sb.AppendLine(('AS{0}  {1}' -f $sh.Asn.Asn, $sh.Asn.AsName))
        [void]$sb.AppendLine(('Prefix : {0}   Registry: {1}   Allocated: {2}' -f $sh.Asn.Prefix, $sh.Asn.Registry, $sh.Asn.Allocated))
    } else { [void]$sb.AppendLine('(no ASN data)') }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Geolocation (ipinfo.io) ===')
    if ($sh.Geo -and ($sh.Geo.Org -or $sh.Geo.City)) {
        [void]$sb.AppendLine(('Org     : {0}' -f $sh.Geo.Org))
        [void]$sb.AppendLine(('Location: {0}, {1} {2} ({3})' -f $sh.Geo.City, $sh.Geo.Region, $sh.Geo.Country, $sh.Geo.Postal))
        [void]$sb.AppendLine(('Timezone: {0}' -f $sh.Geo.Timezone))
    } else { [void]$sb.AppendLine('(no geo data)') }
    if ($sh.InternetDb -and $sh.InternetDb.Found) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('=== Shodan InternetDB (passive) ===')
        [void]$sb.AppendLine(('Ports   : {0}' -f (@($sh.InternetDb.Ports) -join ', ')))
        [void]$sb.AppendLine(('Tags    : {0}' -f (@($sh.InternetDb.Tags) -join ', ')))
        [void]$sb.AppendLine(('CPEs    : {0}' -f (@($sh.InternetDb.Cpes) -join ', ')))
        if (@($sh.InternetDb.Vulns).Count -gt 0) { [void]$sb.AppendLine(('Vulns   : {0}' -f (@($sh.InternetDb.Vulns) -join ', '))) }
    }
    $script:txtNetwork.Text = $sb.ToString()
}

function Hide-RiskBanner {
    $script:panelBanner.Visible = $false
    $tlp.RowStyles[0].Height = 0
    if ($script:bannerTimer) { $script:bannerTimer.Stop() }
    # Restore the plain tab caption.
    foreach ($tp in $script:tabs.TabPages) { if ($tp.Text -like 'Security*') { $tp.Text = 'Security' } }
}

function Show-RiskBanner {
    param($sh)
    $banner = Get-RiskBanner -Risk $sh.Risk -Abuse $sh.Abuse -KnownMatch $sh.KnownMatch
    if (-not $banner.Show) { Hide-RiskBanner; return }

    $script:lblBannerHead.Text = $banner.Headline
    $script:lblBannerDetail.Text = $banner.Detail
    $script:bannerBase = if ($banner.Level -eq 'High') { $Theme.Bad } else { $Theme.Warn }
    $script:panelBanner.BackColor = $script:bannerBase
    $tlp.RowStyles[0].Height = 52
    $script:panelBanner.Visible = $true

    # Mark the tab that holds the detail, so it is obvious where to look.
    foreach ($tp in $script:tabs.TabPages) { if ($tp.Text -like 'Security*') { $tp.Text = 'Security (!)' } }

    if ($banner.Level -eq 'High') {
        try { [System.Media.SystemSounds]::Hand.Play() } catch {}
        # Flash a few times, then settle - enough to catch the eye without
        # becoming a strobe that has to be waited out.
        $script:bannerFlashes = 0
        if (-not $script:bannerTimer) {
            $script:bannerTimer = New-Object System.Windows.Forms.Timer
            $script:bannerTimer.Interval = 220
            $script:bannerTimer.Add_Tick({
                $script:bannerFlashes++
                if ($script:bannerFlashes -ge 6) {
                    $script:bannerTimer.Stop()
                    $script:panelBanner.BackColor = $script:bannerBase
                    return
                }
                if ($script:bannerFlashes % 2 -eq 1) {
                    $script:panelBanner.BackColor = [System.Drawing.Color]::FromArgb(230, 90, 90)
                } else {
                    $script:panelBanner.BackColor = $script:bannerBase
                }
            })
        }
        $script:bannerTimer.Start()
    }
}

function Render-Security {
    param($sh)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=== Risk ===')
    if ($sh.Risk) {
        [void]$sb.AppendLine(('Rating   : {0}' -f $sh.Risk.Level))
        foreach ($r in @($sh.Risk.Reasons)) { [void]$sb.AppendLine((' * ' + $r)) }
    } else { [void]$sb.AppendLine('(not yet rated)') }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Address classification ===')
    if ($sh.KnownMatch -and $sh.KnownMatch.Matched) {
        [void]$sb.AppendLine(('Known    : {0} - {1}  (matched {2})' -f $sh.KnownMatch.Type, $sh.KnownMatch.Label, $sh.KnownMatch.Range))
    } else {
        [void]$sb.AppendLine('Known    : not in KnownRanges.csv')
    }
    if ($sh.CountryVerdict -and $sh.CountryVerdict.Country) {
        [void]$sb.AppendLine(('Country  : {0} (from {1}) - {2}' -f $sh.CountryVerdict.Country, $sh.CountryVerdict.Source,
            $(if ($sh.CountryVerdict.IsExpected) { 'expected' } else { 'OUTSIDE expected set' })))
        if ($sh.CountryVerdict.Disagreement) { [void]$sb.AppendLine(('           {0}' -f $sh.CountryVerdict.Disagreement)) }
    }
    if ($sh.NetworkKind) {
        [void]$sb.AppendLine(('Kind     : {0}' -f $sh.NetworkKind.Kind))
        if ($sh.NetworkKind.Reason) { [void]$sb.AppendLine(('           {0}' -f $sh.NetworkKind.Reason)) }
    }
    [void]$sb.AppendLine(('Tor exit : {0}' -f $(if ($sh.IsTorExit) { 'YES - listed as a Tor exit node' } else { 'no' })))

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== AbuseIPDB ===')
    if ($sh.Abuse -and $sh.Abuse.Available) {
        [void]$sb.AppendLine(('Confidence : {0}%' -f $sh.Abuse.Score))
        [void]$sb.AppendLine(('Reports    : {0}' -f $sh.Abuse.TotalReports))
        if ($sh.Abuse.LastReported) { [void]$sb.AppendLine(('Last report: {0}' -f $sh.Abuse.LastReported)) }
        if ($sh.Abuse.UsageType)   { [void]$sb.AppendLine(('Usage type : {0}' -f $sh.Abuse.UsageType)) }
        [void]$sb.AppendLine(('Whitelisted: {0}' -f $(if ($sh.Abuse.IsWhitelisted) { 'yes' } else { 'no' })))
    } elseif ($sh.Abuse) {
        [void]$sb.AppendLine(('Not checked - {0}.' -f $sh.Abuse.Error))
        [void]$sb.AppendLine('Use the "API key" button to add a free AbuseIPDB key.')
    } else {
        [void]$sb.AppendLine('(not run)')
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Known CVEs (Shodan InternetDB) ===')
    if ($sh.InternetDb -and @($sh.InternetDb.Vulns).Count -gt 0) {
        [void]$sb.AppendLine(('{0} reported against this host:' -f @($sh.InternetDb.Vulns).Count))
        foreach ($v in @($sh.InternetDb.Vulns)) { [void]$sb.AppendLine('  ' + $v) }
    } elseif ($sh.InternetDb -and $sh.InternetDb.Found) {
        [void]$sb.AppendLine('None reported.')
    } else {
        [void]$sb.AppendLine('(no InternetDB data)')
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== Exposure ===')
    $notes = @(Get-ExposureNotes -Shared $sh)
    if (@($notes).Count -gt 0) {
        foreach ($n in $notes) { [void]$sb.AppendLine(' * ' + $n) }
    } else {
        [void]$sb.AppendLine('Nothing flagged by the checks that ran.')
    }
    $script:txtSecurity.Text = $sb.ToString()
}

function Render-Services {
    param($sh)
    $script:gridServices.Rows.Clear()
    foreach ($r in @($sh.Probe)) {
        $idx = $script:gridServices.Rows.Add(@($r.Port, $r.Service, $r.State, ($(if ($r.Server) { $r.Server } else { $r.Banner })), $r.Title))
        $cell = $script:gridServices.Rows[$idx].Cells['svcState']
        switch ($r.State) {
            'Open'     { $cell.Style.ForeColor = $Theme.Good }
            'Refused'  { $cell.Style.ForeColor = $Theme.Warn }
            default    { $cell.Style.ForeColor = [System.Drawing.Color]::Gray }
        }
    }
}

function Render-Certs {
    param($sh)
    $script:gridCerts.Rows.Clear()
    foreach ($c in @($sh.Certs)) {
        $exp = ''
        try { $exp = ([DateTime]$c.NotAfter).ToString('yyyy-MM-dd') } catch {}
        [void]$script:gridCerts.Rows.Add(@($c.Port, $c.Subject, $c.Issuer, $c.SelfSigned, $c.Protocol, $exp))
    }
}

function Render-Domains {
    param($sh)
    $script:gridDomains.Rows.Clear()
    foreach ($d in @($sh.Domains)) {
        $idx = $script:gridDomains.Rows.Add(@($d.Name, $d.Source, $(if ($d.PointsHere) { 'YES' } else { '' }), $d.ResolvesTo, $d.RegDomain, $d.RegistrantOrg, $d.Registrar))
        if ($d.PointsHere) { $script:gridDomains.Rows[$idx].Cells['dPoints'].Style.ForeColor = $Theme.Good }
    }
}

function Render-Evidence {
    param($sh)
    $script:gridEvidence.Rows.Clear()
    if ($sh.Fingerprint) {
        foreach ($m in @($sh.Fingerprint.Matches)) {
            [void]$script:gridEvidence.Rows.Add(@($m.Vendor, $m.Class, $m.Weight, $m.Port, $m.Field, $m.Evidence))
        }
    }
}

function Render-Summary {
    param($sh)
    $script:txtSummary.Text = [string]$sh.Summary
    $script:lastReport = [string]$sh.Summary
}

function Clear-DnsTab {
    # Wipes the DNS / MX tab back to empty, including the domain box so the next
    # triage run can pre-fill it for the new target. A DNS job that is actually
    # running is left alone - the user started it deliberately and its results
    # should not be thrown away just because an IP lookup began.
    if ($script:dnsActive) { return }
    $script:txtDns.Clear()
    $script:txtDnsDomain.Clear()
    $script:panelDnsFindings.Controls.Clear()
    $script:lblDnsStatus.ForeColor = [System.Drawing.Color]::Black
    $script:lblDnsStatus.Text = ''
}

function Set-DnsDomainFromTriage {
    # Pre-fill the DNS tab with the most promising domain this lookup turned up:
    # one that both resolves to the target and has a registrant, else any with a
    # registrant, else any registrable domain. Never overwrite typing in progress.
    param($sh)
    if ($script:dnsActive) { return }
    if ($script:txtDnsDomain.Text.Trim()) { return }
    $rows = @($sh.Domains) | Where-Object { $_.RegDomain }
    if (@($rows).Count -eq 0) { return }
    # Rank exactly as the summary does: a domain found only in the ISP's reverse
    # DNS (url.net.au and friends) is the carrier, not the customer, so it goes
    # last however well it otherwise scores.
    $ranked = @($rows | Sort-Object -Property @{ Expression = {
        if ($_.Source -eq 'PTR') { 3 }
        elseif ($_.PointsHere -and $_.RegistrantOrg) { 0 }
        elseif ($_.RegistrantOrg) { 1 }
        else { 2 }
    } })
    $pick = @($ranked)[0]
    if ($pick) { $script:txtDnsDomain.Text = [string]$pick.RegDomain }
}

# ---------------------------------------------------------------------------
# Start / stop
# ---------------------------------------------------------------------------
function Start-Lookup {
    if ($script:scanActive) { return }
    $raw = $script:txtIp.Text
    $target = Resolve-TargetInput $raw
    if (-not $target.Ip) {
        [void][System.Windows.Forms.MessageBox]::Show(
            ($target.Error + [Environment]::NewLine + [Environment]::NewLine +
             'Accepts an IP, ip:port, a URL, a hostname, or a pasted log or alert line.'),
            'IP Triage', 'OK', 'Warning'); return
    }
    $ip = $target.Ip
    $inputHost = $target.InputHost
    if ($inputHost) {
        # Leave what they typed in the box; show the mapping instead of
        # silently replacing the hostname with an address.
        $script:lblResolved.Text = ('{0} -> {1}{2}' -f $inputHost, $ip,
            $(if (@($target.AllIps).Count -gt 1) { (' (+{0} more)' -f (@($target.AllIps).Count - 1)) } else { '' }))
    } else {
        $script:txtIp.Text = $ip
        $script:lblResolved.Text = ''
    }
    $doProbe = [bool]$script:chkProbe.Checked
    if ($doProbe) {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            ('Active probing opens connections to {0} on common service ports and reads what each service offers.' + [Environment]::NewLine + [Environment]::NewLine +
             'Only probe IPs you own or are authorised to test. Continue?') -f $ip,
            'Confirm active probe', 'YesNo', 'Warning')
        if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    $script:scanActive = $true
    $script:logIndex = 0
    $script:networkRendered = $false
    $script:domainsVersionRendered = -1
    $script:probeVersionRendered = -1
    $script:evidenceRendered = $false
    $script:summaryRendered = $false
    $script:txtLog.Clear()
    Hide-RiskBanner
    Clear-DnsTab
    $script:txtSummary.Clear()
    $script:txtSecurity.Clear()
    $script:txtNetwork.Clear()
    $script:gridServices.Rows.Clear()
    $script:gridCerts.Rows.Clear()
    $script:gridDomains.Rows.Clear()
    $script:gridEvidence.Rows.Clear()
    $script:txtSvcDetail.Clear()
    $script:progress.Value = 0
    $script:lblStatus.Text = 'Starting...'
    Set-Busy $true

    $shared = [hashtable]::Synchronized(@{})
    $shared.Log = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $shared.Progress = 0
    $shared.Status = ''
    $shared.Done = $false
    $shared.Cancel = $false
    $shared.Error = $null
    $shared.IpClass = ''
    $shared.OwnPublicIp = ''
    $shared.InputHost = $inputHost
    $shared.InputAllIps = @($target.AllIps)
    $shared.Ptr = @(); $shared.PtrGeneric = $false
    $shared.Asn = $null; $shared.Rdap = $null; $shared.Geo = $null
    $shared.InternetDb = $null; $shared.IsTorExit = $false; $shared.ReverseIp = $null
    $shared.NetworkReady = $false
    $shared.Probe = @(); $shared.Certs = @(); $shared.ProbeReady = $false; $shared.ProbeVersion = 0
    $shared.Domains = @(); $shared.DomainsReady = $false; $shared.DomainsVersion = 0
    $shared.Registrations = @(); $shared.RegistrationsReady = $false
    $shared.Fingerprint = $null; $shared.EvidenceReady = $false
    $shared.KnownMatch = $null; $shared.Abuse = $null
    $shared.CountryVerdict = $null; $shared.NetworkKind = $null; $shared.Risk = $null
    $shared.Summary = ''; $shared.SummaryReady = $false
    $script:shared = $shared

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.ApartmentState = 'MTA'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($WorkerScript.ToString())
    [void]$ps.AddParameter('Shared', $shared)
    [void]$ps.AddParameter('HelpersSource', $HelpersSource)
    [void]$ps.AddParameter('TargetIp', $ip)
    [void]$ps.AddParameter('DoOnline', [bool]$script:chkOnline.Checked)
    [void]$ps.AddParameter('DoProbe', $doProbe)
    [void]$ps.AddParameter('InputHost', $inputHost)
    [void]$ps.AddParameter('KnownRangesPath', $script:knownRangesPath)
    [void]$ps.AddParameter('AbuseKey', (Get-AbuseIpdbKey))
    [void]$ps.AddParameter('ExpectedCountries', $script:expectedCountryList)
    $script:ps = $ps
    $script:rs = $rs
    $script:async = $ps.BeginInvoke()
    $script:timer.Start()
}

function Copy-Report {
    if (-not $script:lastReport) {
        [void][System.Windows.Forms.MessageBox]::Show('Nothing to copy yet - run a lookup first.', 'IP Triage', 'OK', 'Information'); return
    }
    try { [System.Windows.Forms.Clipboard]::SetText($script:lastReport); $script:lblStatus.Text = 'Report copied to clipboard.' }
    catch { [void][System.Windows.Forms.MessageBox]::Show('Could not access the clipboard.', 'IP Triage', 'OK', 'Warning') }
}

function Save-Report {
    if (-not $script:lastReport) {
        [void][System.Windows.Forms.MessageBox]::Show('Nothing to save yet - run a lookup first.', 'IP Triage', 'OK', 'Information'); return
    }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'Text files (*.txt)|*.txt'
    $sfd.FileName = ('IP-Triage_{0}_{1}.txt' -f ($script:txtIp.Text -replace '[^\d]', '_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Set-Content -LiteralPath $sfd.FileName -Value $script:lastReport -Encoding UTF8
        $script:lblStatus.Text = ('Saved: {0}' -f $sfd.FileName)
    }
}

# ---------------------------------------------------------------------------
# DNS / MX tab - its own runspace and timer so a slow propagation sweep never
# blocks the window or interferes with an IP lookup.
# ---------------------------------------------------------------------------
$DnsWorkerScript = {
    param($Shared, $HelpersSource, $Domain, $Selectors, $Resolver, $Mode, $RecordType)

    . ([scriptblock]::Create($HelpersSource))
    try {
        $progress = { param($m) $Shared.Status = [string]$m }
        $cancel = { [bool]$Shared.Cancel }
        if ($Mode -eq 'Propagation') {
            $Shared.Text = Get-GlobalDnsRecordReport -Domain $Domain -RecordType $RecordType `
                -Selectors $Selectors -Progress $progress -CancelCheck $cancel
            $Shared.Findings = @()
        } else {
            $rep = Get-DomainDnsReport -Domain $Domain -Selectors $Selectors -Resolver $Resolver -Progress $progress
            $Shared.Text = $rep.Text
            $Shared.Findings = @($rep.Findings)
        }
        $Shared.Ready = $true
    } catch {
        $Shared.Error = $_.Exception.Message
    } finally {
        $Shared.Done = $true
    }
}

function Get-SelectedResolver {
    switch ($script:cboResolver.SelectedIndex) {
        0 { return '1.1.1.1' }
        1 { return '8.8.8.8' }
        2 { return '9.9.9.9' }
        default { return '' }   # this PC's DNS
    }
}

function Set-DnsBusy {
    param([bool]$Busy)
    $script:btnDnsCheck.Enabled = -not $Busy
    $script:btnDnsProp.Enabled = -not $Busy
    $script:txtDnsDomain.Enabled = -not $Busy
    $script:cboResolver.Enabled = -not $Busy
    $script:btnDnsStop.Enabled = $Busy
}

function Render-DnsFindings {
    param($findings)
    $script:panelDnsFindings.Controls.Clear()
    foreach ($f in @($findings)) {
        $lab = New-Object System.Windows.Forms.Label
        $lab.AutoSize = $true
        $lab.Margin = New-Object System.Windows.Forms.Padding(0, 2, 14, 0)
        $lab.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $lab.Text = ('{0}: {1} ({2})' -f $f.Area, $f.Status, $f.Detail)
        switch ([string]$f.Status) {
            'OK'    { $lab.ForeColor = $Theme.Good }
            'FOUND' { $lab.ForeColor = $Theme.Good }
            'WARN'  { $lab.ForeColor = $Theme.Warn }
            'FAIL'  { $lab.ForeColor = $Theme.Bad }
            default { $lab.ForeColor = [System.Drawing.Color]::DimGray }
        }
        [void]$script:panelDnsFindings.Controls.Add($lab)
    }
}

function Start-DnsJob {
    param([string]$Mode)
    if ($script:dnsActive) { return }
    $domain = $script:txtDnsDomain.Text.Trim()
    # Accept a pasted URL or host and reduce it to something checkable.
    $hostOnly = Get-HostFromUrl $domain
    if ($hostOnly) { $domain = $hostOnly }
    if (-not $domain) {
        [void][System.Windows.Forms.MessageBox]::Show('Enter a domain to check.', 'IP Triage', 'OK', 'Warning'); return
    }
    $script:txtDnsDomain.Text = $domain

    $recordType = [string]$script:cboPropType.SelectedItem
    if ($Mode -eq 'Propagation' -and $recordType -eq 'DKIM') {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            ('A DKIM propagation sweep probes every known selector against 8 resolvers - ' +
             'hundreds of queries, and it can take several minutes.' + [Environment]::NewLine + [Environment]::NewLine +
             'Continue?'),
            'DKIM propagation', 'YesNo', 'Question')
        if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    $selectors = @($script:txtDnsSelectors.Text -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $script:dnsActive = $true
    $script:txtDns.Clear()
    $script:panelDnsFindings.Controls.Clear()
    $script:lblDnsStatus.ForeColor = [System.Drawing.Color]::Black
    $script:lblDnsStatus.Text = 'Starting...'
    Set-DnsBusy $true

    $shared = [hashtable]::Synchronized(@{})
    $shared.Status = ''; $shared.Text = ''; $shared.Findings = @()
    $shared.Done = $false; $shared.Ready = $false; $shared.Cancel = $false; $shared.Error = $null
    $script:dnsShared = $shared

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.ApartmentState = 'MTA'
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($DnsWorkerScript.ToString())
    [void]$ps.AddParameter('Shared', $shared)
    [void]$ps.AddParameter('HelpersSource', $HelpersSource)
    [void]$ps.AddParameter('Domain', $domain)
    [void]$ps.AddParameter('Selectors', $selectors)
    [void]$ps.AddParameter('Resolver', (Get-SelectedResolver))
    [void]$ps.AddParameter('Mode', $Mode)
    [void]$ps.AddParameter('RecordType', $recordType)
    $script:dnsPs = $ps
    $script:dnsRs = $rs
    $script:dnsAsync = $ps.BeginInvoke()
    $script:dnsTimer.Start()
}

function Open-LookupUrl {
    # Opens an external reputation / certificate-transparency site in the default
    # browser. The value is checked against an address-shaped pattern and then
    # URL-encoded, so nothing odd in the box can be smuggled into the URL.
    param([string]$UrlTemplate, [string]$Value, [string]$What)
    $v = ''
    if ($Value) { $v = $Value.Trim() }
    if (-not $v) {
        [void][System.Windows.Forms.MessageBox]::Show(('Enter a {0} first.' -f $What), 'IP Triage', 'OK', 'Warning')
        return
    }
    if ($v -notmatch '^[A-Za-z0-9][A-Za-z0-9\.\-:]*$') {
        [void][System.Windows.Forms.MessageBox]::Show(
            ('"{0}" does not look like a {1}.' -f $v, $What), 'IP Triage', 'OK', 'Warning')
        return
    }
    $url = $UrlTemplate -f [System.Uri]::EscapeDataString($v)
    try { Start-Process $url }
    catch {
        [void][System.Windows.Forms.MessageBox]::Show(
            ('Could not open the browser: {0}' -f $_.Exception.Message), 'IP Triage', 'OK', 'Warning')
    }
}

function Show-ApiKeyDialog {
    # The dialog is built in the helpers file (New-ApiKeyDialog) so it can be
    # constructed and render-tested without entering a modal loop.
    $dlg = New-ApiKeyDialog -Theme $Theme
    [void]$dlg.ShowDialog($script:form)
    $dlg.Dispose()
}
function Clear-All {
    if ($script:scanActive) { return }
    # Clear the target too - otherwise "Clear" leaves the previous (or the
    # clipboard-prefilled) address sitting in the box.
    $script:txtIp.Clear()
    $script:lblResolved.Text = ''
    $script:txtIp.Focus()
    Hide-RiskBanner
    Clear-DnsTab
    $script:txtSummary.Clear(); $script:txtSecurity.Clear(); $script:txtNetwork.Clear(); $script:txtLog.Clear(); $script:txtSvcDetail.Clear()
    $script:gridServices.Rows.Clear(); $script:gridCerts.Rows.Clear(); $script:gridDomains.Rows.Clear(); $script:gridEvidence.Rows.Clear()
    $script:progress.Value = 0
    $script:lastReport = ''
    $script:lblStatus.Text = 'Cleared.'
}

# ---- Timer ----
$script:timer = New-Object System.Windows.Forms.Timer
$script:timer.Interval = 200
$script:timer.Add_Tick({
    $sh = $script:shared
    if (-not $sh) { return }

    if ($null -ne $sh.Log) {
        $count = $sh.Log.Count
        while ($script:logIndex -lt $count) {
            $script:txtLog.AppendText([string]$sh.Log[$script:logIndex] + [Environment]::NewLine)
            $script:logIndex++
        }
    }

    $p = [int]$sh.Progress
    if ($p -lt 0) { $p = 0 }; if ($p -gt 100) { $p = 100 }
    $script:progress.Value = $p
    $script:lblStatus.Text = [string]$sh.Status

    if ($sh.NetworkReady -and -not $script:networkRendered) { Render-Network $sh; $script:networkRendered = $true }
    if ($sh.ProbeReady -and $sh.ProbeVersion -ne $script:probeVersionRendered) { Render-Services $sh; Render-Certs $sh; $script:probeVersionRendered = $sh.ProbeVersion }
    if ($sh.DomainsReady -and $sh.DomainsVersion -ne $script:domainsVersionRendered) { Render-Domains $sh; Set-DnsDomainFromTriage $sh; $script:domainsVersionRendered = $sh.DomainsVersion }
    if ($sh.EvidenceReady -and -not $script:evidenceRendered) { Render-Evidence $sh; $script:evidenceRendered = $true }
    if ($sh.SummaryReady -and -not $script:summaryRendered) { Render-Summary $sh; Render-Security $sh; Show-RiskBanner $sh; $script:summaryRendered = $true }

    if ($sh.Done) {
        $script:timer.Stop()
        try { $script:ps.EndInvoke($script:async) } catch {}
        try { $script:ps.Dispose() } catch {}
        try { $script:rs.Close(); $script:rs.Dispose() } catch {}
        $script:scanActive = $false
        Set-Busy $false
        # Final render pass in case the last flags landed on the same tick as Done.
        if ($sh.NetworkReady) { Render-Network $sh }
        if ($sh.ProbeReady) { Render-Services $sh; Render-Certs $sh }
        if ($sh.DomainsReady) { Render-Domains $sh; Set-DnsDomainFromTriage $sh }
        if ($sh.EvidenceReady) { Render-Evidence $sh }
        if ($sh.SummaryReady) { Render-Summary $sh; Render-Security $sh; Show-RiskBanner $sh }
        if ($sh.Error) {
            $script:lblStatus.Text = 'Error: ' + $sh.Error
            $script:lblStatus.ForeColor = $Theme.Bad
        } elseif ($sh.Cancel) {
            $script:lblStatus.Text = 'Stopped.'
            $script:lblStatus.ForeColor = [System.Drawing.Color]::Black
        } else {
            $risk = ''; $colour = [System.Drawing.Color]::Black
            if ($sh.Risk) {
                $risk = ('   Risk: {0}' -f $sh.Risk.Level)
                switch ($sh.Risk.Level) {
                    'High'   { $colour = $Theme.Bad }
                    'Medium' { $colour = $Theme.Warn }
                    default  { $colour = $Theme.Good }
                }
            }
            $knownTxt = ''
            if ($sh.KnownMatch -and $sh.KnownMatch.Matched) { $knownTxt = ('   [{0}: {1}]' -f $sh.KnownMatch.Type, $sh.KnownMatch.Label) }
            $script:lblStatus.Text = ('Done.{0}{1}' -f $risk, $knownTxt)
            $script:lblStatus.ForeColor = $colour
        }
        if ($script:selfTestPngPath) {
            if ($script:selfTestTabName) {
                foreach ($tp in $script:tabs.TabPages) {
                    if ($tp.Text -eq $script:selfTestTabName) { $script:tabs.SelectedTab = $tp; break }
                }
                [System.Windows.Forms.Application]::DoEvents()
            }
            try { Save-FormPng $script:form $script:selfTestPngPath } catch {}
            $script:form.Close()
        }
    }
})

# ---- Services grid selection -> detail ----
$script:gridServices.Add_SelectionChanged({
    if ($script:gridServices.SelectedRows.Count -gt 0 -and $script:shared) {
        $port = [string]$script:gridServices.SelectedRows[0].Cells['svcPort'].Value
        $match = @($script:shared.Probe) | Where-Object { [string]$_.Port -eq $port } | Select-Object -First 1
        if ($match) { $script:txtSvcDetail.Text = [string]$match.Detail }
    }
})
$script:gridServices.Add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -lt 0) { return }
    $port = [string]$script:gridServices.Rows[$e.RowIndex].Cells['svcPort'].Value
    $state = [string]$script:gridServices.Rows[$e.RowIndex].Cells['svcState'].Value
    $svc = [string]$script:gridServices.Rows[$e.RowIndex].Cells['svcName'].Value
    if ($state -eq 'Open' -and $svc -match 'HTTP') {
        $scheme = if ($svc -match 'HTTPS') { 'https' } else { 'http' }
        $url = ('{0}://{1}:{2}/' -f $scheme, $script:txtIp.Text, $port)
        try { Start-Process $url } catch {}
    }
})

# ---- Wire events ----
$script:btnLookup.Add_Click({ Start-Lookup })
$script:btnStop.Add_Click({
    if ($script:scanActive -and $script:shared) { $script:shared.Cancel = $true; $script:lblStatus.Text = 'Stopping...'; $script:btnStop.Enabled = $false }
})
$script:btnCopy.Add_Click({ Copy-Report })
$script:btnSave.Add_Click({ Save-Report })
$script:btnClear.Add_Click({ Clear-All })
$script:btnApiKey.Add_Click({ Show-ApiKeyDialog })
$script:btnTalos.Add_Click({
    Open-LookupUrl 'https://www.talosintelligence.com/reputation_center/lookup?search={0}' $script:txtIp.Text 'IP address'
})

# ---- DNS tab timer and wiring ----
$script:dnsActive = $false
$script:dnsShared = $null
$script:dnsPs = $null
$script:dnsRs = $null
$script:dnsAsync = $null
$script:dnsTimer = New-Object System.Windows.Forms.Timer
$script:dnsTimer.Interval = 200
$script:dnsTimer.Add_Tick({
    $sh = $script:dnsShared
    if (-not $sh) { return }
    if ($sh.Status) { $script:lblDnsStatus.Text = [string]$sh.Status }
    if ($sh.Done) {
        $script:dnsTimer.Stop()
        try { $script:dnsPs.EndInvoke($script:dnsAsync) } catch {}
        try { $script:dnsPs.Dispose() } catch {}
        try { $script:dnsRs.Close(); $script:dnsRs.Dispose() } catch {}
        $script:dnsActive = $false
        Set-DnsBusy $false
        if ($sh.Error) {
            $script:lblDnsStatus.ForeColor = $Theme.Bad
            $script:lblDnsStatus.Text = 'Error: ' + $sh.Error
        } else {
            $script:txtDns.Text = [string]$sh.Text
            Render-DnsFindings $sh.Findings
            $script:lblDnsStatus.ForeColor = [System.Drawing.Color]::Black
            $script:lblDnsStatus.Text = if ($sh.Cancel) { 'Stopped.' } else { 'Done.' }
        }
        # Test hook: when the DNS job is what we were asked to capture, the
        # screenshot waits for THIS job rather than the triage one.
        if ($script:selfTestDnsPending -and $script:selfTestPngPath) {
            $script:selfTestDnsPending = $false
            foreach ($tp in $script:tabs.TabPages) {
                if ($tp.Text -eq 'DNS / MX') { $script:tabs.SelectedTab = $tp; break }
            }
            [System.Windows.Forms.Application]::DoEvents()
            try { Save-FormPng $script:form $script:selfTestPngPath } catch {}
            $script:form.Close()
        }
    }
})

$script:btnDnsCheck.Add_Click({ Start-DnsJob 'Report' })
$script:btnDnsProp.Add_Click({ Start-DnsJob 'Propagation' })
$script:btnDnsStop.Add_Click({
    if ($script:dnsActive -and $script:dnsShared) {
        $script:dnsShared.Cancel = $true
        $script:lblDnsStatus.Text = 'Stopping...'
        $script:btnDnsStop.Enabled = $false
    }
})
$script:btnDnsCopy.Add_Click({
    if (-not $script:txtDns.Text) {
        [void][System.Windows.Forms.MessageBox]::Show('Nothing to copy yet.', 'IP Triage', 'OK', 'Information'); return
    }
    try { [System.Windows.Forms.Clipboard]::SetText($script:txtDns.Text); $script:lblDnsStatus.Text = 'Copied.' }
    catch { [void][System.Windows.Forms.MessageBox]::Show('Could not access the clipboard.', 'IP Triage', 'OK', 'Warning') }
})
$script:btnCrtSh.Add_Click({ Open-LookupUrl 'https://crt.sh/?q={0}' $script:txtDnsDomain.Text 'domain' })
$script:btnCtLogs.Add_Click({ Open-LookupUrl 'https://ctlogs.dev/search?q={0}' $script:txtDnsDomain.Text 'domain' })
$script:txtDnsDomain.Add_KeyDown({ param($sender, $e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Start-DnsJob 'Report' } })
$bannerJump = {
    foreach ($tp in $script:tabs.TabPages) { if ($tp.Text -like 'Security*') { $script:tabs.SelectedTab = $tp; break } }
}
$script:panelBanner.Add_Click($bannerJump)
$script:lblBannerHead.Add_Click($bannerJump)
$script:lblBannerDetail.Add_Click($bannerJump)
$script:txtIp.Add_KeyDown({ param($sender, $e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Start-Lookup } })

$script:form.AcceptButton = $script:btnLookup

$script:form.Add_FormClosing({
    try { $script:timer.Stop() } catch {}
    try { if ($script:shared) { $script:shared.Cancel = $true } } catch {}
    try { if ($script:ps) { $script:ps.Dispose() } } catch {}
    try { if ($script:rs) { $script:rs.Close(); $script:rs.Dispose() } } catch {}
    try { $script:dnsTimer.Stop() } catch {}
    try { if ($script:dnsShared) { $script:dnsShared.Cancel = $true } } catch {}
    try { if ($script:dnsPs) { $script:dnsPs.Dispose() } } catch {}
    try { if ($script:dnsRs) { $script:dnsRs.Close(); $script:dnsRs.Dispose() } } catch {}
})

# ---- Prefill ----
if ($Ip) {
    $script:txtIp.Text = $Ip
} elseif (-not $NoClipboard) {
    # Convenience only: prefill from a LITERAL IP on the clipboard. It is
    # announced in the status bar and pre-selected, so typing replaces it and
    # you can see why the box is not empty. -NoClipboard turns it off.
    try {
        $clip = [System.Windows.Forms.Clipboard]::GetText()
        $clipIp = Get-FirstIpv4 $clip
        if ($clipIp) {
            $script:txtIp.Text = $clipIp
            $script:lblStatus.Text = ('Prefilled {0} from the clipboard - type over it, or press Clear.' -f $clipIp)
            $script:form.Add_Shown({ $script:txtIp.Focus(); $script:txtIp.SelectAll() })
        }
    } catch {}
}
if ($Probe) { $script:chkProbe.Checked = $true }

# ---- Self-test / auto-run hooks ----
$script:selfTestPngPath = $SelfTestPng
$script:selfTestTabName = $SelfTestTab
$script:selfTestDnsPending = $false
if ($SelfTestDnsDomain) {
    # Run a DNS check on startup and let its completion drive the capture.
    $script:selfTestDnsPending = $true
    $script:form.Add_Shown({
        $script:txtDnsDomain.Text = $SelfTestDnsDomain
        Start-DnsJob 'Report'
    })
}
if ($AutoRun -and $script:txtIp.Text) {
    $script:form.Add_Shown({ Start-Lookup })
}

[void]$script:form.ShowDialog()
