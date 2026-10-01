<#
    IP-Triage - worker helpers (Windows PowerShell 5.1)
    ---------------------------------------------------
    Loaded as TEXT by IP-Triage.ps1 (Get-Content -Raw) and dot-sourced into
    BOTH the UI thread and the background runspace from that one definition.

    Purpose: an MSP-facing tool that identifies the business/network behind a
    public IP from an alert, log or firewall entry, and (opt-in) reports what services
    answer on it, for our own troubleshooting. All lookups here are keyless.

    Rules for anything added here:
      * PowerShell 5.1 only. No PS7 syntax (no ternary, ?., ??, -Parallel,
        -SkipCertificateCheck) and no System.Buffers.* / BinaryPrimitives.
      * Function definitions ONLY - nothing executes at load time, because the
        file is dot-sourced onto the UI thread during form construction.
      * The runspace does not inherit script variables, so helpers must not read
        any script-scope state; pass it in or return it.
#>

# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------
function Get-FirstIpv4 {
    # Pulls the first LITERAL IPv4 address out of arbitrary text (an alert line,
    # a URL, "ip:port", or a bare address). Returns '' when none is present.
    # Deliberately does NO name resolution - the clipboard prefill relies on
    # that, so a copied URL never silently turns into a resolved address. Use
    # Resolve-TargetInput when you do want a hostname resolved.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $rx = [regex]::Matches($Text, '(?<!\d)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d)')
    foreach ($m in $rx) {
        $o1 = [int]$m.Groups[1].Value; $o2 = [int]$m.Groups[2].Value
        $o3 = [int]$m.Groups[3].Value; $o4 = [int]$m.Groups[4].Value
        if ($o1 -le 255 -and $o2 -le 255 -and $o3 -le 255 -and $o4 -le 255) {
            return ('{0}.{1}.{2}.{3}' -f $o1, $o2, $o3, $o4)
        }
    }
    return ''
}

function Resolve-TargetInput {
    # Turns whatever was typed into a target. A literal IPv4 wins; otherwise the
    # text is treated as a hostname (or URL) and resolved, so you can paste
    # "mail.example.com.au" or "https://host/path" for a quick lookup.
    # Returns the IP to triage plus the hostname it came from.
    param([string]$Text)
    $out = [pscustomobject]@{
        Ip = ''; InputHost = ''; AllIps = @(); Resolved = $false; Error = ''
    }
    if ([string]::IsNullOrWhiteSpace($Text)) { $out.Error = 'Enter an IP address or hostname.'; return $out }

    $literal = Get-FirstIpv4 $Text
    if ($literal) { $out.Ip = $literal; $out.AllIps = @($literal); return $out }

    $hostName = Get-HostFromUrl $Text
    if (-not $hostName) { $out.Error = 'That is not an IP address or a hostname.'; return $out }
    $out.InputHost = $hostName
    try {
        $addrs = @([System.Net.Dns]::GetHostAddresses($hostName) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.IPAddressToString })
        if (@($addrs).Count -gt 0) {
            $out.Ip = @($addrs)[0]
            $out.AllIps = @($addrs)
            $out.Resolved = $true
        } else {
            $out.Error = ('{0} has no IPv4 address.' -f $hostName)
        }
    } catch {
        $out.Error = ('Could not resolve {0}.' -f $hostName)
    }
    return $out
}

function Get-IpClass {
    # Classifies an IPv4 address. Returns Class (Public/Private/Loopback/
    # LinkLocal/CGNAT/Multicast/Reserved) and IsPublic.
    param([string]$Ip)
    $parts = $Ip.Split('.')
    if (@($parts).Count -ne 4) {
        return [pscustomobject]@{ Class = 'Invalid'; IsPublic = $false }
    }
    $a = [int]$parts[0]; $b = [int]$parts[1]
    $class = 'Public'
    if     ($a -eq 10)                              { $class = 'Private' }
    elseif ($a -eq 172 -and $b -ge 16 -and $b -le 31) { $class = 'Private' }
    elseif ($a -eq 192 -and $b -eq 168)            { $class = 'Private' }
    elseif ($a -eq 127)                            { $class = 'Loopback' }
    elseif ($a -eq 169 -and $b -eq 254)            { $class = 'LinkLocal' }
    elseif ($a -eq 100 -and $b -ge 64 -and $b -le 127) { $class = 'CGNAT' }
    elseif ($a -ge 224 -and $a -le 239)            { $class = 'Multicast' }
    elseif ($a -eq 0 -or $a -ge 240)               { $class = 'Reserved' }
    [pscustomobject]@{ Class = $class; IsPublic = ($class -eq 'Public') }
}

# ---------------------------------------------------------------------------
# Passive lookups
# ---------------------------------------------------------------------------
function Get-PtrRecord {
    param([string]$Ip)
    $names = [System.Collections.Generic.List[string]]::new()
    try {
        $recs = Resolve-DnsName -Name $Ip -Type PTR -DnsOnly -ErrorAction Stop
        foreach ($r in $recs) {
            if ($r.NameHost) { [void]$names.Add([string]$r.NameHost) }
        }
    } catch {
        try {
            $he = [System.Net.Dns]::GetHostEntry($Ip)
            if ($he -and $he.HostName) { [void]$names.Add([string]$he.HostName) }
        } catch {}
    }
    return @($names.ToArray())
}

function Test-GenericPtr {
    # A PTR that merely embeds the IP's own octets (any order) tells you the ISP,
    # not the customer. Flag those as low-value.
    param([string]$Ptr, [string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ptr)) { return $true }
    $octets = $Ip.Split('.')
    $hits = 0
    foreach ($o in $octets) { if ($Ptr -match ('(?<!\d){0}(?!\d)' -f [regex]::Escape($o))) { $hits++ } }
    # 3+ of the 4 octets appearing in the name = generic reverse record.
    return ($hits -ge 3)
}

function Get-AsnInfo {
    # Team Cymru IP-to-ASN over DNS TXT. Keyless, no HTTP.
    param([string]$Ip)
    $result = [pscustomobject]@{
        Asn = ''; Prefix = ''; Country = ''; Registry = ''; Allocated = ''; AsName = ''
    }
    try {
        $octets = $Ip.Split('.')
        $rev = '{0}.{1}.{2}.{3}' -f $octets[3], $octets[2], $octets[1], $octets[0]
        $txt = Resolve-DnsName -Name ("$rev.origin.asn.cymru.com") -Type TXT -DnsOnly -ErrorAction Stop |
            Where-Object { $_.Strings } | Select-Object -First 1
        if ($txt) {
            $line = ($txt.Strings -join '')
            $f = $line.Split('|') | ForEach-Object { $_.Trim() }
            if (@($f).Count -ge 5) {
                $result.Asn = $f[0]; $result.Prefix = $f[1]; $result.Country = $f[2]
                $result.Registry = $f[3]; $result.Allocated = $f[4]
            }
            if ($result.Asn) {
                try {
                    $atxt = Resolve-DnsName -Name ("AS{0}.asn.cymru.com" -f $result.Asn) -Type TXT -DnsOnly -ErrorAction Stop |
                        Where-Object { $_.Strings } | Select-Object -First 1
                    if ($atxt) {
                        $af = (($atxt.Strings -join '').Split('|') | ForEach-Object { $_.Trim() })
                        if (@($af).Count -ge 5) { $result.AsName = $af[4] }
                    }
                } catch {}
            }
        }
    } catch {}
    return $result
}

function Invoke-JsonGet {
    # Small GET returning parsed JSON (or $null). Uses the system proxy.
    # $Headers carries an API key where one is needed (e.g. AbuseIPDB's 'Key').
    param([string]$Url, [int]$TimeoutMs = 8000, $Headers = $null)
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'
        $req.Timeout = $TimeoutMs
        $req.UserAgent = 'IP-Triage/1.0'
        $req.Accept = 'application/json'
        if ($Headers) {
            foreach ($k in $Headers.Keys) { $req.Headers.Add([string]$k, [string]$Headers[$k]) }
        }
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $sr.ReadToEnd()
        $sr.Close(); $resp.Close()
        if ([string]::IsNullOrWhiteSpace($body)) { return $null }
        $parsed = $body | ConvertFrom-Json
        return $parsed
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) {
            try {
                $sr2 = New-Object System.IO.StreamReader($r.GetResponseStream())
                $b2 = $sr2.ReadToEnd(); $sr2.Close()
                return [pscustomobject]@{ __httperror = [int]$r.StatusCode; __body = $b2 }
            } catch {}
        }
        return $null
    } catch { return $null }
}

function Invoke-TextGet {
    # Keyless GET returning the raw body text (or ''). Uses the system proxy.
    param([string]$Url, [int]$TimeoutMs = 12000)
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'
        $req.Timeout = $TimeoutMs
        $req.UserAgent = 'IP-Triage/1.0'
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $sr.ReadToEnd()
        $sr.Close(); $resp.Close()
        return [string]$body
    } catch [System.Net.WebException] {
        $r = $_.Exception.Response
        if ($r) {
            try {
                $sr2 = New-Object System.IO.StreamReader($r.GetResponseStream())
                $b2 = $sr2.ReadToEnd(); $sr2.Close(); return [string]$b2
            } catch {}
        }
        return ''
    } catch { return '' }
}

function Get-RdapIp {
    # RDAP IP record via rdap.org (redirects to the right RIR). Org-level fields.
    param([string]$Ip)
    $out = [pscustomobject]@{
        Handle = ''; Name = ''; StartAddress = ''; EndAddress = ''; Country = ''
        Type = ''; Entities = @(); Remarks = @()
    }
    $j = Invoke-JsonGet ("https://rdap.org/ip/{0}" -f $Ip)
    if (-not $j -or ($j.PSObject.Properties.Name -contains '__httperror')) { return $out }
    $out.Handle = [string]$j.handle
    $out.Name = [string]$j.name
    $out.StartAddress = [string]$j.startAddress
    $out.EndAddress = [string]$j.endAddress
    $out.Country = [string]$j.country
    $out.Type = [string]$j.type
    $ents = [System.Collections.Generic.List[object]]::new()
    if ($j.entities) {
        foreach ($e in $j.entities) {
            $fn = Get-VcardField $e 'fn'
            $org = Get-VcardField $e 'org'
            [void]$ents.Add([pscustomobject]@{
                Handle = [string]$e.handle
                Roles  = (@($e.roles) -join ', ')
                Name   = $fn
                Org    = $org
            })
        }
    }
    $out.Entities = @($ents.ToArray())
    $rem = [System.Collections.Generic.List[string]]::new()
    if ($j.remarks) {
        foreach ($rm in $j.remarks) {
            $t = [string]$rm.title
            $d = (@($rm.description) -join ' ')
            $line = (($t + ': ' + $d).Trim(': ').Trim())
            if ($line) { [void]$rem.Add($line) }
        }
    }
    $out.Remarks = @($rem.ToArray())
    return $out
}

function Get-VcardField {
    # Extracts a jCard field value (fn, org, ...) from an RDAP entity.
    param($Entity, [string]$Field)
    try {
        if (-not $Entity.vcardArray) { return '' }
        $arr = $Entity.vcardArray[1]
        foreach ($item in $arr) {
            if ([string]$item[0] -eq $Field) {
                $val = $item[3]
                if ($val -is [array]) { return (@($val) -join ' ') }
                return [string]$val
            }
        }
    } catch {}
    return ''
}

function Get-IpGeo {
    # ipinfo.io tokenless. Degrades quietly on 429.
    param([string]$Ip)
    $out = [pscustomobject]@{
        City = ''; Region = ''; Country = ''; Org = ''; Postal = ''; Timezone = ''; Hostname = ''; Limited = $false
    }
    $j = Invoke-JsonGet ("https://ipinfo.io/{0}/json" -f $Ip)
    if (-not $j) { return $out }
    if ($j.PSObject.Properties.Name -contains '__httperror') {
        if ($j.__httperror -eq 429) { $out.Limited = $true }
        return $out
    }
    $out.City = [string]$j.city; $out.Region = [string]$j.region; $out.Country = [string]$j.country
    $out.Org = [string]$j.org; $out.Postal = [string]$j.postal; $out.Timezone = [string]$j.timezone
    $out.Hostname = [string]$j.hostname
    return $out
}

function Get-InternetDb {
    # Shodan InternetDB - passively collected ports/hostnames/CPEs/tags. Keyless.
    param([string]$Ip)
    $out = [pscustomobject]@{ Ports = @(); Hostnames = @(); Cpes = @(); Tags = @(); Vulns = @(); Found = $false }
    $j = Invoke-JsonGet ("https://internetdb.shodan.io/{0}" -f $Ip)
    if (-not $j -or ($j.PSObject.Properties.Name -contains '__httperror')) { return $out }
    if ($j.ports)     { $out.Ports     = @($j.ports) }
    if ($j.hostnames) { $out.Hostnames = @($j.hostnames) }
    if ($j.cpes)      { $out.Cpes      = @($j.cpes) }
    if ($j.tags)      { $out.Tags      = @($j.tags) }
    if ($j.vulns)     { $out.Vulns     = @($j.vulns) }
    $out.Found = $true
    return $out
}

function Get-ReverseIpDomains {
    # HackerTarget reverse-IP (about 50/day without a key). Detects the quota
    # message. Returns names hosted on the IP.
    param([string]$Ip)
    $out = [pscustomobject]@{ Names = @(); Limited = $false; Note = '' }
    $body = Invoke-TextGet ("https://api.hackertarget.com/reverseiplookup/?q={0}" -f $Ip)
    if ([string]::IsNullOrWhiteSpace($body)) { return $out }
    if ($body -match 'API count exceeded' -or $body -match 'error check your search') {
        $out.Limited = $true; $out.Note = $body.Trim(); return $out
    }
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($body -split "`n")) {
        $t = $line.Trim()
        if ($t -and $t -match '^[A-Za-z0-9\.\-]+$' -and $t -match '\.') { [void]$names.Add($t) }
    }
    $out.Names = @($names.ToArray())
    return $out
}

function Get-TorExitList {
    # Bulk Tor exit list, once per session (the caller caches it).
    $out = [System.Collections.Generic.HashSet[string]]::new()
    $body = Invoke-TextGet 'https://check.torproject.org/torbulkexitlist' 15000
    if ($body) {
        foreach ($line in ($body -split "`n")) {
            $t = $line.Trim()
            if ($t -match '^\d{1,3}(\.\d{1,3}){3}$') { [void]$out.Add($t) }
        }
    }
    return $out
}

# ---------------------------------------------------------------------------
# Domain registration (organisation-level only)
# ---------------------------------------------------------------------------
function Get-RegisteredDomain {
    # Reduces a hostname to its registrable domain using a small multi-label
    # suffix list plus a single-label eTLD fallback. Returns '' for internal
    # / non-registrable names (.local, single label, etc).
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $n = $Name.Trim('.').ToLower()
    if ($n -notmatch '\.') { return '' }
    if ($n -match '\.(local|lan|internal|corp|home|intranet)$') { return '' }
    $multi = @(
        'com.au','net.au','org.au','edu.au','gov.au','asn.au','id.au',
        'co.uk','org.uk','me.uk','gov.uk','ac.uk',
        'co.nz','net.nz','org.nz','govt.nz',
        'com.sg','com.my','co.za','com.br','co.in','co.jp','com.cn','com.hk'
    )
    $labels = $n.Split('.')
    foreach ($suffix in $multi) {
        if ($n -like ('*.' + $suffix) -or $n -eq $suffix) {
            $sc = $suffix.Split('.').Count
            if (@($labels).Count -ge ($sc + 1)) {
                return (($labels[($labels.Count - $sc - 1)..($labels.Count - 1)]) -join '.')
            }
            return ''
        }
    }
    # Ordinary single-label TLD: keep the last two labels.
    return (($labels[($labels.Count - 2)..($labels.Count - 1)]) -join '.')
}

function Invoke-Whois {
    # Port-43 WHOIS with one referral hop. Returns raw text.
    param([string]$Query, [string]$Server = '', [int]$TimeoutMs = 8000)
    if (-not $Server) {
        $Server = 'whois.iana.org'
    }
    $raw = Read-WhoisRaw -Server $Server -Query $Query -TimeoutMs $TimeoutMs
    return $raw
}

function Read-WhoisRaw {
    param([string]$Server, [string]$Query, [int]$TimeoutMs = 8000)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($Server, 43, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return '' }
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $writer = [System.IO.StreamWriter]::new($stream)
        $writer.NewLine = "`r`n"
        $writer.WriteLine($Query)
        $writer.Flush()
        $reader = [System.IO.StreamReader]::new($stream)
        $text = $reader.ReadToEnd()
        return [string]$text
    } catch { return '' } finally { try { $client.Close() } catch {} }
}

function Get-WhoisReferral {
    # Finds the 'refer:'/'whois:' server in an IANA WHOIS response.
    param([string]$Text)
    foreach ($line in ($Text -split "`n")) {
        if ($line -match '^\s*(refer|whois):\s*(\S+)') {
            $srv = $matches[2].Trim()
            return $srv
        }
    }
    return ''
}

function Get-DomainRegistration {
    # Organisation-level registration for a domain. Tries RDAP, then port-43
    # WHOIS via the IANA referral. Keeps only org/registrar/status/dates/NS -
    # personal contact fields (names, emails, phones, addresses) are dropped.
    param([string]$Domain)
    $out = [pscustomobject]@{
        Domain = $Domain; Registrar = ''; RegistrantOrg = ''; Eligibility = ''
        Status = ''; Created = ''; Updated = ''; Expires = ''; NameServers = @()
        Source = ''; Ok = $false
    }
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $out }

    # --- RDAP ---
    $j = Invoke-JsonGet ("https://rdap.org/domain/{0}" -f $Domain)
    if ($j -and -not ($j.PSObject.Properties.Name -contains '__httperror')) {
        $out.Source = 'RDAP'; $out.Ok = $true
        if ($j.entities) {
            foreach ($e in $j.entities) {
                $roles = @($e.roles)
                if ($roles -contains 'registrar' -and -not $out.Registrar) {
                    $rn = Get-VcardField $e 'fn'; if (-not $rn) { $rn = Get-VcardField $e 'org' }
                    $out.Registrar = $rn
                }
                if ($roles -contains 'registrant') {
                    $org = Get-VcardField $e 'org'; if (-not $org) { $org = Get-VcardField $e 'fn' }
                    $out.RegistrantOrg = $org
                }
            }
        }
        if ($j.events) {
            foreach ($ev in $j.events) {
                switch ([string]$ev.eventAction) {
                    'registration'      { $out.Created = [string]$ev.eventDate }
                    'last changed'      { $out.Updated = [string]$ev.eventDate }
                    'expiration'        { $out.Expires = [string]$ev.eventDate }
                }
            }
        }
        if ($j.status) { $out.Status = (@($j.status) -join ', ') }
        $ns = [System.Collections.Generic.List[string]]::new()
        if ($j.nameservers) { foreach ($n in $j.nameservers) { if ($n.ldhName) { [void]$ns.Add([string]$n.ldhName) } } }
        $out.NameServers = @($ns.ToArray())
    }

    # --- WHOIS fallback / enrichment (needed for .au registrant org) ---
    if (-not $out.RegistrantOrg) {
        $iana = Invoke-Whois -Query $Domain -Server 'whois.iana.org'
        $srv = Get-WhoisReferral $iana
        $tld = $Domain.Split('.')[-1]
        if (-not $srv) {
            switch ($tld) {
                'au' { $srv = 'whois.auda.org.au' }
                'nz' { $srv = 'whois.srs.net.nz' }
                'uk' { $srv = 'whois.nic.uk' }
            }
        }
        if ($srv) {
            $wr = Read-WhoisRaw -Server $srv -Query $Domain
            $parsed = ConvertFrom-WhoisText -Text $wr
            if (-not $out.Registrar -and $parsed.Registrar) { $out.Registrar = $parsed.Registrar }
            if (-not $out.RegistrantOrg -and $parsed.RegistrantOrg) { $out.RegistrantOrg = $parsed.RegistrantOrg }
            if (-not $out.Status -and $parsed.Status) { $out.Status = $parsed.Status }
            if (-not $out.Created -and $parsed.Created) { $out.Created = $parsed.Created }
            if (-not $out.Updated -and $parsed.Updated) { $out.Updated = $parsed.Updated }
            if (-not $out.Expires -and $parsed.Expires) { $out.Expires = $parsed.Expires }
            if ($parsed.Eligibility) { $out.Eligibility = $parsed.Eligibility }
            if (@($out.NameServers).Count -eq 0 -and @($parsed.NameServers).Count -gt 0) { $out.NameServers = $parsed.NameServers }
            if ($parsed.RegistrantOrg -or $parsed.Registrar) { $out.Ok = $true; if (-not $out.Source) { $out.Source = 'WHOIS' } else { $out.Source = 'RDAP+WHOIS' } }
        }
    }
    return $out
}

function ConvertFrom-WhoisText {
    # Parses a port-43 WHOIS body, keeping ONLY organisation-level fields.
    # Individual registrant name/email/phone/address are intentionally ignored.
    param([string]$Text)
    $out = [pscustomobject]@{
        Registrar = ''; RegistrantOrg = ''; Status = ''; Created = ''; Updated = ''
        Expires = ''; Eligibility = ''; NameServers = @()
    }
    if ([string]::IsNullOrWhiteSpace($Text)) { return $out }
    $ns = [System.Collections.Generic.List[string]]::new()
    $statuses = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`n")) {
        $l = $line.Trim()
        if (-not $l -or $l.StartsWith('%') -or $l.StartsWith('#')) { continue }
        $idx = $l.IndexOf(':')
        if ($idx -lt 1) { continue }
        $key = $l.Substring(0, $idx).Trim().ToLower()
        $val = $l.Substring($idx + 1).Trim()
        if (-not $val) { continue }
        switch -Regex ($key) {
            '^registrar( name)?$'              { if (-not $out.Registrar) { $out.Registrar = $val } }
            '^sponsoring registrar$'           { if (-not $out.Registrar) { $out.Registrar = $val } }
            '^(registrant|registrant organisation|registrant organization|registrant contact organisation|org)$' {
                                                 if (-not $out.RegistrantOrg) { $out.RegistrantOrg = $val } }
            '^eligibility type$'               { $out.Eligibility = $val }
            '^(creation date|created|registered on|domain registration date)$' { if (-not $out.Created) { $out.Created = $val } }
            '^(updated date|last modified|last update|modified)$'              { if (-not $out.Updated) { $out.Updated = $val } }
            '^(registry expiry date|expiry date|expires|expiration date|paid-till)$' { if (-not $out.Expires) { $out.Expires = $val } }
            '^(domain status|status)$'         { [void]$statuses.Add($val) }
            '^(name server|nserver|nameserver)$' { [void]$ns.Add(($val -split '\s+')[0]) }
        }
    }
    if ($statuses.Count -gt 0) { $out.Status = (($statuses | Select-Object -Unique) -join ', ') }
    $out.NameServers = @(($ns | Select-Object -Unique))
    return $out
}

# ---------------------------------------------------------------------------
# Active probes (opt-in; read-only)
# ---------------------------------------------------------------------------
function Get-ProbePortDefs {
    # The common service ports we identify. Name is what we tell the tech;
    # Kind drives how we read the service.
    @(
        [pscustomobject]@{ Port = 21;    Name = 'FTP';                 Kind = 'banner' }
        [pscustomobject]@{ Port = 22;    Name = 'SSH';                 Kind = 'banner' }
        [pscustomobject]@{ Port = 23;    Name = 'Telnet';             Kind = 'banner' }
        [pscustomobject]@{ Port = 25;    Name = 'SMTP';               Kind = 'banner' }
        [pscustomobject]@{ Port = 53;    Name = 'DNS';                Kind = 'tcp'    }
        [pscustomobject]@{ Port = 80;    Name = 'HTTP';               Kind = 'http'   }
        [pscustomobject]@{ Port = 110;   Name = 'POP3';               Kind = 'banner' }
        [pscustomobject]@{ Port = 143;   Name = 'IMAP';               Kind = 'banner' }
        [pscustomobject]@{ Port = 443;   Name = 'HTTPS';              Kind = 'https'  }
        [pscustomobject]@{ Port = 445;   Name = 'SMB';                Kind = 'tcp'    }
        [pscustomobject]@{ Port = 465;   Name = 'SMTPS';              Kind = 'tls'    }
        [pscustomobject]@{ Port = 587;   Name = 'SMTP submission';    Kind = 'banner' }
        [pscustomobject]@{ Port = 993;   Name = 'IMAPS';              Kind = 'tls'    }
        [pscustomobject]@{ Port = 995;   Name = 'POP3S';              Kind = 'tls'    }
        [pscustomobject]@{ Port = 1723;  Name = 'PPTP VPN';           Kind = 'tcp'    }
        [pscustomobject]@{ Port = 3306;  Name = 'MySQL';              Kind = 'banner' }
        [pscustomobject]@{ Port = 3389;  Name = 'RDP';                Kind = 'rdp'    }
        [pscustomobject]@{ Port = 4433;  Name = 'HTTPS (alt)';        Kind = 'https'  }
        [pscustomobject]@{ Port = 4443;  Name = 'HTTPS (alt)';        Kind = 'https'  }
        [pscustomobject]@{ Port = 5001;  Name = 'HTTPS (alt)';        Kind = 'https'  }
        [pscustomobject]@{ Port = 5060;  Name = 'SIP';                Kind = 'tcp'    }
        [pscustomobject]@{ Port = 5061;  Name = 'SIP TLS';            Kind = 'tls'    }
        [pscustomobject]@{ Port = 5900;  Name = 'VNC';                Kind = 'banner' }
        [pscustomobject]@{ Port = 8000;  Name = 'HTTP (alt)';         Kind = 'http'   }
        [pscustomobject]@{ Port = 8080;  Name = 'HTTP proxy/alt';     Kind = 'http'   }
        [pscustomobject]@{ Port = 8443;  Name = 'HTTPS (alt)';        Kind = 'https'  }
        [pscustomobject]@{ Port = 8880;  Name = 'HTTP (alt)';         Kind = 'http'   }
        [pscustomobject]@{ Port = 9443;  Name = 'HTTPS (alt)';        Kind = 'https'  }
        [pscustomobject]@{ Port = 10000; Name = 'Webmin';            Kind = 'https'  }
    )
}

function Test-TcpPortState {
    # Distinguishes Open / Refused / Filtered. Refused takes ~2s on Windows, so
    # allow at least 3s (see refused-connect timing note).
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 3000)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = [System.Net.Sockets.TcpClient]::new()
    $state = 'Filtered'
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            try { $client.EndConnect($iar); if ($client.Connected) { $state = 'Open' } }
            catch [System.Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -eq 'ConnectionRefused') { $state = 'Refused' } else { $state = 'Filtered' }
            } catch { $state = 'Filtered' }
        } else { $state = 'Filtered' }
    } catch { $state = 'Filtered' } finally { try { $client.Close() } catch {} }
    $sw.Stop()
    [pscustomobject]@{ Port = $Port; State = $state; LatencyMs = [int]$sw.ElapsedMilliseconds }
}

function Read-TcpBanner {
    # Reads whatever a service volunteers on connect (SMTP/SSH/FTP/etc).
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 4000)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return '' }
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        Start-Sleep -Milliseconds 250
        $buf = New-Object byte[] 1024
        $sb = New-Object System.Text.StringBuilder
        try {
            $read = $stream.Read($buf, 0, $buf.Length)
            if ($read -gt 0) { [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $read)) }
        } catch {}
        return ($sb.ToString().Trim())
    } catch { return '' } finally { try { $client.Close() } catch {} }
}

function Get-TlsCertInfo {
    # Reads the certificate a TLS service presents (we do not trust it).
    # Returns subject/SANs/issuer/validity/self-signed + negotiated protocol.
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 5000, [string]$Sni = '')
    if (-not $Sni) { $Sni = $ComputerName }
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $null }
        $client.EndConnect($iar)
        $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $h, $e) $true }
        $ssl = [System.Net.Security.SslStream]::new($client.GetStream(), $false, $cb)
        try {
            $ssl.AuthenticateAsClient($Sni)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
            $sans = ''
            foreach ($ext in $cert.Extensions) {
                if ($ext.Oid.Value -eq '2.5.29.17') { $sans = $ext.Format($false) }
            }
            $selfSigned = ($cert.Subject -eq $cert.Issuer)
            $days = [int][math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
            [pscustomobject]@{
                Subject = $cert.Subject; Issuer = $cert.Issuer; Sans = $sans
                NotBefore = $cert.NotBefore; NotAfter = $cert.NotAfter; DaysToExpiry = $days
                SelfSigned = $selfSigned; Thumbprint = $cert.Thumbprint
                SigAlg = $cert.SignatureAlgorithm.FriendlyName
                Protocol = [string]$ssl.SslProtocol
            }
        } finally { $ssl.Dispose() }
    } catch { return $null } finally { try { $client.Close() } catch {} }
}

function Invoke-HttpProbe {
    # One GET / read over a raw socket (optionally TLS), so embedded devices with
    # sloppy headers still parse - HttpWebRequest throws on those. Returns the
    # status line, headers, Server, title and any Location.
    param([string]$ComputerName, [int]$Port, [bool]$UseTls = $false, [int]$TimeoutMs = 6000, [string]$HostHeader = '')
    if (-not $HostHeader) { $HostHeader = $ComputerName }
    $client = [System.Net.Sockets.TcpClient]::new()
    $out = [pscustomobject]@{ StatusLine = ''; Server = ''; Title = ''; Location = ''; Headers = ''; Ok = $false }
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $out }
        $client.EndConnect($iar)
        $rawStream = $client.GetStream()
        $rawStream.ReadTimeout = $TimeoutMs
        $stream = $rawStream
        if ($UseTls) {
            $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $h, $e) $true }
            $ssl = [System.Net.Security.SslStream]::new($rawStream, $false, $cb)
            $ssl.AuthenticateAsClient($HostHeader)
            $stream = $ssl
        }
        $req = "GET / HTTP/1.1`r`nHost: $HostHeader`r`nUser-Agent: Mozilla/5.0 (IP-Triage)`r`nAccept: */*`r`nConnection: close`r`n`r`n"
        $reqBytes = [System.Text.Encoding]::ASCII.GetBytes($req)
        $stream.Write($reqBytes, 0, $reqBytes.Length)
        $stream.Flush()
        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 4096
        $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
        while ([DateTime]::UtcNow -lt $deadline -and $ms.Length -lt 65536) {
            try {
                $read = $stream.Read($buf, 0, $buf.Length)
                if ($read -le 0) { break }
                $ms.Write($buf, 0, $read)
            } catch { break }
        }
        $text = [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
        if ($UseTls -and $stream) { try { $stream.Dispose() } catch {} }
        if ([string]::IsNullOrWhiteSpace($text)) { return $out }
        $headEnd = $text.IndexOf("`r`n`r`n")
        $headPart = if ($headEnd -ge 0) { $text.Substring(0, $headEnd) } else { $text }
        $bodyPart = if ($headEnd -ge 0) { $text.Substring($headEnd + 4) } else { '' }
        $headLines = $headPart -split "`r`n"
        if (@($headLines).Count -gt 0) { $out.StatusLine = $headLines[0].Trim() }
        $out.Headers = $headPart.Trim()
        foreach ($hl in $headLines) {
            if ($hl -match '^(?i)Server:\s*(.+)$') { $out.Server = $matches[1].Trim() }
            elseif ($hl -match '^(?i)Location:\s*(.+)$') { $out.Location = $matches[1].Trim() }
        }
        $tm = [regex]::Match($bodyPart, '(?is)<title[^>]*>(.*?)</title>')
        if ($tm.Success) { $out.Title = ($tm.Groups[1].Value -replace '\s+', ' ').Trim() }
        $out.Ok = $true
        return $out
    } catch { return $out } finally { try { $client.Close() } catch {} }
}

function Get-PublicIp {
    param([int]$TimeoutMs = 4000)
    foreach ($u in @('https://checkip.amazonaws.com', 'https://api.ipify.org', 'https://ifconfig.me/ip')) {
        $txt = Invoke-TextGet $u $TimeoutMs
        if ($txt) {
            $m = [regex]::Match($txt, '\d{1,3}(?:\.\d{1,3}){3}')
            if ($m.Success) { return $m.Value }
        }
    }
    return ''
}

# ---------------------------------------------------------------------------
# Known ranges, country, network kind, reputation, risk
# ---------------------------------------------------------------------------
function ConvertTo-Ipv4Number {
    # Dotted quad -> UInt32. Uses plain arithmetic, not -shl: 255 -shl 24
    # overflows Int32 in PS 5.1.
    param([string]$Ip)
    $o = $Ip.Split('.')
    if (@($o).Count -ne 4) { return $null }
    foreach ($part in $o) { if ($part -notmatch '^\d{1,3}$' -or [int]$part -gt 255) { return $null } }
    return [uint32](([int64]$o[0] * 16777216) + ([int64]$o[1] * 65536) + ([int64]$o[2] * 256) + [int64]$o[3])
}

function Test-IpInCidr {
    # Is $Ip inside $Cidr? $Cidr may be "10.1.2.0/24" or a bare address (= /32).
    # Compares network numbers by block size, so there is no bitmask overflow.
    param([string]$Ip, [string]$Cidr)
    if ([string]::IsNullOrWhiteSpace($Ip) -or [string]::IsNullOrWhiteSpace($Cidr)) { return $false }
    $text = $Cidr.Trim()
    $prefix = 32
    if ($text -match '^(.+)/(\d{1,2})$') {
        $netText = $matches[1].Trim()
        $prefix = [int]$matches[2]
    } else {
        $netText = $text
    }
    if ($prefix -lt 0 -or $prefix -gt 32) { return $false }
    $ipVal = ConvertTo-Ipv4Number $Ip
    $netVal = ConvertTo-Ipv4Number $netText
    if ($null -eq $ipVal -or $null -eq $netVal) { return $false }
    if ($prefix -eq 0) { return $true }
    $size = [int64][math]::Pow(2, (32 - $prefix))
    $ipNet = [int64][math]::Floor([int64]$ipVal / $size)
    $netNet = [int64][math]::Floor([int64]$netVal / $size)
    return ($ipNet -eq $netNet)
}

function Get-KnownRangeMatch {
    # Looks the address up in our own KnownRanges.csv (Range,Label,Type) so an
    # alert IP can be recognised as a customer or one of our own ranges before
    # any online lookup. Rows whose Range starts with # are comments.
    param([string]$Ip, [string]$CsvPath)
    $out = [pscustomobject]@{ Matched = $false; Label = ''; Type = ''; Range = ''; Error = '' }
    if ([string]::IsNullOrWhiteSpace($CsvPath) -or -not (Test-Path -LiteralPath $CsvPath)) { return $out }
    try {
        $rows = @(Import-Csv -LiteralPath $CsvPath)
    } catch {
        $out.Error = ('Could not read {0}: {1}' -f $CsvPath, $_.Exception.Message)
        return $out
    }
    foreach ($row in $rows) {
        $range = [string]$row.Range
        if ([string]::IsNullOrWhiteSpace($range) -or $range.TrimStart().StartsWith('#')) { continue }
        if (Test-IpInCidr -Ip $Ip -Cidr $range.Trim()) {
            $out.Matched = $true
            $out.Label = [string]$row.Label
            $out.Type = [string]$row.Type
            $out.Range = $range.Trim()
            return $out
        }
    }
    return $out
}

function Get-CountryVerdict {
    # Compares the address's country against the countries we expect to see.
    # Registry data (RDAP / Team Cymru) is preferred over the ipinfo geo guess,
    # and a disagreement between them is reported rather than hidden.
    param(
        [string]$RegistryCountry,
        [string]$GeoCountry,
        $Expected = @()
    )
    $out = [pscustomobject]@{
        Country = ''; Source = ''; IsExpected = $true; AltExpected = $false
        Disagreement = ''; Note = ''
    }
    $reg = ''; if ($RegistryCountry) { $reg = $RegistryCountry.Trim().ToUpper() }
    $geo = ''; if ($GeoCountry) { $geo = $GeoCountry.Trim().ToUpper() }
    if ($reg) { $out.Country = $reg; $out.Source = 'registry' }
    elseif ($geo) { $out.Country = $geo; $out.Source = 'geo' }
    else { $out.Note = 'No country data.'; return $out }

    if ($reg -and $geo -and $reg -ne $geo) {
        $out.Disagreement = ('registry says {0}, geolocation says {1}' -f $reg, $geo)
    }
    $list = @($Expected | ForEach-Object { ([string]$_).Trim().ToUpper() } | Where-Object { $_ })
    $out.IsExpected = ((@($list).Count -eq 0) -or ($list -contains $out.Country))
    # The other source's country, when the two disagree. Global cloud providers
    # register whole ranges to a US head office while the hosts themselves sit
    # in-country, so an AWS Frankfurt address reads as "US" by registry and "DE" by
    # geolocation. Record that so the risk logic can avoid calling it foreign.
    $other = ''
    if ($out.Source -eq 'registry') { $other = $geo } else { $other = $reg }
    if ($other -and $other -ne $out.Country) { $out.AltExpected = ((@($list).Count -eq 0) -or ($list -contains $other)) }
    if (@($list).Count -eq 0) { $out.Note = 'No expected countries set (start with -ExpectedCountries, e.g. GB,IE), so the country is shown but not judged.' }; if (-not $out.IsExpected) {
        $out.Note = ('Country {0} is outside the expected set ({1}).' -f $out.Country, ($list -join ', '))
        if ($out.AltExpected) {
            $out.Note = ('Registry country {0} is outside the expected set ({1}), but geolocation places it in {2} - typical of a global cloud provider.' -f $out.Country, ($list -join ', '), $other)
        }
    }
    return $out
}

function Get-NetworkKind {
    # Hosting/datacenter vs a consumer or business ISP line. A login from cloud
    # or VPN space reads very differently from a residential connection.
    # AbuseIPDB's usageType is authoritative when we have it; otherwise this
    # matches the AS name / netname, since ipinfo's free tier has no such field.
    param([string]$AsName, [string]$NetName, [string]$UsageType)
    $out = [pscustomobject]@{ Kind = 'Unknown'; Reason = '' }
    if ($UsageType) {
        $usage = $UsageType.Trim()
        switch -Regex ($usage) {
            '(?i)data ?cent|hosting|transit' { $out.Kind = 'Hosting'; $out.Reason = ('AbuseIPDB usage type: {0}' -f $usage); return $out }
            '(?i)mobile'                      { $out.Kind = 'Mobile';  $out.Reason = ('AbuseIPDB usage type: {0}' -f $usage); return $out }
            '(?i)isp|fixed line|cable|dsl'    { $out.Kind = 'ISP';     $out.Reason = ('AbuseIPDB usage type: {0}' -f $usage); return $out }
            default { $out.Kind = 'Other'; $out.Reason = ('AbuseIPDB usage type: {0}' -f $usage); return $out }
        }
    }
    $text = (('{0} {1}' -f $AsName, $NetName)).Trim()
    if (-not $text) { return $out }
    $hosting = 'amazon|aws|azure|microsoft corp|google cloud|digitalocean|linode|akamai|ovh|hetzner|vultr|choopa|contabo|leaseweb|m247|datacamp|cloudflare|oracle cloud|alibaba|tencent|scaleway|rackspace|equinix|colocation|hosting|datacent|data cent|vps|server'
    $mobile = 'mobile|cellular|wireless| 4g| 5g|lte'
    $isp = 'telstra|optus|vodafone|tpg|iinet|superloop|aussie broadband|vocus|exetel|launtel|spark|chorus|comcast|verizon|at&t| bt |sky broadband|virgin|broadband|telecom|communications|internet|isp'
    if ($text -match ('(?i)' + $hosting)) { $out.Kind = 'Hosting'; $out.Reason = ('AS/net name matches a hosting or cloud provider: {0}' -f (Get-Truncated $text 60)); return $out }
    if ($text -match ('(?i)' + $mobile))  { $out.Kind = 'Mobile';  $out.Reason = ('AS/net name looks like a mobile carrier: {0}' -f (Get-Truncated $text 60)); return $out }
    if ($text -match ('(?i)' + $isp))     { $out.Kind = 'ISP';     $out.Reason = ('AS/net name looks like an ISP: {0}' -f (Get-Truncated $text 60)); return $out }
    return $out
}

function Get-ApiConfigPath {
    # Per-user, per-machine. Never beside the script: it may live on a
    # synced or shared folder, and keys must not land there.
    return (Join-Path $env:APPDATA 'IP-Triage\config.json')
}

function Get-AbuseIpdbKey {
    # Optional key. Environment variable wins, then the saved config, which may
    # hold a DPAPI-protected value (AbuseIpdbKeyEnc) or a plain one the user set
    # by hand (AbuseIpdbKey).
    param([string]$ConfigPath = '')
    if ($env:ABUSEIPDB_KEY) { return $env:ABUSEIPDB_KEY.Trim() }
    if (-not $ConfigPath) { $ConfigPath = Get-ApiConfigPath }
    try {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { return '' }
        $raw = Get-Content -LiteralPath $ConfigPath -Raw
        $obj = $raw | ConvertFrom-Json
        if ($obj.AbuseIpdbKeyEnc) {
            # DPAPI: only this Windows account on this machine can read it back.
            try {
                $sec = ConvertTo-SecureString ([string]$obj.AbuseIpdbKeyEnc)
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
                try { return ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)).Trim() }
                finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            } catch { return '' }
        }
        if ($obj.AbuseIpdbKey) { return ([string]$obj.AbuseIpdbKey).Trim() }
    } catch {}
    return ''
}

function Get-AbuseIpdbKeySource {
    # Where the key in force came from, so the dialog can explain precedence.
    param([string]$ConfigPath = '')
    if ($env:ABUSEIPDB_KEY) { return 'environment variable ABUSEIPDB_KEY' }
    if (-not $ConfigPath) { $ConfigPath = Get-ApiConfigPath }
    try {
        if (Test-Path -LiteralPath $ConfigPath) {
            $obj = (Get-Content -LiteralPath $ConfigPath -Raw) | ConvertFrom-Json
            if ($obj.AbuseIpdbKeyEnc) { return 'saved on this PC (encrypted)' }
            if ($obj.AbuseIpdbKey) { return 'saved on this PC (plain text)' }
        }
    } catch {}
    return ''
}

function Set-AbuseIpdbKey {
    # Saves the key DPAPI-protected under %APPDATA%. Returns $true on success.
    param([string]$Key, [string]$ConfigPath = '')
    if (-not $ConfigPath) { $ConfigPath = Get-ApiConfigPath }
    try {
        $dir = Split-Path -Parent $ConfigPath
        if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        $obj = [ordered]@{}
        if (Test-Path -LiteralPath $ConfigPath) {
            try {
                $existing = (Get-Content -LiteralPath $ConfigPath -Raw) | ConvertFrom-Json
                foreach ($p in $existing.PSObject.Properties) { $obj[$p.Name] = $p.Value }
            } catch {}
        }
        $sec = ConvertTo-SecureString -String $Key -AsPlainText -Force
        $obj['AbuseIpdbKeyEnc'] = (ConvertFrom-SecureString -SecureString $sec)
        # Drop any earlier plain-text value so it does not linger on disk.
        if ($obj.Contains('AbuseIpdbKey')) { [void]$obj.Remove('AbuseIpdbKey') }
        ($obj | ConvertTo-Json) | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
        return $true
    } catch { return $false }
}

function Remove-AbuseIpdbKey {
    param([string]$ConfigPath = '')
    if (-not $ConfigPath) { $ConfigPath = Get-ApiConfigPath }
    try {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { return $true }
        $obj = [ordered]@{}
        try {
            $existing = (Get-Content -LiteralPath $ConfigPath -Raw) | ConvertFrom-Json
            foreach ($p in $existing.PSObject.Properties) { $obj[$p.Name] = $p.Value }
        } catch {}
        if ($obj.Contains('AbuseIpdbKeyEnc')) { [void]$obj.Remove('AbuseIpdbKeyEnc') }
        if ($obj.Contains('AbuseIpdbKey')) { [void]$obj.Remove('AbuseIpdbKey') }
        ($obj | ConvertTo-Json) | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
        return $true
    } catch { return $false }
}

function Get-AbuseCategoryName {
    # AbuseIPDB's fixed category ids. Knowing an address is reported for
    # "Fraud VoIP / Brute-Force" rather than just "abuse" is what makes the
    # result actionable - especially with a PBX exposed.
    param([int]$Id)
    switch ($Id) {
        1  { 'DNS Compromise' }      2  { 'DNS Poisoning' }     3  { 'Fraud Orders' }
        4  { 'DDoS Attack' }         5  { 'FTP Brute-Force' }   6  { 'Ping of Death' }
        7  { 'Phishing' }            8  { 'Fraud VoIP' }        9  { 'Open Proxy' }
        10 { 'Web Spam' }            11 { 'Email Spam' }        12 { 'Blog Spam' }
        13 { 'VPN IP' }              14 { 'Port Scan' }         15 { 'Hacking' }
        16 { 'SQL Injection' }       17 { 'Spoofing' }          18 { 'Brute-Force' }
        19 { 'Bad Web Bot' }         20 { 'Exploited Host' }    21 { 'Web App Attack' }
        22 { 'SSH' }                 23 { 'IoT Targeted' }
        default { ('Category ' + $Id) }
    }
}

function Get-AbuseIpdb {
    # Abuse-report reputation. Skipped silently when no key is configured, so
    # the tool stays fully keyless by default. Verbose so we can say WHAT the
    # address is reported for, not merely that it is reported.
    param([string]$Ip, [string]$ApiKey, [int]$MaxAgeDays = 90)
    $out = [pscustomobject]@{
        Available = $false; Score = 0; TotalReports = 0; LastReported = ''
        UsageType = ''; IsTor = $false; IsWhitelisted = $false; Error = ''
        DistinctReporters = 0; TopCategories = @(); Domain = ''
    }
    if ([string]::IsNullOrWhiteSpace($ApiKey)) { $out.Error = 'no key configured'; return $out }
    $url = ('https://api.abuseipdb.com/api/v2/check?ipAddress={0}&maxAgeInDays={1}&verbose' -f $Ip, $MaxAgeDays)
    $resp = Invoke-JsonGet -Url $url -TimeoutMs 10000 -Headers @{ 'Key' = $ApiKey }
    if (-not $resp) { $out.Error = 'no response'; return $out }
    if ($resp.PSObject.Properties.Name -contains '__httperror') {
        $out.Error = ('HTTP {0}' -f $resp.__httperror)
        return $out
    }
    $d = $resp.data
    if (-not $d) { $out.Error = 'unexpected response'; return $out }
    $out.Available = $true
    if ($null -ne $d.abuseConfidenceScore) { $out.Score = [int]$d.abuseConfidenceScore }
    if ($null -ne $d.totalReports) { $out.TotalReports = [int]$d.totalReports }
    $out.LastReported = [string]$d.lastReportedAt
    $out.UsageType = [string]$d.usageType
    $out.IsTor = [bool]$d.isTor
    $out.IsWhitelisted = [bool]$d.isWhitelisted
    $out.Domain = [string]$d.domain
    if ($null -ne $d.numDistinctUsers) { $out.DistinctReporters = [int]$d.numDistinctUsers }
    # Roll the individual reports up into the categories seen most often.
    if ($d.reports) {
        $tally = @{}
        foreach ($rep in @($d.reports)) {
            foreach ($cid in @($rep.categories)) {
                $nm = Get-AbuseCategoryName ([int]$cid)
                if (-not $tally.ContainsKey($nm)) { $tally[$nm] = 0 }
                $tally[$nm] = $tally[$nm] + 1
            }
        }
        $out.TopCategories = @($tally.GetEnumerator() | Sort-Object -Property Value -Descending |
            Select-Object -First 5 | ForEach-Object { $_.Key })
    }
    return $out
}

function Get-RiskBanner {
    # Decides the big warning strip shown across the top of the window. Kept out
    # of the GUI so the wording and the show/hide rule can be unit tested.
    # Returns Show, Level (High/Medium), Headline and Detail.
    param($Risk, $Abuse, $KnownMatch)
    $out = [pscustomobject]@{ Show = $false; Level = 'Low'; Headline = ''; Detail = '' }
    if (-not $Risk) { return $out }
    $out.Level = $Risk.Level
    if ($Risk.Level -eq 'Low') { return $out }
    $out.Show = $true

    $bits = [System.Collections.Generic.List[string]]::new()
    if ($Abuse -and $Abuse.Available -and ($Abuse.Score -gt 0 -or $Abuse.TotalReports -gt 0)) {
        $who = ''
        if ($Abuse.DistinctReporters -gt 0) { $who = (' from {0} sources' -f $Abuse.DistinctReporters) }
        [void]$bits.Add(('AbuseIPDB {0}% confidence, {1} report(s){2}' -f $Abuse.Score, $Abuse.TotalReports, $who))
        if (@($Abuse.TopCategories).Count -gt 0) {
            [void]$bits.Add(('reported for: ' + ((@($Abuse.TopCategories) | Select-Object -First 4) -join ', ')))
        }
        if ($Abuse.LastReported) { [void]$bits.Add(('last report ' + $Abuse.LastReported)) }
    }
    # Fall back to the risk reasons when there is no abuse data to quote.
    if (@($bits).Count -eq 0) {
        foreach ($r in (@($Risk.Reasons) | Select-Object -First 2)) { [void]$bits.Add($r.TrimEnd('.')) }
    }
    $out.Detail = ((@($bits.ToArray()) -join '  |  '))

    if ($Risk.Level -eq 'High') {
        if ($Abuse -and $Abuse.Available -and $Abuse.Score -ge 50) {
            $out.Headline = 'MALICIOUS IP - DO NOT TRUST THIS ADDRESS'
        } else {
            $out.Headline = 'HIGH RISK ADDRESS'
        }
    } else {
        $out.Headline = 'CAUTION - THIS ADDRESS NEEDS A LOOK'
    }
    if ($KnownMatch -and $KnownMatch.Matched) {
        $out.Headline = ($out.Headline + ('   [but it is on our known list: {0}]' -f $KnownMatch.Label))
    }
    return $out
}

function Get-RiskVerdict {
    # "Is this IP itself suspect?" - deliberately separate from the exposure
    # notes, which describe how well configured the thing behind it is.
    # Every reason is listed so the rating can be argued with.
    param($KnownMatch, $Abuse, $CountryVerdict, [string]$NetworkKind, [bool]$IsTorExit)
    $reasons = [System.Collections.Generic.List[string]]::new()
    $level = 0   # 0 Low, 1 Medium, 2 High
    function Raise([int]$To, [ref]$Cur) { if ($To -gt $Cur.Value) { $Cur.Value = $To } }

    if ($IsTorExit) { [void]$reasons.Add('Listed as a Tor exit node.'); Raise 2 ([ref]$level) }
    if ($Abuse -and $Abuse.Available) {
        if ($Abuse.IsTor -and -not $IsTorExit) { [void]$reasons.Add('AbuseIPDB flags this as Tor.'); Raise 2 ([ref]$level) }
        if ($Abuse.Score -ge 50) {
            [void]$reasons.Add(('AbuseIPDB confidence {0}% from {1} report(s).' -f $Abuse.Score, $Abuse.TotalReports)); Raise 2 ([ref]$level)
        } elseif ($Abuse.Score -ge 25) {
            [void]$reasons.Add(('AbuseIPDB confidence {0}% from {1} report(s).' -f $Abuse.Score, $Abuse.TotalReports)); Raise 1 ([ref]$level)
        } elseif ($Abuse.Score -gt 0 -or $Abuse.TotalReports -gt 0) {
            [void]$reasons.Add(('AbuseIPDB confidence {0}% from {1} report(s) - low.' -f $Abuse.Score, $Abuse.TotalReports))
        }
        if ($Abuse.IsWhitelisted) { [void]$reasons.Add('AbuseIPDB lists this address as whitelisted.') }
    }
    if ($CountryVerdict -and $CountryVerdict.Country -and -not $CountryVerdict.IsExpected) {
        [void]$reasons.Add($CountryVerdict.Note)
        # Only a genuine foreign address raises the rating. When geolocation
        # still places it in an expected country the note stands on its own,
        # otherwise every in-country AWS/Azure address would read as foreign.
        if (-not $CountryVerdict.AltExpected) { Raise 1 ([ref]$level) }
    }
    if ($CountryVerdict -and $CountryVerdict.Disagreement -and -not $CountryVerdict.AltExpected) {
        [void]$reasons.Add(('Country sources disagree - {0}.' -f $CountryVerdict.Disagreement))
    }
    if ($NetworkKind -eq 'Hosting') {
        [void]$reasons.Add('Hosting/cloud or VPN space, not a consumer or business ISP line.'); Raise 1 ([ref]$level)
    }

    $known = ($KnownMatch -and $KnownMatch.Matched)
    if ($known) {
        [void]$reasons.Add(('Matches our own list: {0} ({1}).' -f $KnownMatch.Label, $KnownMatch.Range))
    }
    if (@($reasons).Count -eq 0) { [void]$reasons.Add('Nothing adverse found in the checks that ran.') }

    $names = @('Low', 'Medium', 'High')
    [pscustomobject]@{
        Level = $names[$level]
        Known = [bool]$known
        Reasons = @($reasons.ToArray())
    }
}

# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------
function Get-SignatureTable {
    # Each row: Field (which evidence string), Pattern (regex), Vendor, Class,
    # Weight. Class 'Edge' items (firewalls/routers/VPNs) weigh more because the
    # public IP usually terminates on the edge device.
    @(
        [pscustomobject]@{ Field='server';  Pattern='(?i)fortinet|fortigate';        Vendor='Fortinet FortiGate'; Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)fortigate|fortinet';        Vendor='Fortinet FortiGate'; Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='cert';    Pattern='(?i)fortinet|fortigate';        Vendor='Fortinet FortiGate'; Class='Firewall'; Weight=5 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)sonicwall';                 Vendor='SonicWall';          Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='cert';    Pattern='(?i)sonicwall';                 Vendor='SonicWall';          Class='Firewall'; Weight=5 }
        [pscustomobject]@{ Field='server';  Pattern='(?i)pfsense';                   Vendor='pfSense';            Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)pfsense|opnsense';          Vendor='pfSense/OPNsense';   Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)sophos';                    Vendor='Sophos';             Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='cert';    Pattern='(?i)sophos';                    Vendor='Sophos';             Class='Firewall'; Weight=5 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)watchguard';                Vendor='WatchGuard';         Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)meraki';                    Vendor='Cisco Meraki';       Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='cert';    Pattern='(?i)cisco';                     Vendor='Cisco';              Class='Network';  Weight=4 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)draytek|vigor';             Vendor='DrayTek Vigor';      Class='Router';   Weight=6 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)mikrotik|routeros';         Vendor='MikroTik RouterOS';  Class='Router';   Weight=6 }
        [pscustomobject]@{ Field='banner';  Pattern='(?i)mikrotik|routeros';         Vendor='MikroTik RouterOS';  Class='Router';   Weight=6 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)ubiquiti|unifi|edgeos';     Vendor='Ubiquiti';           Class='Router';   Weight=5 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)palo alto|globalprotect';   Vendor='Palo Alto';          Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='server';  Pattern='(?i)pan-os';                    Vendor='Palo Alto PAN-OS';   Class='Firewall'; Weight=6 }
        [pscustomobject]@{ Field='cert';    Pattern='(?i)synology';                  Vendor='Synology NAS';       Class='NAS';      Weight=6 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)synology|diskstation';      Vendor='Synology NAS';       Class='NAS';      Weight=6 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)qnap';                      Vendor='QNAP NAS';           Class='NAS';      Weight=6 }
        [pscustomobject]@{ Field='server';  Pattern='(?i)microsoft-iis';             Vendor='Microsoft IIS';      Class='Server';   Weight=3 }
        [pscustomobject]@{ Field='server';  Pattern='(?i)nginx';                     Vendor='nginx';              Class='Server';   Weight=2 }
        [pscustomobject]@{ Field='server';  Pattern='(?i)apache';                    Vendor='Apache';             Class='Server';   Weight=2 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)outlook|owa|exchange';      Vendor='MS Exchange/OWA';    Class='Server';   Weight=4 }
        [pscustomobject]@{ Field='title';   Pattern='(?i)remote desktop|rd web';     Vendor='RD Web Access';      Class='Server';   Weight=4 }
        [pscustomobject]@{ Field='banner';  Pattern='(?i)openssh';                   Vendor='OpenSSH';            Class='Server';   Weight=2 }
        [pscustomobject]@{ Field='banner';  Pattern='(?i)exchange|microsoft esmtp';  Vendor='MS Exchange';        Class='Server';   Weight=3 }
        [pscustomobject]@{ Field='banner';  Pattern='(?i)postfix|exim';              Vendor='Mail server';        Class='Server';   Weight=2 }
        [pscustomobject]@{ Field='tag';     Pattern='(?i)vpn';                       Vendor='VPN endpoint';       Class='Edge';     Weight=3 }
        [pscustomobject]@{ Field='port';    Pattern='^1723$';                        Vendor='PPTP VPN endpoint';  Class='Edge';     Weight=3 }
        [pscustomobject]@{ Field='port';    Pattern='^3389$';                        Vendor='RDP host';           Class='Server';   Weight=2 }
    )
}

function Invoke-Fingerprint {
    # Scores evidence against the signature table. Evidence is a list of
    # [pscustomobject]@{ Field=...; Value=...; Port=... }. Returns a ranked list
    # of matches and a top verdict.
    param($Evidence, $Signatures)
    $matchesOut = [System.Collections.Generic.List[object]]::new()
    $scoreByVendor = @{}
    foreach ($sig in $Signatures) {
        foreach ($ev in $Evidence) {
            if ([string]$ev.Field -ne [string]$sig.Field) { continue }
            $val = [string]$ev.Value
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            $isMatch = $false
            $captured = ''
            if ($val -match $sig.Pattern) { $isMatch = $true; $captured = $matches[0] }
            if ($isMatch) {
                [void]$matchesOut.Add([pscustomobject]@{
                    Vendor = $sig.Vendor; Class = $sig.Class; Weight = $sig.Weight
                    Field = $sig.Field; Port = $ev.Port; Matched = $captured
                    Evidence = (Get-Truncated $val 120)
                })
                if (-not $scoreByVendor.ContainsKey($sig.Vendor)) { $scoreByVendor[$sig.Vendor] = 0 }
                $scoreByVendor[$sig.Vendor] += $sig.Weight
            }
        }
    }
    $ranked = @($scoreByVendor.GetEnumerator() | Sort-Object -Property Value -Descending |
        ForEach-Object { [pscustomobject]@{ Vendor = $_.Key; Score = $_.Value } })
    $verdict = ''
    $confidence = 'Low'
    if (@($ranked).Count -gt 0) {
        $verdict = $ranked[0].Vendor
        $top = $ranked[0].Score
        if ($top -ge 6) { $confidence = 'High' } elseif ($top -ge 3) { $confidence = 'Medium' } else { $confidence = 'Low' }
    }

    # A public IP usually terminates on the perimeter device, so also compute a
    # best edge/perimeter guess from firewall/router/NAS/VPN-class matches. This
    # is shown alongside the overall top product (which is often a server behind
    # the firewall).
    $edgeClasses = @('Firewall', 'Router', 'NAS', 'Edge', 'Network')
    $edgeScore = @{}; $edgeClassOf = @{}
    foreach ($mm in $matchesOut) {
        if ($edgeClasses -contains [string]$mm.Class) {
            if (-not $edgeScore.ContainsKey($mm.Vendor)) { $edgeScore[$mm.Vendor] = 0 }
            $edgeScore[$mm.Vendor] += $mm.Weight
            $edgeClassOf[$mm.Vendor] = $mm.Class
        }
    }
    $edgeRanked = @($edgeScore.GetEnumerator() | Sort-Object -Property Value -Descending |
        ForEach-Object { [pscustomobject]@{ Vendor = $_.Key; Score = $_.Value; Class = $edgeClassOf[$_.Key] } })
    $edgeVerdict = ''; $edgeClass = ''; $edgeConfidence = 'Low'
    if (@($edgeRanked).Count -gt 0) {
        $edgeVerdict = $edgeRanked[0].Vendor
        $edgeClass = $edgeRanked[0].Class
        $et = $edgeRanked[0].Score
        if ($et -ge 6) { $edgeConfidence = 'High' } elseif ($et -ge 3) { $edgeConfidence = 'Medium' } else { $edgeConfidence = 'Low' }
    }

    [pscustomobject]@{
        Matches = @($matchesOut.ToArray())
        Ranked = $ranked
        Verdict = $verdict
        Confidence = $confidence
        EdgeVerdict = $edgeVerdict
        EdgeClass = $edgeClass
        EdgeConfidence = $edgeConfidence
    }
}

function Get-Truncated {
    param([string]$Text, [int]$Max = 100)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text -replace '\s+', ' '
    if ($t.Length -le $Max) { return $t }
    return ($t.Substring(0, $Max) + '...')
}

function Get-HostFromUrl {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return '' }
    $h = $Url.Trim()
    $h = $h -replace '^\s*[a-zA-Z][a-zA-Z0-9+.\-]*://', ''
    $h = $h -replace '/.*$', ''
    $h = $h -replace ':\d+$', ''
    if ($h -match '^[A-Za-z0-9\.\-]+$' -and $h -match '[A-Za-z]') { return $h }
    return ''
}

function Get-NamesFromCert {
    # Extracts DNS names (CN + SAN DNS entries) from a Get-TlsCertInfo object.
    param($Cert)
    $names = [System.Collections.Generic.List[string]]::new()
    if (-not $Cert) { return @() }
    $cnm = [regex]::Match([string]$Cert.Subject, '(?i)CN=([^,]+)')
    if ($cnm.Success) {
        $cn = $cnm.Groups[1].Value.Trim()
        if ($cn -match '^[A-Za-z0-9\.\-\*]+$' -and $cn -match '\.') { [void]$names.Add(($cn -replace '^\*\.', '')) }
    }
    if ($Cert.Sans) {
        foreach ($m in [regex]::Matches([string]$Cert.Sans, '(?i)DNS Name=([^\s,]+)')) {
            $dn = $m.Groups[1].Value.Trim()
            if ($dn -match '\.') { [void]$names.Add(($dn -replace '^\*\.', '')) }
        }
        # Some providers format SANs as "DNS:host".
        foreach ($m in [regex]::Matches([string]$Cert.Sans, '(?i)DNS:([^\s,]+)')) {
            $dn = $m.Groups[1].Value.Trim()
            if ($dn -match '\.') { [void]$names.Add(($dn -replace '^\*\.', '')) }
        }
    }
    return @($names.ToArray())
}

function Build-Summary {
    # Assembles the plain-text triage report shown on the Summary tab and used by
    # Copy/Save.
    param([string]$Ip, $Shared, $Fp)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('================ IP TRIAGE REPORT ================')
    [void]$sb.AppendLine(('IP        : {0}   ({1})' -f $Ip, $Shared.IpClass))
    if ($Shared.InputHost) {
        $extra = ''
        if (@($Shared.InputAllIps).Count -gt 1) {
            $extra = ('  [also {0}]' -f ((@($Shared.InputAllIps) | Select-Object -Skip 1) -join ', '))
        }
        [void]$sb.AppendLine(('Hostname  : {0}  (resolved to this IP){1}' -f $Shared.InputHost, $extra))
    }
    [void]$sb.AppendLine(('Generated : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    if ($Shared.OwnPublicIp) {
        if ($Shared.OwnPublicIp -eq $Ip) { [void]$sb.AppendLine('NOTE      : This is THIS machine''s own public IP.') }
        else { [void]$sb.AppendLine(('Our IP    : {0} (this machine)' -f $Shared.OwnPublicIp)) }
    }
    [void]$sb.AppendLine('')

    # Known range first - "is this one of ours" outranks everything else.
    if ($Shared.KnownMatch -and $Shared.KnownMatch.Matched) {
        $kind = $Shared.KnownMatch.Type
        if (-not $kind) { $kind = 'Known' }
        [void]$sb.AppendLine('--- Known range ---')
        [void]$sb.AppendLine(('{0}: {1}   (matched {2})' -f $kind.ToUpper(), $Shared.KnownMatch.Label, $Shared.KnownMatch.Range))
        [void]$sb.AppendLine('')
    }

    # Risk (is the address itself suspect) - separate from exposure below.
    if ($Shared.Risk) {
        # A pasted or saved report has to carry the warning too, not just the
        # on-screen banner.
        $banner = Get-RiskBanner -Risk $Shared.Risk -Abuse $Shared.Abuse -KnownMatch $Shared.KnownMatch
        if ($banner.Show) {
            $bar = ('*' * 66)
            [void]$sb.AppendLine($bar)
            [void]$sb.AppendLine(('*** {0}' -f $banner.Headline))
            if ($banner.Detail) { [void]$sb.AppendLine(('*** {0}' -f $banner.Detail)) }
            [void]$sb.AppendLine($bar)
            [void]$sb.AppendLine('')
        }
        [void]$sb.AppendLine('--- Risk ---')
        [void]$sb.AppendLine(('Rating     : {0}{1}' -f $Shared.Risk.Level, $(if ($Shared.Risk.Known) { '   (address is on our known list)' } else { '' })))
        foreach ($r in @($Shared.Risk.Reasons)) { [void]$sb.AppendLine((' * ' + $r)) }
        if ($Shared.Abuse -and $Shared.Abuse.Available -and @($Shared.Abuse.TopCategories).Count -gt 0) {
            [void]$sb.AppendLine((' * Reported for: {0}' -f ((@($Shared.Abuse.TopCategories)) -join ', ')))
        }
        if ($Shared.Abuse -and -not $Shared.Abuse.Available) {
            [void]$sb.AppendLine((' * AbuseIPDB not checked ({0}).' -f $Shared.Abuse.Error))
        }
        [void]$sb.AppendLine('')
    }

    # Verdict
    [void]$sb.AppendLine('--- Likely device ---')
    if ($Fp -and ($Fp.Verdict -or $Fp.EdgeVerdict)) {
        if ($Fp.EdgeVerdict) {
            [void]$sb.AppendLine(('Perimeter  : {0}  ({1}, confidence: {2})' -f $Fp.EdgeVerdict, $Fp.EdgeClass, $Fp.EdgeConfidence))
        }
        if ($Fp.Verdict) {
            [void]$sb.AppendLine(('Top product: {0}  (confidence: {1})' -f $Fp.Verdict, $Fp.Confidence))
        }
        $others = @($Fp.Ranked | Where-Object { $_.Vendor -ne $Fp.Verdict -and $_.Vendor -ne $Fp.EdgeVerdict } | Select-Object -First 4)
        if (@($others).Count -gt 0) {
            [void]$sb.AppendLine(('Also seen  : {0}' -f ((@($others) | ForEach-Object { ('{0} ({1})' -f $_.Vendor, $_.Score) }) -join ', ')))
        }
    } else {
        [void]$sb.AppendLine('Best guess : (insufficient evidence - try enabling active probing if authorised)')
    }
    [void]$sb.AppendLine('')

    # Who
    [void]$sb.AppendLine('--- Who owns this network ---')
    if ($Shared.Rdap -and $Shared.Rdap.Name) {
        $ownerEntity = @($Shared.Rdap.Entities) | Where-Object { $_.Roles -match 'registrant|administrative' -and ($_.Org -or $_.Name) } | Select-Object -First 1
        $owner = ''
        if ($ownerEntity) { $owner = $ownerEntity.Org; if (-not $owner) { $owner = $ownerEntity.Name } }
        [void]$sb.AppendLine(('Netname    : {0}' -f $Shared.Rdap.Name))
        if ($owner) { [void]$sb.AppendLine(('Registrant : {0}' -f $owner)) }
        [void]$sb.AppendLine(('Range      : {0} - {1}  ({2})' -f $Shared.Rdap.StartAddress, $Shared.Rdap.EndAddress, $Shared.Rdap.Country))
    }
    if ($Shared.Asn -and $Shared.Asn.Asn) { [void]$sb.AppendLine(('ASN        : AS{0} {1}' -f $Shared.Asn.Asn, $Shared.Asn.AsName)) }
    if ($Shared.Geo -and $Shared.Geo.Org) { [void]$sb.AppendLine(('ISP/Org    : {0}' -f $Shared.Geo.Org)) }
    if ($Shared.Geo -and $Shared.Geo.City) { [void]$sb.AppendLine(('Location   : {0}, {1} {2}' -f $Shared.Geo.City, $Shared.Geo.Region, $Shared.Geo.Country)) }
    if (@($Shared.Ptr).Count -gt 0) {
        $flag = ''; if ($Shared.PtrGeneric) { $flag = '  (generic ISP name - low value)' }
        [void]$sb.AppendLine(('Reverse DNS: {0}{1}' -f (@($Shared.Ptr) -join ', '), $flag))
    }
    [void]$sb.AppendLine('')

    # Business association from domains. List every registrant org found, with
    # customer domains (resolve here / from cert or reverse-IP) ranked ABOVE the
    # ISP's own reverse-DNS domain, which is the least interesting.
    $orgDomains = @($Shared.Domains) | Where-Object { $_.RegistrantOrg }
    if (@($orgDomains).Count -gt 0) {
        [void]$sb.AppendLine('--- Business associated (from domains on this IP) ---')
        $ranked = @($orgDomains | Sort-Object -Property `
            @{ Expression = { if ($_.Source -eq 'PTR') { 2 } elseif ($_.PointsHere) { 0 } else { 1 } } }, `
            @{ Expression = { $_.RegDomain } })
        $seen = @{}
        foreach ($d in $ranked) {
            $key = ('{0}|{1}' -f $d.RegDomain, $d.RegistrantOrg)
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $note = ''
            if ($d.PointsHere) { $note = ' (resolves here)' }
            elseif ($d.Source -eq 'PTR') { $note = ' (ISP reverse-DNS)' }
            elseif ($d.Source) { $note = (' (from ' + $d.Source + ')') }
            [void]$sb.AppendLine(('{0,-24} {1}{2}' -f $d.RegDomain, $d.RegistrantOrg, $note))
        }
        [void]$sb.AppendLine('')
    }

    # Reputation / exposure
    $notes = [System.Collections.Generic.List[string]]::new()
    foreach ($n in @(Get-ExposureNotes -Shared $Shared)) { [void]$notes.Add($n) }
    if (@($notes).Count -gt 0) {
        [void]$sb.AppendLine('--- Notes / exposure ---')
        foreach ($n in $notes) { [void]$sb.AppendLine((' * ' + $n)) }
        [void]$sb.AppendLine('')
    }

    # Open services
    $openList = @($Shared.Probe) | Where-Object { $_.State -eq 'Open' }
    if (@($openList).Count -gt 0) {
        [void]$sb.AppendLine('--- Services answering ---')
        foreach ($o in $openList) {
            $desc = $o.Server; if (-not $desc) { $desc = $o.Banner }
            [void]$sb.AppendLine(('{0,-6} {1,-16} {2}' -f $o.Port, $o.Service, (Get-Truncated $desc 90)))
        }
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('==================================================')
    return $sb.ToString()
}

function Get-ExposureNotes {
    # "Is the thing behind this address badly configured?" - shared by the
    # Summary and the Security tab so there is one definition.
    param($Shared)
    $notes = [System.Collections.Generic.List[string]]::new()
    if ($Shared.IsTorExit) { [void]$notes.Add('Listed as a Tor EXIT node.') }
    if ($Shared.InternetDb -and @($Shared.InternetDb.Tags) -contains 'vpn') { [void]$notes.Add('Shodan tags this as a VPN endpoint.') }
    if ($Shared.InternetDb -and @($Shared.InternetDb.Tags) -contains 'self-signed') { [void]$notes.Add('Self-signed certificate present.') }
    if ($Shared.InternetDb -and @($Shared.InternetDb.Tags) -contains 'eol-product') { [void]$notes.Add('End-of-life software reported (patching risk).') }
    # Known CVEs - Shodan already collected these; surface them here rather than
    # leaving them buried on the Network tab.
    if ($Shared.InternetDb -and @($Shared.InternetDb.Vulns).Count -gt 0) {
        $cves = @($Shared.InternetDb.Vulns)
        $shown = @($cves | Select-Object -First 8)
        $more = ''
        if (@($cves).Count -gt @($shown).Count) { $more = (' (+{0} more)' -f (@($cves).Count - @($shown).Count)) }
        [void]$notes.Add(('{0} known CVE(s) reported against this host: {1}{2}' -f @($cves).Count, ($shown -join ', '), $more))
    }
    # Certificate hygiene, from what Get-TlsCertInfo already returned.
    foreach ($crt in @($Shared.Certs)) {
        try {
            $days = [int]([DateTime]$crt.NotAfter - (Get-Date)).TotalDays
            if ($days -lt 0) { [void]$notes.Add(('Certificate on port {0} EXPIRED {1} day(s) ago.' -f $crt.Port, [math]::Abs($days))) }
            elseif ($days -le 30) { [void]$notes.Add(('Certificate on port {0} expires in {1} day(s).' -f $crt.Port, $days)) }
        } catch {}
        if ([string]$crt.Protocol -match '^(Tls|Ssl3|Tls11)$') {
            [void]$notes.Add(('Port {0} negotiated {1} - obsolete TLS.' -f $crt.Port, $crt.Protocol))
        }
    }
    $openList = @($Shared.Probe) | Where-Object { $_.State -eq 'Open' }
    foreach ($o in $openList) {
        if ($o.Port -in @(1723)) { [void]$notes.Add('PPTP VPN open to the internet (weak protocol).') }
        if ($o.Port -in @(3389)) { [void]$notes.Add('RDP (3389) reachable from the internet.') }
        if ($o.Port -in @(445))  { [void]$notes.Add('SMB (445) reachable from the internet.') }
        if ($o.Port -in @(23))   { [void]$notes.Add('Telnet (23) open (cleartext).') }
    }
    return @(@($notes.ToArray()) | Select-Object -Unique)
}

function New-ApiKeyDialog {
    # Builds (but does not show) the optional AbuseIPDB key dialog. Returning the
    # form instead of calling ShowDialog keeps it render-testable headlessly.
    #
    # IMPORTANT: because this function RETURNS the form, its local scope is gone
    # by the time the events fire - the caller shows the dialog somewhere else
    # entirely. Every handler below therefore ends in .GetNewClosure() so it
    # captures $txtKey/$lblResult/$refresh/$Theme by reference. Without that they
    # are all $null at click time and the dialog throws PropertyNotFound on every
    # interaction. (It worked before only because build and ShowDialog shared one
    # live scope.) Test-IPTriage.ps1 fires the Show toggle to guard this.
    param($Theme)
    # Small modal for the optional AbuseIPDB key. Stored DPAPI-protected under
    # %APPDATA% - never beside the script, which may sit in a synced folder.
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'AbuseIPDB API key'
    $dlg.Size = New-Object System.Drawing.Size(700, 300)
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.StartPosition = 'CenterParent'
    $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Location = New-Object System.Drawing.Point(12, 12)
    $lblInfo.Size = New-Object System.Drawing.Size(660, 52)
    $lblInfo.Text = ("Optional. A free key (1000 checks/day) from abuseipdb.com adds abuse-report" + [Environment]::NewLine +
                     "reputation to each lookup. Without one, every other check still runs." + [Environment]::NewLine +
                     "Saved encrypted for your Windows account on this PC only.")

    $lblState = New-Object System.Windows.Forms.Label
    $lblState.Location = New-Object System.Drawing.Point(12, 70)
    $lblState.Size = New-Object System.Drawing.Size(660, 20)

    $lblKey = New-Object System.Windows.Forms.Label
    $lblKey.Text = 'Key:'
    $lblKey.Location = New-Object System.Drawing.Point(12, 102)
    $lblKey.Size = New-Object System.Drawing.Size(36, 20)

    $txtKey = New-Object System.Windows.Forms.TextBox
    $txtKey.Location = New-Object System.Drawing.Point(52, 99)
    $txtKey.Size = New-Object System.Drawing.Size(530, 24)
    $txtKey.UseSystemPasswordChar = $true
    $txtKey.Font = New-Object System.Drawing.Font('Consolas', 9)

    $chkShow = New-Object System.Windows.Forms.CheckBox
    $chkShow.Text = 'Show'
    $chkShow.Location = New-Object System.Drawing.Point(592, 100)
    $chkShow.Size = New-Object System.Drawing.Size(60, 22)
    $chkShow.Add_CheckedChanged({ $txtKey.UseSystemPasswordChar = -not $chkShow.Checked }.GetNewClosure())

    $lblResult = New-Object System.Windows.Forms.Label
    $lblResult.Location = New-Object System.Drawing.Point(12, 134)
    $lblResult.Size = New-Object System.Drawing.Size(660, 40)

    $btnTest = New-Object System.Windows.Forms.Button
    $btnTest.Text = 'Test'
    $btnTest.Location = New-Object System.Drawing.Point(12, 186)
    $btnTest.Size = New-Object System.Drawing.Size(90, 30)

    $btnSaveKey = New-Object System.Windows.Forms.Button
    $btnSaveKey.Text = 'Save'
    $btnSaveKey.Location = New-Object System.Drawing.Point(110, 186)
    $btnSaveKey.Size = New-Object System.Drawing.Size(90, 30)

    $btnRemove = New-Object System.Windows.Forms.Button
    $btnRemove.Text = 'Remove'
    $btnRemove.Location = New-Object System.Drawing.Point(208, 186)
    $btnRemove.Size = New-Object System.Drawing.Size(90, 30)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = 'Close'
    $btnClose.Location = New-Object System.Drawing.Point(582, 186)
    $btnClose.Size = New-Object System.Drawing.Size(90, 30)
    $btnClose.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $refresh = {
        $src = Get-AbuseIpdbKeySource
        if ($src) {
            $lblState.Text = ('Currently configured - {0}.' -f $src)
            $lblState.ForeColor = $Theme.Good
        } else {
            $lblState.Text = 'No key configured - AbuseIPDB checks are skipped.'
            $lblState.ForeColor = $Theme.Warn
        }
        if ($env:ABUSEIPDB_KEY) {
            $lblState.Text = $lblState.Text + '  (the environment variable overrides anything saved here)'
        }
    }.GetNewClosure()
    & $refresh

    $btnTest.Add_Click({
        $k = $txtKey.Text.Trim()
        if (-not $k) { $k = Get-AbuseIpdbKey }
        if (-not $k) { $lblResult.ForeColor = $Theme.Warn; $lblResult.Text = 'Enter a key first.'; return }
        $dlg.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $lblResult.ForeColor = [System.Drawing.Color]::Black
        $lblResult.Text = 'Testing...'
        [System.Windows.Forms.Application]::DoEvents()
        try {
            $probe = Get-AbuseIpdb -Ip '8.8.8.8' -ApiKey $k
            if ($probe.Available) {
                $lblResult.ForeColor = $Theme.Good
                $lblResult.Text = ('Key works. Test lookup of 8.8.8.8 returned confidence {0}%.' -f $probe.Score)
            } else {
                $lblResult.ForeColor = $Theme.Bad
                $lblResult.Text = ('Key did not work: {0}. (HTTP 401 means the key is wrong.)' -f $probe.Error)
            }
        } finally { $dlg.Cursor = [System.Windows.Forms.Cursors]::Default }
    }.GetNewClosure())

    $btnSaveKey.Add_Click({
        $k = $txtKey.Text.Trim()
        if (-not $k) { $lblResult.ForeColor = $Theme.Warn; $lblResult.Text = 'Enter a key first.'; return }
        if (Set-AbuseIpdbKey -Key $k) {
            $txtKey.Clear()
            $lblResult.ForeColor = $Theme.Good
            $lblResult.Text = ('Saved to {0} (encrypted).' -f (Get-ApiConfigPath))
        } else {
            $lblResult.ForeColor = $Theme.Bad
            $lblResult.Text = 'Could not save the key.'
        }
        & $refresh
    }.GetNewClosure())

    $btnRemove.Add_Click({
        if (Remove-AbuseIpdbKey) {
            $txtKey.Clear()
            $lblResult.ForeColor = $Theme.Good
            $lblResult.Text = 'Saved key removed.'
        } else {
            $lblResult.ForeColor = $Theme.Bad
            $lblResult.Text = 'Could not remove the key.'
        }
        & $refresh
    }.GetNewClosure())

    $dlg.Controls.AddRange(@($lblInfo, $lblState, $lblKey, $txtKey, $chkShow, $lblResult,
        $btnTest, $btnSaveKey, $btnRemove, $btnClose))
    $dlg.AcceptButton = $btnClose
    return $dlg
}

function Save-FormPng {
    # Headless render check: draw the form to a bitmap and save it. Used by the
    # -SelfTestPng test hook.
    param($Form, [string]$Path)
    $bmp = New-Object System.Drawing.Bitmap($Form.Width, $Form.Height)
    try {
        $Form.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $Form.Width, $Form.Height)))
        $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally { $bmp.Dispose() }
}
