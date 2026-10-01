<#
    IP-Triage - domain DNS / mail-security checks
    ---------------------------------------------
    Ported from examples\Get-DomainDNSInfo.ps1, which stays in place untouched as
    the reference original. That script is a console program; this is a library.

    What changed in the port, and why:
      * Every Write-Host became StringBuilder output, so the report can be shown
        in a GUI pane, copied and saved.
      * The interactive propagation menu (Show-Menu + a Read-Host loop) is GONE.
        A Read-Host reached from a background runspace has no console to read
        from and blocks forever - it would hang the window with no error. The
        same capability is exposed as Get-GlobalDnsRecordReport, which takes the
        record type as a parameter instead of prompting.
      * Top-level exit / Set-ExecutionPolicy / Unblock-File / param() removed:
        this file is dot-sourced into the UI thread AND the worker runspace, so
        nothing may execute at load time.
      * Check-GlobalDNSRecord renamed to Get-GlobalDnsRecordReport (approved verb).

    The DNS logic itself - the retry and NXDOMAIN-vs-transient sentinel, the
    recursive SPF lookup counting, the provider-aware DKIM hints and the
    [OK]/[FAIL]/[WARN]/[UNKNOWN]/[FOUND] labels - is carried over as-is. The
    labels matter: "cannot determine" must never read as "broken".

    Windows PowerShell 5.1 only. Function definitions only.
#>

function Get-GlobalDnsServers {
    # Public resolvers used for the propagation check. Ordered for deterministic
    # output; deduplicated (the original listed Cloudflare three times).
    return [ordered]@{
        'Google Primary'       = '8.8.8.8'
        'Google Secondary'     = '8.8.4.4'
        'Cloudflare Primary'   = '1.1.1.1'
        'Cloudflare Secondary' = '1.0.0.1'
        'Quad9'                = '9.9.9.9'
        'OpenDNS Primary'      = '208.67.222.222'
        'OpenDNS Secondary'    = '208.67.220.220'
        'Comodo Secure'        = '8.26.56.26'
    }
}

# ---------------------------------------------------------------------------
# DNS lookup helper (ported as-is)
# ---------------------------------------------------------------------------
# Return values:
#   $null                              - NXDOMAIN or NO_RECORDS (genuinely absent)
#   PSCustomObject with __LookupFailed - transient failure (timeout, SERVFAIL)
#                                        callers surface this as [UNKNOWN], not [FAIL]
#   array of DNS records               - normal success
#
#   9003 = DNS_ERROR_RCODE_NAME_ERROR  (NXDOMAIN - name truly doesn't exist)
#   9501 = DNS_INFO_NO_RECORDS         (name exists, no records of this type)
function Invoke-DnsLookup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Type,
        [string]$Server,
        [int]$MaxAttempts = 2
    )

    $splat = @{
        Name        = $Name
        Type        = $Type
        DnsOnly     = $true
        NoHostsFile = $true
        ErrorAction = 'Stop'
    }
    if ($Server) { $splat.Server = $Server }

    $fallbacks = @('1.1.1.1', '9.9.9.9', '8.8.8.8')
    $attempt = 0

    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            return ,(Resolve-DnsName @splat)
        }
        catch [System.ComponentModel.Win32Exception] {
            $code = $_.Exception.NativeErrorCode
            if ($code -eq 9003 -or $code -eq 9501) {
                return $null
            }
            if ($attempt -lt $MaxAttempts -and -not $PSBoundParameters.ContainsKey('Server')) {
                $splat.Server = $fallbacks[($attempt - 1) % $fallbacks.Count]
                Start-Sleep -Milliseconds 300
                continue
            }
            return [PSCustomObject]@{ __LookupFailed = $true; Error = $_.Exception.Message }
        }
        catch {
            return [PSCustomObject]@{ __LookupFailed = $true; Error = $_.Exception.Message }
        }
    }
}

function Test-LookupFailure {
    param($Result)
    if ($null -eq $Result) { return $false }
    $first = @($Result)[0]
    if ($first -is [PSCustomObject] -and ($first.PSObject.Properties.Name -contains '__LookupFailed')) {
        return $true
    }
    return $false
}

function Join-TxtStrings {
    # DKIM records frequently exceed the 255-char single-string DNS limit and
    # arrive split across .Strings entries.
    param($Record)
    if ($null -eq $Record.Strings) { return '' }
    return -join $Record.Strings
}

# ---------------------------------------------------------------------------
# SPF recursive validation (ported as-is)
# ---------------------------------------------------------------------------
function Test-SpfIncludes {
    param(
        [string]$SpfRecord,
        [array]$CheckedDomains = @(),
        [int]$Depth = 0,
        [string]$Resolver = ''
    )

    $MaxLookups = 10  # RFC 7208 Section 4.6.4
    $Results = [ordered]@{
        ValidRecord = $true
        Issues      = [System.Collections.Generic.List[string]]::new()
        LookupCount = 0
        Details     = @{}
    }

    if ($Depth -gt $MaxLookups) {
        $Results.ValidRecord = $false
        $Results.Issues.Add("ERROR: Maximum SPF lookup limit ($MaxLookups) exceeded")
        return $Results
    }

    $includes = [regex]::Matches($SpfRecord, '(?:include:)([\w\-\.]+)') |
                ForEach-Object { $_.Groups[1].Value }

    foreach ($incDomain in $includes) {
        $Results.Details[$incDomain] = @{
            HasTXTRecords = $false
            TXTRecords    = @()
            HasSPF        = $false
        }

        if ($CheckedDomains -contains $incDomain) {
            $Results.Issues.Add("WARNING: Circular reference detected for domain: $incDomain")
            continue
        }

        if ($Resolver) { $txt = Invoke-DnsLookup -Name $incDomain -Type 'TXT' -Server $Resolver }
        else           { $txt = Invoke-DnsLookup -Name $incDomain -Type 'TXT' }
        if ($null -eq $txt -or (Test-LookupFailure $txt)) {
            $Results.ValidRecord = $false
            $Results.Issues.Add("ERROR: Failed to resolve included domain: $incDomain")
            continue
        }

        $Results.Details[$incDomain].HasTXTRecords = $true
        $spfFound = $false

        foreach ($rec in $txt) {
            $combined = Join-TxtStrings $rec
            if (-not $combined) { continue }
            $Results.Details[$incDomain].TXTRecords += $combined
            if ($combined -match '^v=spf1') {
                $spfFound = $true
                $Results.Details[$incDomain].HasSPF = $true
                $Results.LookupCount++

                $sub = Test-SpfIncludes -SpfRecord $combined `
                                        -CheckedDomains ($CheckedDomains + $incDomain) `
                                        -Depth ($Depth + 1) `
                                        -Resolver $Resolver
                $Results.ValidRecord = $Results.ValidRecord -and $sub.ValidRecord
                foreach ($i in $sub.Issues) { $Results.Issues.Add($i) }
                $Results.LookupCount += $sub.LookupCount
            }
        }

        if (-not $spfFound) {
            $Results.ValidRecord = $false
            $Results.Issues.Add("ERROR: No valid SPF record found for included domain: $incDomain")
        }
    }

    return $Results
}

function Format-SpfResults {
    # Was Write-Host; now returns the text plus an overall status so the UI can
    # colour it. $Results is the ordered dictionary from Test-SpfIncludes.
    param($Results, [string]$OriginalRecord)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== SPF Record ===')
    [void]$sb.AppendLine($OriginalRecord)
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== SPF Validation ===')

    $status = 'FAIL'
    if ($Results.ValidRecord -and $Results.LookupCount -le 8) {
        $status = 'OK'
        [void]$sb.AppendLine('[OK]   Overall Status: Valid')
    } elseif ($Results.ValidRecord -and $Results.LookupCount -gt 8) {
        $status = 'WARN'
        [void]$sb.AppendLine('[WARN] Overall Status: Valid but approaching RFC 7208 lookup limit')
    } else {
        [void]$sb.AppendLine('[FAIL] Overall Status: Invalid')
    }
    [void]$sb.AppendLine(('Total DNS Lookups: {0} (RFC 7208 limit: 10)' -f $Results.LookupCount))

    if ($Results.Issues.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Issues found:')
        foreach ($issue in $Results.Issues) { [void]$sb.AppendLine('  - ' + $issue) }
    } else {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('No issues found')
    }
    return [pscustomobject]@{ Text = $sb.ToString(); Status = $status; Lookups = $Results.LookupCount }
}

# ---------------------------------------------------------------------------
# DKIM helpers (ported as-is)
# ---------------------------------------------------------------------------
function Get-CommonDkimSelectors {
    # Generic selector list covering common providers. NOT exhaustive.
    # Account-specific selectors (SMTP2GO 's<id>', custom SendGrid selectors,
    # Salesforce org selectors) must be passed in by the caller.
    $monthSelector = Get-Date -Format 'yyyyMM'
    $list = @(
        'selector1', 'selector2',
        'selector1-<dashdomain>', 'selector2-<dashdomain>',
        'google', 'google1', 'google2',
        'default', 'dkim', 'dkim1', 'dkim2', 'mail', 'email',
        'k1', 'k2', 'key1', 'key2',
        's1', 's2', 'sg', 'em', 'm1', 'mta', 'smtp',
        'mandrill', 'mte1', 'mte2',
        'amazonses',
        'pps', 'ppdkim',
        'mimecast', 'mimecast1', 'mimecast2',
        'zoho', 'zmail',
        'hs1', 'hs2', 'hs1-<dashdomain>', 'hs2-<dashdomain>',
        'cc', 'sib', 'postmark', 'helpscout',
        $monthSelector
    )
    return $list | Select-Object -Unique
}

function Expand-DkimSelectors {
    # Expand <dashdomain> with the domain's dashed form (example.au ->
    # example-au), used by the M365 / HubSpot CNAME patterns.
    param([string[]]$Selectors, [string]$Domain)
    if ($null -eq $Selectors -or $Selectors.Count -eq 0) { return @() }
    $dashDomain = $Domain -replace '\.', '-'
    return $Selectors | ForEach-Object { $_ -replace '<dashdomain>', $dashDomain }
}

function Get-ProviderSelectorHints {
    # Parse SPF for known providers and suggest selectors. Entries in [] are
    # informational only and are never probed.
    param([string]$SpfRecord, [string]$Domain)

    $dashDomain = $Domain -replace '\.', '-'
    $hints = [ordered]@{}

    $providerMap = [ordered]@{
        'spf.protection.outlook.com'  = @(("selector1-" + $dashDomain), ("selector2-" + $dashDomain))
        '_spf.google.com'              = @('google', 'google1', 'google2')
        'spf.smtp2go.com'              = @('[SMTP2GO uses account-specific selectors: s<accountid>. Pass via Selectors]')
        'sendgrid.net'                 = @('s1', 's2', '[Custom SendGrid selectors if configured - pass via Selectors]')
        'amazonses.com'                = @('amazonses', '[SES also supports per-identity custom selectors]')
        'mailgun.org'                  = @('mailo', 'smtp', 'k1', '[Mailgun domain-scoped selectors]')
        'servers.mcsv.net'             = @('k1', 'k2', 'k3')
        'spf.mandrillapp.com'          = @('mandrill', 'mte1', 'mte2')
        'mktomail.com'                 = @('m1')
        'spf.mail.zendesk.com'         = @('zendesk1', 'zendesk2')
        'helpscoutemail.com'           = @('helpscout')
        'spf.mtasv.net'                = @('postmark')
        '_spf.salesforce.com'          = @('[Salesforce selectors are org-specific; check Salesforce Deliverability setup]')
        'spf.freshemail.net'           = @('freshdesk1', 'freshdesk2')
        'spf.createsend.com'           = @('cm')
        'sendpulse.com'                = @('sendpulse')
        '_spf.sender-net.com'          = @('sender')
        'mailersend.net'               = @('mlsend1', 'mlsend2')
    }

    foreach ($pattern in $providerMap.Keys) {
        if ($SpfRecord -match [regex]::Escape($pattern)) {
            $hints[$pattern] = $providerMap[$pattern]
        }
    }
    return $hints
}

function Get-TxtRecordTag {
    # Tag a TXT record by recognised purpose, so stale verification tokens for
    # discontinued services are easy to spot.
    param([string]$TxtContent)

    switch -Regex ($TxtContent) {
        '^v=spf1'                           { return '[SPF]      ' }
        '^v=DMARC1'                         { return '[DMARC]    ' }
        '^v=DKIM1'                          { return '[DKIM]     ' }
        '^(MS|ms)='                         { return '[M365]     ' }
        '^google-site-verification='        { return '[Google]   ' }
        '^knowbe4-site-verification='       { return '[KnowBe4]  ' }
        '^atlassian-domain-verification='   { return '[Atlassian]' }
        '^(facebook|meta)-domain-verification=' { return '[Meta]     ' }
        '^apple-domain-verification='       { return '[Apple]    ' }
        '^docusign='                        { return '[DocuSign] ' }
        '^adobe-idp-site-verification='     { return '[Adobe]    ' }
        '^stripe-verification='             { return '[Stripe]   ' }
        '^Dynatrace-site-verification='     { return '[Dynatrace]' }
        '^zoom-domain-verification='        { return '[Zoom]     ' }
        '^workplace-domain-verification='   { return '[Workplace]' }
        '^pardot'                           { return '[Pardot]   ' }
        '^mailru-verification='             { return '[Mail.ru]  ' }
        '^yandex-verification='             { return '[Yandex]   ' }
        '^amazonses:'                       { return '[AWS-SES]  ' }
        '^have-i-been-pwned-verification='  { return '[HIBP]     ' }
        '^loaderio='                        { return '[Loader.io]' }
        '^onetrust-domain-verification='    { return '[OneTrust] ' }
        default                             { return '[Other]    ' }
    }
}

# ---------------------------------------------------------------------------
# Report builders (were the MAIN block)
# ---------------------------------------------------------------------------
function Get-DomainDnsReport {
    # The full single-resolver report: A/AAAA/MX/CNAME/NS/TXT, SPF validation,
    # DMARC, DKIM probing and SOA. Returns the text plus a short Findings list
    # the UI colours as a status strip.
    param(
        [string]$Domain,
        [string[]]$Selectors = @(),
        # Default to a PUBLIC resolver. Using this PC's DNS gives the internal
        # split-horizon view inside a customer network - an AD zone for the same
        # name typically has no MX/TXT, so the report would claim SPF, DMARC and
        # MX are all missing when they are published perfectly well. Pass '' to
        # deliberately query whatever this machine uses.
        [string]$Resolver = '1.1.1.1',
        $Progress = $null      # optional scriptblock for status updates
    )
    $sb = New-Object System.Text.StringBuilder
    $findings = [System.Collections.Generic.List[object]]::new()
    function AddFinding($Area, $Status, $Detail) {
        [void]$findings.Add([pscustomobject]@{ Area = $Area; Status = $Status; Detail = $Detail })
    }
    function Report($Message) {
        if ($Progress) { & $Progress $Message }
    }
    function Lookup($Name, $Type) {
        if ($Resolver) { return Invoke-DnsLookup -Name $Name -Type $Type -Server $Resolver }
        return Invoke-DnsLookup -Name $Name -Type $Type
    }

    $resolverLabel = $Resolver
    if (-not $resolverLabel) { $resolverLabel = "this PC's DNS (internal view)" }
    [void]$sb.AppendLine(('Domain Information for: {0}' -f $Domain))
    [void]$sb.AppendLine(('Resolver : {0}' -f $resolverLabel))
    [void]$sb.AppendLine(('Generated: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))

    Report 'Looking up records...'
    $recordTypes = @('A', 'AAAA', 'MX', 'CNAME', 'NS', 'TXT', 'SOA')
    $records = [ordered]@{}
    foreach ($type in $recordTypes) {
        $records[$type] = Lookup $Domain $type
    }

    # --- A ---
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== A Records ===')
    if (Test-LookupFailure $records['A']) {
        [void]$sb.AppendLine(('[UNKNOWN] A lookup failed: {0}' -f $records['A'].Error))
    } else {
        $aRecs = @($records['A'] | Where-Object { $_.IPAddress })
        if (@($aRecs).Count -gt 0) {
            foreach ($r in $aRecs) { [void]$sb.AppendLine(('Hostname: {0}  IP: {1}  TTL: {2}' -f $r.Name, $r.IPAddress, $r.TTL)) }
        } else { [void]$sb.AppendLine('No A records found.') }
    }

    # --- AAAA ---
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== AAAA Records ===')
    if (Test-LookupFailure $records['AAAA']) {
        [void]$sb.AppendLine(('[UNKNOWN] AAAA lookup failed: {0}' -f $records['AAAA'].Error))
    } else {
        $aaaaRecs = @($records['AAAA'] | Where-Object { $_.IPAddress })
        if (@($aaaaRecs).Count -gt 0) {
            foreach ($r in $aaaaRecs) { [void]$sb.AppendLine(('Hostname: {0}  IPv6: {1}  TTL: {2}' -f $r.Name, $r.IPAddress, $r.TTL)) }
        } else { [void]$sb.AppendLine('No AAAA records found.') }
    }

    # --- MX ---
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== MX Records ===')
    if (Test-LookupFailure $records['MX']) {
        [void]$sb.AppendLine(('[UNKNOWN] MX lookup failed: {0}' -f $records['MX'].Error))
        AddFinding 'MX' 'UNKNOWN' 'lookup failed'
    } else {
        $mxRecs = @($records['MX'] | Where-Object { $_.NameExchange })
        if (@($mxRecs).Count -gt 0) {
            foreach ($r in (@($mxRecs) | Sort-Object Preference)) {
                [void]$sb.AppendLine(('Preference: {0}  Exchange: {1}  TTL: {2}' -f $r.Preference, $r.NameExchange, $r.TTL))
            }
            AddFinding 'MX' 'OK' (('{0} host(s)' -f @($mxRecs).Count))
        } else {
            [void]$sb.AppendLine('No MX records found.')
            AddFinding 'MX' 'FAIL' 'none'
        }
    }

    # --- CNAME ---
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== CNAME Records ===')
    if (Test-LookupFailure $records['CNAME']) {
        [void]$sb.AppendLine(('[UNKNOWN] CNAME lookup failed: {0}' -f $records['CNAME'].Error))
    } else {
        $cnameRecs = @($records['CNAME'] | Where-Object { $_.NameHost })
        if (@($cnameRecs).Count -gt 0) {
            foreach ($r in $cnameRecs) { [void]$sb.AppendLine(('Alias: {0}  Target: {1}  TTL: {2}' -f $r.Name, $r.NameHost, $r.TTL)) }
        } else { [void]$sb.AppendLine('No CNAME records found at the apex (subdomain CNAMEs not enumerated).') }
    }

    # --- NS ---
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== NS Records ===')
    if (Test-LookupFailure $records['NS']) {
        [void]$sb.AppendLine(('[UNKNOWN] NS lookup failed: {0}' -f $records['NS'].Error))
    } else {
        $nsRecs = @($records['NS'] | Where-Object { $_.NameHost })
        if (@($nsRecs).Count -gt 0) {
            foreach ($r in $nsRecs) { [void]$sb.AppendLine(('Nameserver: {0}  TTL: {1}' -f $r.NameHost, $r.TTL)) }
        } else { [void]$sb.AppendLine('No NS records found.') }
    }

    # --- TXT (with tagging) ---
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== TXT Records ===')
    $txtRecs = $null
    if (Test-LookupFailure $records['TXT']) {
        [void]$sb.AppendLine(('[UNKNOWN] TXT lookup failed: {0}' -f $records['TXT'].Error))
    } else {
        $txtRecs = @($records['TXT'] | Where-Object { $_.Strings })
        if (@($txtRecs).Count -gt 0) {
            foreach ($r in $txtRecs) {
                $combined = Join-TxtStrings $r
                if (-not $combined) { continue }
                $tag = Get-TxtRecordTag $combined
                [void]$sb.AppendLine(('  {0}{1}' -f $tag, $combined))
            }
        } else { [void]$sb.AppendLine('No TXT records found.') }
    }

    # --- SPF ---
    Report 'Validating SPF...'
    $spfRecords = @()
    if ($txtRecs) {
        foreach ($r in $txtRecs) {
            $combined = Join-TxtStrings $r
            if ($combined -match '^v=spf1') { $spfRecords += $combined }
        }
    }

    if (@($spfRecords).Count -eq 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('[FAIL] No SPF Records Found')
        AddFinding 'SPF' 'FAIL' 'no record'
    } elseif (@($spfRecords).Count -gt 1) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('[FAIL] Multiple SPF Records Found (RFC 7208 violation - receivers MAY reject):')
        foreach ($rec in $spfRecords) { [void]$sb.AppendLine('  ' + $rec) }
        AddFinding 'SPF' 'FAIL' (('{0} records' -f @($spfRecords).Count))
    } else {
        $validation = Test-SpfIncludes -SpfRecord $spfRecords[0] -Resolver $Resolver
        $spfOut = Format-SpfResults -Results $validation -OriginalRecord $spfRecords[0]
        [void]$sb.Append($spfOut.Text)
        AddFinding 'SPF' $spfOut.Status (('{0} lookups' -f $spfOut.Lookups))
    }

    # --- DMARC ---
    Report 'Checking DMARC...'
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== DMARC Record ===')
    $dmarcRecs = Lookup ('_dmarc.' + $Domain) 'TXT'
    $dmarcFound = $false
    $dmarcPolicy = $null

    if (Test-LookupFailure $dmarcRecs) {
        [void]$sb.AppendLine(('[UNKNOWN] DMARC lookup failed: {0}' -f $dmarcRecs.Error))
        AddFinding 'DMARC' 'UNKNOWN' 'lookup failed'
    } elseif ($dmarcRecs) {
        foreach ($r in $dmarcRecs) {
            $combined = Join-TxtStrings $r
            if ($combined -match '^v=DMARC1') {
                $dmarcFound = $true
                # Copy the capture immediately - a later -match clobbers $Matches.
                if ($combined -match 'p=(\w+)') { $dmarcPolicy = $Matches[1].ToLower() }

                $label = '[WARN]'
                if ($dmarcPolicy -eq 'reject' -or $dmarcPolicy -eq 'quarantine') { $label = '[OK]  ' }
                [void]$sb.AppendLine(('{0} {1}' -f $label, $combined))

                if ($dmarcPolicy -eq 'none') {
                    [void]$sb.AppendLine("       Policy is 'none' - reporting only, no enforcement.")
                    [void]$sb.AppendLine("       Recommend tightening to 'quarantine' once SPF+DKIM alignment")
                    [void]$sb.AppendLine('       is verified for all legitimate sending sources.')
                }
                if ($combined -notmatch 'rua=') {
                    [void]$sb.AppendLine("       No 'rua=' configured - DMARC aggregate reports are not being collected.")
                }
                if ($dmarcPolicy -eq 'reject' -or $dmarcPolicy -eq 'quarantine') {
                    AddFinding 'DMARC' 'OK' ('p=' + $dmarcPolicy)
                } else {
                    AddFinding 'DMARC' 'WARN' ('p=' + $dmarcPolicy)
                }
            }
        }
    }
    if (-not $dmarcFound -and -not (Test-LookupFailure $dmarcRecs)) {
        [void]$sb.AppendLine('[FAIL] No DMARC record configured')
        [void]$sb.AppendLine(('       Starter: v=DMARC1; p=none; rua=mailto:dmarc@{0}; fo=1' -f $Domain))
        AddFinding 'DMARC' 'FAIL' 'no record'
    }

    # --- DKIM (with SPF-derived provider hints) ---
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== DKIM Records ===')

    $extras = @(Expand-DkimSelectors -Selectors $Selectors -Domain $Domain)
    $hintSelectors = @()
    $providerHints = $null
    if (@($spfRecords).Count -eq 1) {
        $providerHints = Get-ProviderSelectorHints -SpfRecord $spfRecords[0] -Domain $Domain
        foreach ($p in $providerHints.Keys) {
            foreach ($sel in $providerHints[$p]) {
                if ($sel -notmatch '^\[') { $hintSelectors += $sel }
            }
        }
    }
    $hintSelectors = @(Expand-DkimSelectors -Selectors $hintSelectors -Domain $Domain)
    $generic = @(Expand-DkimSelectors -Selectors (Get-CommonDkimSelectors) -Domain $Domain)
    $probeSelectors = @(@($extras + $hintSelectors + $generic) | Select-Object -Unique)

    if ($providerHints -and $providerHints.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Provider hints (derived from SPF includes):')
        foreach ($p in $providerHints.Keys) {
            [void]$sb.AppendLine(('  [{0}]' -f $p))
            foreach ($sel in $providerHints[$p]) {
                if ($sel -match '^\[') { [void]$sb.AppendLine(('    ! {0}' -f $sel)) }
                else { [void]$sb.AppendLine(('    -> probing selector: {0}' -f $sel)) }
            }
        }
        [void]$sb.AppendLine('')
    }

    Report (('Probing {0} DKIM selectors...' -f @($probeSelectors).Count))
    $dkimFound = $false
    $dkimHits = 0
    foreach ($sel in $probeSelectors) {
        $dkimHost = $sel + '._domainkey.' + $Domain
        $dkimRec = Lookup $dkimHost 'TXT'
        if ($null -eq $dkimRec -or (Test-LookupFailure $dkimRec)) { continue }

        foreach ($r in $dkimRec) {
            $combined = Join-TxtStrings $r
            if (-not $combined) { continue }
            # v= is technically optional, so accept naked k=rsa / p= records too.
            if ($combined -match '^v=DKIM1' -or $combined -match '(^|;\s*)k=rsa' -or $combined -match '(^|;\s*)p=[A-Za-z0-9+/]{20,}') {
                [void]$sb.AppendLine(('[FOUND] Selector: {0}' -f $sel))
                [void]$sb.AppendLine(('        Host:     {0}' -f $dkimHost))
                $preview = $combined
                if ($preview.Length -gt 120) { $preview = $preview.Substring(0, 120) + '...' }
                [void]$sb.AppendLine(('        Record:   {0}' -f $preview))
                $dkimFound = $true
                $dkimHits++
            }
        }
    }

    if (-not $dkimFound) {
        [void]$sb.AppendLine('[UNKNOWN] DKIM status could not be determined from common selectors')
        [void]$sb.AppendLine(('          Checked {0} selectors - none returned a record.' -f @($probeSelectors).Count))
        [void]$sb.AppendLine('          This does NOT confirm DKIM is absent. Selectors are provider-')
        [void]$sb.AppendLine("          and account-specific (e.g. SMTP2GO uses 's<accountid>').")
        [void]$sb.AppendLine('          To confirm:')
        [void]$sb.AppendLine("            1. Inspect a received email's Authentication-Results header")
        [void]$sb.AppendLine("               for the 's=' tag - this names the actual selector.")
        [void]$sb.AppendLine('            2. Re-run with that selector in the Selectors box.')
        [void]$sb.AppendLine("            3. Cross-check TXT/CNAME records at the DNS host for any")
        [void]$sb.AppendLine("               '_domainkey' entries.")
        AddFinding 'DKIM' 'UNKNOWN' (('{0} selectors tried' -f @($probeSelectors).Count))
    } else {
        AddFinding 'DKIM' 'FOUND' (('{0} selector(s)' -f $dkimHits))
    }

    # --- Split-horizon check ---
    # Inside a customer network this PC often resolves the domain from an
    # internal AD zone of the same name, which usually carries no MX/TXT. Left
    # unnoticed that reads as "SPF, DMARC and MX are all missing". Compare the
    # nameservers the two views report and say so plainly.
    if ($Resolver) {
        Report 'Checking for split-horizon DNS...'
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('=== Internal vs public view ===')
        $localNs = Invoke-DnsLookup -Name $Domain -Type 'NS'
        if (Test-LookupFailure $localNs -or $null -eq $localNs) {
            [void]$sb.AppendLine("This PC's DNS returned no NS records - nothing to compare.")
        } else {
            $localNames = @(@($localNs | Where-Object { $_.NameHost } | ForEach-Object { $_.NameHost.ToLower() }) | Sort-Object -Unique)
            $publicNames = @()
            if (-not (Test-LookupFailure $records['NS']) -and $records['NS']) {
                $publicNames = @(@($records['NS'] | Where-Object { $_.NameHost } | ForEach-Object { $_.NameHost.ToLower() }) | Sort-Object -Unique)
            }
            $differs = (($localNames -join ',') -ne ($publicNames -join ','))
            if ($differs -and @($localNames).Count -gt 0) {
                [void]$sb.AppendLine('[WARN] Split-horizon DNS detected - this PC sees a different zone.')
                [void]$sb.AppendLine(('       This PC NS : {0}' -f ($localNames -join ', ')))
                [void]$sb.AppendLine(('       Public NS  : {0}' -f ($publicNames -join ', ')))
                [void]$sb.AppendLine('       The report above is the PUBLIC view, which is the one that')
                [void]$sb.AppendLine('       matters for mail delivery and external access.')
                AddFinding 'Split-horizon' 'WARN' 'internal zone differs'
            } else {
                [void]$sb.AppendLine('No split-horizon detected - internal and public nameservers agree.')
            }
        }
    }

    # --- SOA ---
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== SOA Record ===')
    if (Test-LookupFailure $records['SOA']) {
        [void]$sb.AppendLine(('[UNKNOWN] SOA lookup failed: {0}' -f $records['SOA'].Error))
    } else {
        $soa = @($records['SOA'] | Where-Object { $_.PrimaryServer }) | Select-Object -First 1
        if ($soa) {
            [void]$sb.AppendLine(('Primary NS:   {0}' -f $soa.PrimaryServer))
            [void]$sb.AppendLine(('Admin:        {0}' -f $soa.NameAdministrator))
            [void]$sb.AppendLine(('Serial:       {0}' -f $soa.SerialNumber))
            [void]$sb.AppendLine(('TTL:          {0} seconds' -f $soa.TimeToLive))
        } else { [void]$sb.AppendLine('No SOA record found') }
    }

    return [pscustomobject]@{
        Domain   = $Domain
        Text     = $sb.ToString()
        Findings = @($findings.ToArray())
    }
}

function Get-GlobalDnsRecordReport {
    # Propagation check across the public resolvers. Was Check-GlobalDNSRecord
    # plus the menu's DKIM branch; the record type is now a parameter instead of
    # a Read-Host prompt.
    param(
        [string]$Domain,
        [string]$RecordType,
        [string[]]$Selectors = @(),
        $Servers = $null,
        $Progress = $null,
        $CancelCheck = $null
    )
    if (-not $Servers) { $Servers = Get-GlobalDnsServers }
    $sb = New-Object System.Text.StringBuilder
    function Report2($Message) { if ($Progress) { & $Progress $Message } }
    function Stopped2 { if ($CancelCheck) { return [bool](& $CancelCheck) } return $false }

    # DMARC is just a TXT lookup at a prefixed name.
    $lookupName = $Domain
    $queryType = $RecordType
    if ($RecordType -eq 'DMARC') { $lookupName = '_dmarc.' + $Domain; $queryType = 'TXT' }

    if ($RecordType -eq 'DKIM') {
        [void]$sb.AppendLine(('=== Checking DKIM for {0} across {1} resolvers ===' -f $Domain, @($Servers.Keys).Count))
        $gExtras = @(Expand-DkimSelectors -Selectors $Selectors -Domain $Domain)
        $gGeneric = @(Expand-DkimSelectors -Selectors (Get-CommonDkimSelectors) -Domain $Domain)
        $gSelectors = @(@($gExtras + $gGeneric) | Select-Object -Unique)

        foreach ($location in $Servers.Keys) {
            if (Stopped2) { [void]$sb.AppendLine('(stopped)'); break }
            $server = $Servers[$location]
            Report2 (('DKIM via {0}...' -f $location))
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine(('[{0} ({1})]' -f $location, $server))
            $serverFound = $false
            $serverFailed = $false

            foreach ($sel in $gSelectors) {
                if (Stopped2) { break }
                $dkimHost = $sel + '._domainkey.' + $Domain
                $dkimRec = Lookup $dkimHost 'TXT' -Server $server -MaxAttempts 1
                if (Test-LookupFailure $dkimRec) { $serverFailed = $true; continue }
                if ($null -eq $dkimRec) { continue }
                foreach ($r in $dkimRec) {
                    $combined = Join-TxtStrings $r
                    if (-not $combined) { continue }
                    if ($combined -match '^v=DKIM1' -or $combined -match '(^|;\s*)k=rsa' -or $combined -match '(^|;\s*)p=[A-Za-z0-9+/]{20,}') {
                        $preview = $combined
                        if ($preview.Length -gt 80) { $preview = $preview.Substring(0, 80) + '...' }
                        [void]$sb.AppendLine(("  [FOUND] Selector '{0}': {1}" -f $sel, $preview))
                        $serverFound = $true
                    }
                }
            }
            if (-not $serverFound -and $serverFailed) {
                [void]$sb.AppendLine('  [UNKNOWN] Some lookups failed against this resolver')
            } elseif (-not $serverFound) {
                [void]$sb.AppendLine('  No DKIM found (from probed selectors)')
            }
        }
        return $sb.ToString()
    }

    [void]$sb.AppendLine(('=== Checking {0} for {1} across {2} resolvers ===' -f $RecordType, $lookupName, @($Servers.Keys).Count))
    foreach ($location in $Servers.Keys) {
        if (Stopped2) { [void]$sb.AppendLine('(stopped)'); break }
        $server = $Servers[$location]
        Report2 (('{0} via {1}...' -f $RecordType, $location))
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine(('[{0} ({1})]' -f $location, $server))

        $result = Invoke-DnsLookup -Name $lookupName -Type $queryType -Server $server -MaxAttempts 1
        if (Test-LookupFailure $result) {
            [void]$sb.AppendLine(('  [UNKNOWN] {0}' -f $result.Error))
            continue
        }
        if (-not $result) { [void]$sb.AppendLine('  No Record Found'); continue }

        $hasData = $false
        switch ($queryType) {
            'A'     { foreach ($r in $result) { if ($r.IPAddress) { [void]$sb.AppendLine('  IP: ' + $r.IPAddress); $hasData = $true } } }
            'AAAA'  { foreach ($r in $result) { if ($r.IPAddress) { [void]$sb.AppendLine('  IPv6: ' + $r.IPAddress); $hasData = $true } } }
            'MX'    { foreach ($r in (@($result) | Sort-Object Preference)) { if ($r.NameExchange) { [void]$sb.AppendLine(('  {0} {1}' -f $r.Preference, $r.NameExchange)); $hasData = $true } } }
            'CNAME' { foreach ($r in $result) { if ($r.NameHost) { [void]$sb.AppendLine('  -> ' + $r.NameHost); $hasData = $true } } }
            'NS'    { foreach ($r in $result) { if ($r.NameHost) { [void]$sb.AppendLine('  ' + $r.NameHost); $hasData = $true } } }
            'SOA'   { foreach ($r in $result) { if ($r.PrimaryServer) { [void]$sb.AppendLine(('  Primary: {0}  Serial: {1}' -f $r.PrimaryServer, $r.SerialNumber)); $hasData = $true } } }
            'TXT'   {
                foreach ($r in $result) {
                    $combined = Join-TxtStrings $r
                    if (-not $combined) { continue }
                    $isSecLookup = ($lookupName -like '_dmarc.*' -or $lookupName -like '*._domainkey.*')
                    if ($isSecLookup -or $combined -match '^v=(spf1|DMARC1|DKIM1)') {
                        [void]$sb.AppendLine('  ' + $combined)
                        $hasData = $true
                    }
                }
            }
        }
        if (-not $hasData) { [void]$sb.AppendLine('  No Record Found') }
    }
    return $sb.ToString()
}
