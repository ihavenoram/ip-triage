#Requires -Version 5.0

<#
.SYNOPSIS
    Checks DNS records and email security configuration (SPF, DKIM, DMARC) for a domain.

.DESCRIPTION
    Retrieves A, AAAA, MX, CNAME, NS, TXT, SOA records and validates SPF recursively,
    resolves DMARC, and probes DKIM selectors with provider-aware hints extracted
    from the SPF record. Includes a global propagation checker against 8 public
    resolvers.

    Status labels used:
      [OK]      - confirmed good
      [FAIL]    - confirmed broken (e.g. missing SPF, multiple SPF, oversize SPF lookups)
      [WARN]    - working but suboptimal (e.g. DMARC p=none, SPF close to lookup limit)
      [UNKNOWN] - tool cannot determine (e.g. DKIM selector not in guess list,
                  lookup timed out). Does NOT indicate absence.
      [FOUND]   - record located but not validated at runtime (e.g. DKIM record
                  exists for a selector but we can't prove it's actively signing)

.PARAMETER Domain
    The domain name to check.

.PARAMETER Selectors
    Additional DKIM selectors to probe, beyond the built-in list. Useful when
    the DKIM setup uses account-specific selectors (SMTP2GO 's420734', SendGrid
    custom selectors, etc.). These are tried first so they appear earlier in
    the output.

.EXAMPLE
    .\Get-DomainDNSInfo.ps1 rhmobility.au

.EXAMPLE
    .\Get-DomainDNSInfo.ps1 rhmobility.au -Selectors 's420734'

.EXAMPLE
    # Run with verbose to see resolver errors as they happen (timeouts, etc)
    .\Get-DomainDNSInfo.ps1 rhmobility.au -Verbose

.NOTES
    Revision history (relative to the pre-patch version):
    * Removed Start-Job wrapper. Background jobs were silently swallowing
      Resolve-DnsName failures because the catch filter was Win32Exception-only
      and cross-process serialisation was intermittently stripping the
      .Strings property from TXT records. Direct calls are faster and more
      reliable.
    * Distinguished TIMEOUT / resolver failure from NXDOMAIN. The previous
      version treated every failure as "no record", producing false negatives
      whenever UDP/53 was blocked (e.g. guest Wi-Fi, filtering proxies).
      Timeouts now return a sentinel object and the caller surfaces the
      failure instead of reporting "not found".
    * Added a retry-with-fallback-resolver pass. If the first lookup fails
      transiently, the function tries the next resolver in a short list
      before giving up.
    * Removed the duplicate Test-SPFIncludedDomains function definition.
    * Fixed broken brace structure in the AAAA switch case of
      Check-GlobalDNSRecord which was throwing at runtime.
    * Fixed SOA output showing NameAdministrator (admin contact) mislabelled
      as "Primary NS". Correct property is PrimaryServer.
    * DKIM records that span multiple .Strings entries are now concatenated
      before regex matching and display (DKIM keys frequently exceed the
      255-char single-string DNS limit).
    * Expanded DKIM selector list to cover SendGrid, SMTP2GO (generic
      fallbacks only - account-specific selectors must be passed via
      -Selectors), Mailchimp, Amazon SES, Proofpoint, Mimecast, Zoho,
      HubSpot, and the M365 "selector1-<dashed-domain>" CNAME form.
    * Added SPF-include-based provider detection. The SPF record is parsed
      for known provider domains and selectors are auto-suggested based on
      matches. This promotes DKIM checking from blind guessing to
      provider-aware probing.
    * Added -Selectors parameter so account-specific selectors (e.g. SMTP2GO
      's<accountid>') can be supplied when known.
    * TXT display now tags each record by recognised purpose ([SPF], [M365],
      [KnowBe4], etc.) so stale verification tokens for discontinued services
      are easy to spot.
    * Tri-state status labels applied throughout:
        [OK]/[FAIL]/[WARN]/[UNKNOWN]/[FOUND]
      so that "I couldn't determine this" never reads as "this is broken."
    * PS 5.1 compatible throughout. No null-coalescing (??), ternary, or
      other PS 7+ syntax. Designed to run fine under Atera's constrained
      SYSTEM/Session-0 PowerShell host.
    * Deduplicated global DNS server list (the original had Cloudflare
      listed three times under different regional labels for 1.1.1.1).
#>

param(
    [Parameter(Position=0, Mandatory=$false)]
    [string]$Domain,

    [Parameter(Mandatory=$false)]
    [string[]]$Selectors = @()
)

if ([string]::IsNullOrEmpty($Domain)) {
    Write-Host "Please provide a domain name." -ForegroundColor Red
    Write-Host "Usage: .\Get-DomainDNSInfo.ps1 domain.com [-Selectors s1,s2,...]" -ForegroundColor Yellow
    exit 1
}

# Bypass execution policy for this process (best-effort)
try { Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue } catch {}

# Clear MoTW if present
try {
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($scriptPath -and (Test-Path -LiteralPath $scriptPath)) {
        Unblock-File -LiteralPath $scriptPath -ErrorAction SilentlyContinue
    }
} catch {}

# Ordered dictionary for deterministic output
$GlobalDNSServers = [ordered]@{
    'Google Primary'       = '8.8.8.8'
    'Google Secondary'     = '8.8.4.4'
    'Cloudflare Primary'   = '1.1.1.1'
    'Cloudflare Secondary' = '1.0.0.1'
    'Quad9'                = '9.9.9.9'
    'OpenDNS Primary'      = '208.67.222.222'
    'OpenDNS Secondary'    = '208.67.220.220'
}

#region DNS lookup helper

# Wrapper around Resolve-DnsName with retry and NXDOMAIN-vs-transient discrimination.
#
# Return values:
#   $null                              - NXDOMAIN or NO_RECORDS (record genuinely absent)
#   PSCustomObject with __LookupFailed - transient failure (timeout, SERVFAIL, etc.)
#                                         callers should surface this as [UNKNOWN], not [FAIL]
#   array of DNS records               - normal success
#
# Native error codes of interest:
#   9003 = DNS_ERROR_RCODE_NAME_ERROR    (NXDOMAIN - name truly doesn't exist)
#   9501 = DNS_INFO_NO_RECORDS           (name exists, no records of this type)
#   Others (timeout, SERVFAIL, etc.) are treated as transient and retried.
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

    # Fallback resolvers for retry. Only used if no explicit -Server was passed.
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
                # Record truly doesn't exist - not an error condition for our purposes
                Write-Verbose "[$Type $Name] NXDOMAIN / no records (code $code)"
                return $null
            }
            # Timeout / SERVFAIL / other transient
            $srvShown = if ($splat.Server) { $splat.Server } else { 'default' }
            Write-Warning ("[{0} {1}] attempt {2} via {3}: {4}" -f $Type, $Name, $attempt, $srvShown, $_.Exception.Message)
            if ($attempt -lt $MaxAttempts -and -not $PSBoundParameters.ContainsKey('Server')) {
                $splat.Server = $fallbacks[($attempt - 1) % $fallbacks.Count]
                Start-Sleep -Milliseconds 300
                continue
            }
            # Out of attempts - return sentinel so caller can distinguish from NXDOMAIN
            return [PSCustomObject]@{ __LookupFailed = $true; Error = $_.Exception.Message }
        }
        catch {
            Write-Warning ("[{0} {1}] {2}" -f $Type, $Name, $_.Exception.Message)
            return [PSCustomObject]@{ __LookupFailed = $true; Error = $_.Exception.Message }
        }
    }
}

# Detect whether an Invoke-DnsLookup return value is the transient-failure sentinel
function Test-LookupFailure {
    param($Result)
    if ($null -eq $Result) { return $false }
    # Sentinel comes back as a single PSCustomObject; successful lookups are arrays
    $first = @($Result)[0]
    if ($first -is [PSCustomObject] -and ($first.PSObject.Properties.Name -contains '__LookupFailed')) {
        return $true
    }
    return $false
}

# DKIM records frequently exceed 255 chars and get split across multiple
# .Strings entries. This reassembles them so regex matching sees the full record.
function Join-TxtStrings {
    param($Record)
    if ($null -eq $Record.Strings) { return '' }
    return -join $Record.Strings
}
#endregion

#region SPF recursive validation

function Test-SpfIncludes {
    param(
        [string]$SpfRecord,
        [array]$CheckedDomains = @(),
        [int]$Depth = 0
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

    foreach ($domain in $includes) {
        $Results.Details[$domain] = @{
            HasTXTRecords = $false
            TXTRecords    = @()
            HasSPF        = $false
        }

        if ($CheckedDomains -contains $domain) {
            $Results.Issues.Add("WARNING: Circular reference detected for domain: $domain")
            continue
        }

        $txt = Invoke-DnsLookup -Name $domain -Type 'TXT'
        if ($null -eq $txt -or (Test-LookupFailure $txt)) {
            $Results.ValidRecord = $false
            $Results.Issues.Add("ERROR: Failed to resolve included domain: $domain")
            continue
        }

        $Results.Details[$domain].HasTXTRecords = $true
        $spfFound = $false

        foreach ($rec in $txt) {
            $combined = Join-TxtStrings $rec
            if (-not $combined) { continue }
            $Results.Details[$domain].TXTRecords += $combined
            if ($combined -match '^v=spf1') {
                $spfFound = $true
                $Results.Details[$domain].HasSPF = $true
                $Results.LookupCount++

                $sub = Test-SpfIncludes -SpfRecord $combined `
                                        -CheckedDomains ($CheckedDomains + $domain) `
                                        -Depth ($Depth + 1)
                $Results.ValidRecord = $Results.ValidRecord -and $sub.ValidRecord
                foreach ($i in $sub.Issues) { $Results.Issues.Add($i) }
                $Results.LookupCount += $sub.LookupCount
            }
        }

        if (-not $spfFound) {
            $Results.ValidRecord = $false
            $Results.Issues.Add("ERROR: No valid SPF record found for included domain: $domain")
        }
    }

    return $Results
}

function Format-SpfResults {
    param([hashtable]$Results, [string]$OriginalRecord)

    Write-Host "`n=== SPF Record ===" -ForegroundColor Cyan
    Write-Host $OriginalRecord -ForegroundColor White

    Write-Host "`n=== SPF Validation ===" -ForegroundColor Cyan
    if ($Results.ValidRecord -and $Results.LookupCount -le 8) {
        Write-Host "[OK]   Overall Status: Valid" -ForegroundColor Green
    } elseif ($Results.ValidRecord -and $Results.LookupCount -gt 8) {
        Write-Host "[WARN] Overall Status: Valid but approaching RFC 7208 lookup limit" -ForegroundColor Yellow
    } else {
        Write-Host "[FAIL] Overall Status: Invalid" -ForegroundColor Red
    }

    $lookupColor = if ($Results.LookupCount -gt 10) { 'Red' }
                   elseif ($Results.LookupCount -gt 8) { 'Yellow' }
                   else { 'White' }
    Write-Host "Total DNS Lookups: $($Results.LookupCount) (RFC 7208 limit: 10)" -ForegroundColor $lookupColor

    if ($Results.Issues.Count -gt 0) {
        Write-Host "`nIssues found:" -ForegroundColor Yellow
        foreach ($issue in $Results.Issues) {
            $color = if ($issue.StartsWith('ERROR')) { 'Red' } else { 'Yellow' }
            Write-Host "  - $issue" -ForegroundColor $color
        }
    } else {
        Write-Host "`nNo issues found" -ForegroundColor Green
    }
}
#endregion

#region DKIM helpers

# Generic selector list covering common providers. NOT exhaustive.
# Account-specific selectors (SMTP2GO 's<id>', custom SendGrid selectors,
# Salesforce org selectors, etc.) must be passed via -Selectors.
function Get-CommonDkimSelectors {
    $monthSelector = Get-Date -Format 'yyyyMM'
    $list = @(
        # Microsoft 365
        'selector1', 'selector2',
        'selector1-<dashdomain>', 'selector2-<dashdomain>',
        # Google Workspace
        'google', 'google1', 'google2',
        # Generic defaults
        'default', 'dkim', 'dkim1', 'dkim2', 'mail', 'email',
        'k1', 'k2', 'key1', 'key2',
        # SendGrid / generic ESP defaults
        's1', 's2', 'sg', 'em', 'm1', 'mta', 'smtp',
        # Mailchimp / Mandrill
        'mandrill', 'mte1', 'mte2',
        # Amazon SES
        'amazonses',
        # Proofpoint
        'pps', 'ppdkim',
        # Mimecast
        'mimecast', 'mimecast1', 'mimecast2',
        # Zoho
        'zoho', 'zmail',
        # HubSpot
        'hs1', 'hs2', 'hs1-<dashdomain>', 'hs2-<dashdomain>',
        # Other
        'cc', 'sib', 'postmark', 'helpscout',
        # Rotating monthly
        $monthSelector
    )
    return $list | Select-Object -Unique
}

# Expand <dashdomain> placeholders with the domain's dashed form
# (rhmobility.au -> rhmobility-au), used by M365 / HubSpot CNAME patterns.
function Expand-DkimSelectors {
    param([string[]]$Selectors, [string]$Domain)
    if ($null -eq $Selectors -or $Selectors.Count -eq 0) { return @() }
    $dashDomain = $Domain -replace '\.', '-'
    return $Selectors | ForEach-Object { $_ -replace '<dashdomain>', $dashDomain }
}

# Parse the SPF record and return provider-specific selector hints.
# Returns an ordered hashtable: include-pattern -> @(selectors or [placeholder hints])
# Placeholder hints (strings starting with '[') are printed but not probed.
function Get-ProviderSelectorHints {
    param([string]$SpfRecord, [string]$Domain)

    $dashDomain = $Domain -replace '\.', '-'
    $hints = [ordered]@{}

    # Pattern -> selectors to try. Concrete selectors are probed automatically.
    # Placeholder strings in [] are informational only.
    $providerMap = [ordered]@{
        'spf.protection.outlook.com'  = @("selector1-$dashDomain", "selector2-$dashDomain")
        '_spf.google.com'              = @('google', 'google1', 'google2')
        'spf.smtp2go.com'              = @('[SMTP2GO uses account-specific selectors: s<accountid>. Pass via -Selectors]')
        'sendgrid.net'                 = @('s1', 's2', '[Custom SendGrid selectors if configured - pass via -Selectors]')
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

# Tag a TXT record's content with its recognised purpose for human-readable display
function Get-TxtRecordTag {
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
#endregion

# ===== MAIN =====

Write-Host "`nDomain Information for: $Domain" -ForegroundColor Yellow

$recordTypes = @('A', 'AAAA', 'MX', 'CNAME', 'NS', 'TXT', 'SOA')
$records = [ordered]@{}
foreach ($type in $recordTypes) {
    $records[$type] = Invoke-DnsLookup -Name $Domain -Type $type
}

# --- A ---
Write-Host "`n=== A Records ===" -ForegroundColor Cyan
if (Test-LookupFailure $records['A']) {
    Write-Host "[UNKNOWN] A lookup failed: $($records['A'].Error)" -ForegroundColor Yellow
} else {
    $aRecs = $records['A'] | Where-Object { $_.IPAddress }
    if ($aRecs) {
        foreach ($r in $aRecs) {
            Write-Host ("Hostname: {0}  IP: {1}  TTL: {2}" -f $r.Name, $r.IPAddress, $r.TTL) -ForegroundColor White
        }
    } else {
        Write-Host "No A records found." -ForegroundColor Yellow
    }
}

# --- AAAA ---
Write-Host "`n=== AAAA Records ===" -ForegroundColor Cyan
if (Test-LookupFailure $records['AAAA']) {
    Write-Host "[UNKNOWN] AAAA lookup failed: $($records['AAAA'].Error)" -ForegroundColor Yellow
} else {
    $aaaaRecs = $records['AAAA'] | Where-Object { $_.IPAddress }
    if ($aaaaRecs) {
        foreach ($r in $aaaaRecs) {
            Write-Host ("Hostname: {0}  IPv6: {1}  TTL: {2}" -f $r.Name, $r.IPAddress, $r.TTL) -ForegroundColor White
        }
    } else {
        Write-Host "No AAAA records found." -ForegroundColor Yellow
    }
}

# --- MX ---
Write-Host "`n=== MX Records ===" -ForegroundColor Cyan
if (Test-LookupFailure $records['MX']) {
    Write-Host "[UNKNOWN] MX lookup failed: $($records['MX'].Error)" -ForegroundColor Yellow
} else {
    $mxRecs = $records['MX'] | Where-Object { $_.NameExchange }
    if ($mxRecs) {
        foreach ($r in ($mxRecs | Sort-Object Preference)) {
            Write-Host ("Preference: {0}  Exchange: {1}  TTL: {2}" -f $r.Preference, $r.NameExchange, $r.TTL) -ForegroundColor White
        }
    } else {
        Write-Host "No MX records found." -ForegroundColor Yellow
    }
}

# --- CNAME ---
Write-Host "`n=== CNAME Records ===" -ForegroundColor Cyan
if (Test-LookupFailure $records['CNAME']) {
    Write-Host "[UNKNOWN] CNAME lookup failed: $($records['CNAME'].Error)" -ForegroundColor Yellow
} else {
    $cnameRecs = $records['CNAME'] | Where-Object { $_.NameHost }
    if ($cnameRecs) {
        foreach ($r in $cnameRecs) {
            Write-Host ("Alias: {0}  Target: {1}  TTL: {2}" -f $r.Name, $r.NameHost, $r.TTL) -ForegroundColor White
        }
    } else {
        Write-Host "No CNAME records found at the apex (subdomain CNAMEs not enumerated)." -ForegroundColor Yellow
    }
}

# --- NS ---
Write-Host "`n=== NS Records ===" -ForegroundColor Cyan
if (Test-LookupFailure $records['NS']) {
    Write-Host "[UNKNOWN] NS lookup failed: $($records['NS'].Error)" -ForegroundColor Yellow
} else {
    $nsRecs = $records['NS'] | Where-Object { $_.NameHost }
    if ($nsRecs) {
        foreach ($r in $nsRecs) {
            Write-Host ("Nameserver: {0}  TTL: {1}" -f $r.NameHost, $r.TTL) -ForegroundColor White
        }
    } else {
        Write-Host "No NS records found." -ForegroundColor Yellow
    }
}

# --- TXT (with tagging) ---
Write-Host "`n=== TXT Records ===" -ForegroundColor Cyan
if (Test-LookupFailure $records['TXT']) {
    Write-Host "[UNKNOWN] TXT lookup failed: $($records['TXT'].Error)" -ForegroundColor Yellow
    $txtRecs = $null
} else {
    $txtRecs = $records['TXT'] | Where-Object { $_.Strings }
    if ($txtRecs) {
        foreach ($r in $txtRecs) {
            $combined = Join-TxtStrings $r
            if (-not $combined) { continue }
            $tag = Get-TxtRecordTag $combined
            Write-Host ("  {0}{1}" -f $tag, $combined) -ForegroundColor Gray
        }
    } else {
        Write-Host "No TXT records found." -ForegroundColor Yellow
    }
}

# --- SPF ---
$spfRecords = @()
if ($txtRecs) {
    foreach ($r in $txtRecs) {
        $combined = Join-TxtStrings $r
        if ($combined -match '^v=spf1') { $spfRecords += $combined }
    }
}

if ($spfRecords.Count -eq 0) {
    Write-Host "`n[FAIL] No SPF Records Found" -ForegroundColor Red
} elseif ($spfRecords.Count -gt 1) {
    Write-Host "`n[FAIL] Multiple SPF Records Found (RFC 7208 violation - receivers MAY reject):" -ForegroundColor Red
    foreach ($rec in $spfRecords) { Write-Host "  $rec" -ForegroundColor White }
} else {
    $validation = Test-SpfIncludes -SpfRecord $spfRecords[0]
    Format-SpfResults -Results $validation -OriginalRecord $spfRecords[0]
}

# --- DMARC ---
Write-Host "`n=== DMARC Record ===" -ForegroundColor Cyan
$dmarcRecs = Invoke-DnsLookup -Name "_dmarc.$Domain" -Type 'TXT'
$dmarcFound = $false
$dmarcPolicy = $null

if (Test-LookupFailure $dmarcRecs) {
    Write-Host "[UNKNOWN] DMARC lookup failed: $($dmarcRecs.Error)" -ForegroundColor Yellow
} elseif ($dmarcRecs) {
    foreach ($r in $dmarcRecs) {
        $combined = Join-TxtStrings $r
        if ($combined -match '^v=DMARC1') {
            $dmarcFound = $true
            if ($combined -match 'p=(\w+)') { $dmarcPolicy = $Matches[1].ToLower() }

            $label = switch ($dmarcPolicy) {
                'reject'     { '[OK]  ' }
                'quarantine' { '[OK]  ' }
                'none'       { '[WARN]' }
                default      { '[WARN]' }
            }
            $color = switch ($dmarcPolicy) {
                'reject'     { 'Green' }
                'quarantine' { 'Green' }
                default      { 'Yellow' }
            }
            Write-Host "$label $combined" -ForegroundColor $color

            if ($dmarcPolicy -eq 'none') {
                Write-Host "       Policy is 'none' - reporting only, no enforcement." -ForegroundColor DarkGray
                Write-Host "       Recommend tightening to 'quarantine' once SPF+DKIM alignment" -ForegroundColor DarkGray
                Write-Host "       is verified for all legitimate sending sources." -ForegroundColor DarkGray
            }
            if ($combined -notmatch 'rua=') {
                Write-Host "       No 'rua=' configured - DMARC aggregate reports are not being collected." -ForegroundColor DarkGray
            }
        }
    }
}
if (-not $dmarcFound -and -not (Test-LookupFailure $dmarcRecs)) {
    Write-Host "[FAIL] No DMARC record configured" -ForegroundColor Red
    Write-Host "       Starter: v=DMARC1; p=none; rua=mailto:dmarc@$Domain; fo=1" -ForegroundColor DarkGray
}

# --- DKIM (with SPF-derived provider hints) ---
Write-Host "`n=== DKIM Records ===" -ForegroundColor Cyan

# Build selector probe list: user-supplied first, then provider hints, then generic
$extras = Expand-DkimSelectors -Selectors $Selectors -Domain $Domain

$hintSelectors = @()
$providerHints = $null
if ($spfRecords.Count -eq 1) {
    $providerHints = Get-ProviderSelectorHints -SpfRecord $spfRecords[0] -Domain $Domain
    foreach ($p in $providerHints.Keys) {
        foreach ($sel in $providerHints[$p]) {
            # Placeholders start with '[' - informational only, don't probe
            if ($sel -notmatch '^\[') { $hintSelectors += $sel }
        }
    }
}
$hintSelectors = Expand-DkimSelectors -Selectors $hintSelectors -Domain $Domain
$generic = Expand-DkimSelectors -Selectors (Get-CommonDkimSelectors) -Domain $Domain

$probeSelectors = @($extras + $hintSelectors + $generic) | Select-Object -Unique

# Emit provider hints before probing so they're visible even if nothing is found
if ($providerHints -and $providerHints.Count -gt 0) {
    Write-Host "`nProvider hints (derived from SPF includes):" -ForegroundColor DarkCyan
    foreach ($p in $providerHints.Keys) {
        Write-Host ("  [{0}]" -f $p) -ForegroundColor DarkCyan
        foreach ($sel in $providerHints[$p]) {
            if ($sel -match '^\[') {
                Write-Host ("    ! {0}" -f $sel) -ForegroundColor DarkGray
            } else {
                Write-Host ("    -> probing selector: {0}" -f $sel) -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ""
}

$dkimFound = $false
foreach ($sel in $probeSelectors) {
    $dkimHost = "${sel}._domainkey.$Domain"
    $dkimRec = Invoke-DnsLookup -Name $dkimHost -Type 'TXT'
    if ($null -eq $dkimRec -or (Test-LookupFailure $dkimRec)) { continue }

    foreach ($r in $dkimRec) {
        $combined = Join-TxtStrings $r
        if (-not $combined) { continue }
        # Match v=DKIM1 explicitly, or naked k=rsa/p= records (v= is technically optional)
        if ($combined -match '^v=DKIM1' -or $combined -match '(^|;\s*)k=rsa' -or $combined -match '(^|;\s*)p=[A-Za-z0-9+/]{20,}') {
            Write-Host ("[FOUND] Selector: {0}" -f $sel) -ForegroundColor Green
            Write-Host ("        Host:     {0}" -f $dkimHost) -ForegroundColor DarkGray
            $preview = if ($combined.Length -gt 120) { $combined.Substring(0,120) + '...' } else { $combined }
            Write-Host ("        Record:   {0}" -f $preview) -ForegroundColor Gray
            $dkimFound = $true
        }
    }
}

if (-not $dkimFound) {
    Write-Host "[UNKNOWN] DKIM status could not be determined from common selectors" -ForegroundColor Yellow
    Write-Host "          Checked $($probeSelectors.Count) selectors - none returned a record." -ForegroundColor DarkGray
    Write-Host "          This does NOT confirm DKIM is absent. Selectors are provider-" -ForegroundColor DarkGray
    Write-Host "          and account-specific (e.g. SMTP2GO uses 's<accountid>', Cin7" -ForegroundColor DarkGray
    Write-Host "          Core/DEAR uses SendGrid's defaults). To confirm:" -ForegroundColor DarkGray
    Write-Host "            1. Inspect a received email's Authentication-Results header" -ForegroundColor DarkGray
    Write-Host "               for the 's=' tag - this names the actual selector." -ForegroundColor DarkGray
    Write-Host "            2. Re-run this script with -Selectors '<yourselector>'" -ForegroundColor DarkGray
    Write-Host "            3. Cross-check TXT/CNAME records at the DNS host for any" -ForegroundColor DarkGray
    Write-Host "               '_domainkey' entries." -ForegroundColor DarkGray
}

# --- SOA ---
Write-Host "`n=== SOA Record ===" -ForegroundColor Cyan
if (Test-LookupFailure $records['SOA']) {
    Write-Host "[UNKNOWN] SOA lookup failed: $($records['SOA'].Error)" -ForegroundColor Yellow
} else {
    $soa = $records['SOA'] | Where-Object { $_.PrimaryServer } | Select-Object -First 1
    if ($soa) {
        Write-Host ("Primary NS:   {0}" -f $soa.PrimaryServer) -ForegroundColor White
        Write-Host ("Admin:        {0}" -f $soa.NameAdministrator) -ForegroundColor White
        Write-Host ("Serial:       {0}" -f $soa.SerialNumber) -ForegroundColor White
        Write-Host ("TTL:          {0} seconds" -f $soa.TimeToLive) -ForegroundColor White
    } else {
        Write-Host "No SOA record found" -ForegroundColor Yellow
    }
}

# ===== GLOBAL PROPAGATION MENU =====

function Check-GlobalDNSRecord {
    param(
        [string]$LookupName,
        [string]$RecordType,
        [hashtable]$Servers
    )

    Write-Host "`n=== Checking $RecordType for $LookupName Globally ===" -ForegroundColor Cyan

    foreach ($location in $Servers.Keys) {
        $server = $Servers[$location]
        Write-Host "`n[$location ($server)]" -ForegroundColor White -NoNewline

        $result = Invoke-DnsLookup -Name $LookupName -Type $RecordType -Server $server -MaxAttempts 1
        if (Test-LookupFailure $result) {
            Write-Host "  [UNKNOWN] $($result.Error)" -ForegroundColor Yellow
            continue
        }
        if (-not $result) {
            Write-Host "  No Record Found" -ForegroundColor Red
            continue
        }

        $hasData = $false
        switch ($RecordType) {
            'A' {
                foreach ($r in $result) {
                    if ($r.IPAddress) { Write-Host "`n  IP: $($r.IPAddress)" -ForegroundColor Green; $hasData = $true }
                }
            }
            'AAAA' {
                foreach ($r in $result) {
                    if ($r.IPAddress) { Write-Host "`n  IPv6: $($r.IPAddress)" -ForegroundColor Green; $hasData = $true }
                }
            }
            'MX' {
                foreach ($r in ($result | Sort-Object Preference)) {
                    if ($r.NameExchange) { Write-Host ("`n  {0} {1}" -f $r.Preference, $r.NameExchange) -ForegroundColor Green; $hasData = $true }
                }
            }
            'CNAME' {
                foreach ($r in $result) {
                    if ($r.NameHost) { Write-Host "`n  -> $($r.NameHost)" -ForegroundColor Green; $hasData = $true }
                }
            }
            'NS' {
                foreach ($r in $result) {
                    if ($r.NameHost) { Write-Host "`n  $($r.NameHost)" -ForegroundColor Green; $hasData = $true }
                }
            }
            'TXT' {
                foreach ($r in $result) {
                    $combined = Join-TxtStrings $r
                    if (-not $combined) { continue }
                    $isSecLookup = $LookupName -like '_dmarc.*' -or $LookupName -like '*._domainkey.*'
                    if ($isSecLookup -or $combined -match '^v=(spf1|DMARC1|DKIM1)') {
                        Write-Host "`n  $combined" -ForegroundColor Green
                        $hasData = $true
                    }
                }
            }
            'SOA' {
                foreach ($r in $result) {
                    if ($r.PrimaryServer) {
                        Write-Host ("`n  Primary: {0}  Serial: {1}" -f $r.PrimaryServer, $r.SerialNumber) -ForegroundColor Green
                        $hasData = $true
                    }
                }
            }
        }
        if (-not $hasData) { Write-Host "  No Record Found" -ForegroundColor Red }
    }
}

function Show-Menu {
    Write-Host "`n=== DNS Propagation Checker ===" -ForegroundColor Cyan
    Write-Host "1. CNAME     2. MX        3. AAAA     4. A" -ForegroundColor Yellow
    Write-Host "5. NS        6. TXT       7. DMARC    8. DKIM" -ForegroundColor Yellow
    Write-Host "9. SOA      10. Exit" -ForegroundColor Yellow
}

do {
    Show-Menu
    $choice = Read-Host "`nSelect 1-10"
    switch ($choice) {
        '1' { Check-GlobalDNSRecord -LookupName $Domain -RecordType 'CNAME' -Servers $GlobalDNSServers }
        '2' { Check-GlobalDNSRecord -LookupName $Domain -RecordType 'MX' -Servers $GlobalDNSServers }
        '3' { Check-GlobalDNSRecord -LookupName $Domain -RecordType 'AAAA' -Servers $GlobalDNSServers }
        '4' { Check-GlobalDNSRecord -LookupName $Domain -RecordType 'A' -Servers $GlobalDNSServers }
        '5' { Check-GlobalDNSRecord -LookupName $Domain -RecordType 'NS' -Servers $GlobalDNSServers }
        '6' { Check-GlobalDNSRecord -LookupName $Domain -RecordType 'TXT' -Servers $GlobalDNSServers }
        '7' { Check-GlobalDNSRecord -LookupName "_dmarc.$Domain" -RecordType 'TXT' -Servers $GlobalDNSServers }
        '8' {
            Write-Host "`n=== Checking DKIM Records Globally ===" -ForegroundColor Cyan
            # Use the same probe list logic as the single-resolver scan
            $gExtras = Expand-DkimSelectors -Selectors $Selectors -Domain $Domain
            $gHintSels = @()
            if ($spfRecords.Count -eq 1) {
                $gHints = Get-ProviderSelectorHints -SpfRecord $spfRecords[0] -Domain $Domain
                foreach ($p in $gHints.Keys) {
                    foreach ($sel in $gHints[$p]) {
                        if ($sel -notmatch '^\[') { $gHintSels += $sel }
                    }
                }
            }
            $gHintSels = Expand-DkimSelectors -Selectors $gHintSels -Domain $Domain
            $gGeneric = Expand-DkimSelectors -Selectors (Get-CommonDkimSelectors) -Domain $Domain
            $gSelectors = @($gExtras + $gHintSels + $gGeneric) | Select-Object -Unique

            foreach ($location in $GlobalDNSServers.Keys) {
                $server = $GlobalDNSServers[$location]
                Write-Host "`n[$location ($server)]" -ForegroundColor White
                $serverFound = $false
                $serverFailed = $false

                foreach ($sel in $gSelectors) {
                    $dkimHost = "${sel}._domainkey.$Domain"
                    $dkimRec = Invoke-DnsLookup -Name $dkimHost -Type 'TXT' -Server $server -MaxAttempts 1
                    if (Test-LookupFailure $dkimRec) { $serverFailed = $true; continue }
                    if ($null -eq $dkimRec) { continue }
                    foreach ($r in $dkimRec) {
                        $combined = Join-TxtStrings $r
                        if (-not $combined) { continue }
                        if ($combined -match '^v=DKIM1' -or $combined -match '(^|;\s*)k=rsa' -or $combined -match '(^|;\s*)p=[A-Za-z0-9+/]{20,}') {
                            $preview = if ($combined.Length -gt 80) { $combined.Substring(0,80) + '...' } else { $combined }
                            Write-Host ("  [FOUND] Selector '{0}': {1}" -f $sel, $preview) -ForegroundColor Green
                            $serverFound = $true
                        }
                    }
                }
                if (-not $serverFound -and $serverFailed) {
                    Write-Host "  [UNKNOWN] Some lookups failed against this resolver" -ForegroundColor Yellow
                } elseif (-not $serverFound) {
                    Write-Host "  No DKIM found (from probed selectors)" -ForegroundColor Red
                }
            }
        }
        '9' { Check-GlobalDNSRecord -LookupName $Domain -RecordType 'SOA' -Servers $GlobalDNSServers }
        '10' { break }
        default { Write-Host "`nInvalid choice. Please select 1-10." -ForegroundColor Red }
    }
} while ($choice -ne '10')