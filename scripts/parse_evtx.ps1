<#
.SYNOPSIS
  Windows EVTX forensic parser for Security / System / Sysmon logs.

.DESCRIPTION
  Modes:
    summary    Event volume, time range, host, EventID histogram
    logons     Structured 4624/4625 table (LogonType, user, source IP, port, process)
    netlogons  Only logons carrying a real remote IP, grouped by IP/type/user
    accounts   Account lifecycle events with full message (4720/4722/4732/4738/...)
    tasks      4698/4697/4702/7045 scheduled tasks and service installs, full message
    dump       Full message of any EventIDs given via -Ids
    all        summary + logons.csv + accounts.txt + tasks.txt + netlogons.csv into -Out

  Performance note:
  Events are enumerated with System.Diagnostics.Eventing.Reader.EventLogReader and
  converted with ToXml(). Message text (FormatDescription) is rendered ONLY for the
  few events that are actually printed, because rendering every message is roughly
  300x slower than parsing the XML and dominates the runtime on large logs.

.PARAMETER Path
  Path to a .evtx file, or a directory (all *.evtx inside are read).

.PARAMETER Mode
  One of: summary | logons | netlogons | accounts | tasks | dump | all

.PARAMETER Ids
  Comma separated EventIDs, used by -Mode dump.

.PARAMETER Out
  Output directory. Defaults to <log dir>\analysis_out

.PARAMETER MaxEvents
  Optional per-file cap, for very large logs during quick triage.

.EXAMPLE
  .\parse_evtx.ps1 -Path C:\case\Security.evtx -Mode summary

.EXAMPLE
  .\parse_evtx.ps1 -Path C:\case\Security.evtx -Mode all -Out C:\case\out
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [ValidateSet('summary','logons','netlogons','accounts','tasks','dump','all')]
    [string]$Mode = 'summary',
    [string[]]$Ids = @(),
    [string]$Out = '',
    [int]$MaxEvents = 0
)

$ErrorActionPreference = 'Stop'

# ---------- helpers ----------

function Get-EvtxFiles {
    param([string]$P)
    if (Test-Path -LiteralPath $P -PathType Container) {
        return @(Get-ChildItem -LiteralPath $P -Filter *.evtx -File | Select-Object -ExpandProperty FullName)
    }
    return @($P)
}

function Read-Evtx {
    param([string[]]$Files, [int]$Cap)
    $list = New-Object System.Collections.ArrayList
    foreach ($f in $Files) {
        try {
            $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
                    $f, [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
            $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
        } catch {
            Write-Warning ("Cannot open {0}: {1}" -f $f, $_.Exception.Message)
            continue
        }
        $n = 0
        while ($null -ne ($rec = $reader.ReadEvent())) {
            $n++
            if ($Cap -gt 0 -and $n -gt $Cap) { $rec.Dispose(); break }
            $time = $null
            try { $time = $rec.TimeCreated } catch { }
            if ($null -eq $time) { $time = [datetime]::MinValue }
            [void]$list.Add([PSCustomObject]@{
                Id           = $rec.Id
                RecordId     = $rec.RecordId
                TimeCreated  = $time
                MachineName  = $rec.MachineName
                LogName      = $rec.LogName
                ProviderName = $rec.ProviderName
                Record       = $rec
            })
        }
        $reader.Dispose()
    }
    return ,$list
}

# Message rendering is expensive: call it only on events that will be printed.
function Get-Msg {
    param($Event)
    try {
        if ($Event.Record) { return [string]$Event.Record.FormatDescription() }
    } catch { }
    return ''
}

function Get-Xml {
    param($Event)
    try { return [xml]$Event.Record.ToXml() } catch { return $null }
}

function Get-Data {
    param($Event)
    $h = @{}
    $x = Get-Xml $Event
    if ($null -eq $x) { return $h }
    foreach ($n in $x.Event.EventData.Data) { $h[[string]$n.Name] = [string]$n.'#text' }
    $h['_Channel']  = [string]$x.Event.System.Channel
    $h['_Computer'] = [string]$x.Event.System.Computer
    $h['_Provider'] = [string]$x.Event.System.Provider.Name
    $h['_EventId']  = [string]$x.Event.System.EventID
    $h['_RecordId'] = [string]$x.Event.System.EventRecordID
    $h['_Time']     = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    return $h
}

function New-CsvRow {
    param($Event, $Data, [string[]]$Fields)
    $o = [ordered]@{
        Time     = $Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        EventId  = $Event.Id
        RecordId = $Event.RecordId
    }
    foreach ($f in $Fields) { $o[$f] = $Data[$f] }
    return [PSCustomObject]$o
}

function Resolve-OutDir {
    param([string]$Requested, [string[]]$Files)
    if ($Requested -ne '') {
        if (-not (Test-Path -LiteralPath $Requested)) { New-Item -ItemType Directory -Path $Requested -Force | Out-Null }
        return (Resolve-Path -LiteralPath $Requested).Path
    }
    $base = Split-Path -Parent (Resolve-Path -LiteralPath $Files[0]).Path
    $d = Join-Path $base 'analysis_out'
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    return $d
}

function Write-Text {
    param([string]$File, [System.Text.StringBuilder]$Sb)
    Set-Content -LiteralPath $File -Value $Sb.ToString() -Encoding UTF8
    Write-Host ("[+] wrote {0}" -f $File)
}

# ---------- modes ----------

function Invoke-Summary {
    param($Events)
    $valid = @($Events | Where-Object { $_.TimeCreated -gt [datetime]::MinValue } | Sort-Object TimeCreated)
    Write-Host ''
    Write-Host '=== SUMMARY ==='
    Write-Host ("Events      : {0}" -f $Events.Count)
    if ($valid.Count -gt 0) {
        Write-Host ("First       : {0}" -f $valid[0].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))
        Write-Host ("Last        : {0}" -f $valid[-1].TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))
    }
    $topHost = ($Events | Group-Object MachineName | Sort-Object Count -Descending | Select-Object -First 1)
    if ($topHost) { Write-Host ("Host        : {0}  ({1} events)" -f $topHost.Name, $topHost.Count) }
    Write-Host ''
    Write-Host '--- EventID histogram (top 40) ---'
    $Events | Group-Object Id | Sort-Object Count -Descending |
        Select-Object -First 40 @{n='Count';e={$_.Count}}, @{n='EventId';e={$_.Name}} |
        Format-Table -AutoSize | Out-String -Width 120 | Write-Host
    Write-Host '--- Channel histogram ---'
    $Events | Group-Object LogName | Sort-Object Count -Descending |
        Select-Object @{n='Count';e={$_.Count}}, Name |
        Format-Table -AutoSize | Out-String -Width 120 | Write-Host
}

function Get-LogonRows {
    param($Events)
    $fields = @('TargetUserName','TargetDomainName','LogonType','IpAddress','IpPort',
                'WorkstationName','ProcessName','AuthenticationPackageName','Status','SubStatus','TargetLogonId')
    foreach ($e in $Events) {
        if ($e.Id -ne 4624 -and $e.Id -ne 4625) { continue }
        $d = Get-Data $e
        New-CsvRow -Event $e -Data $d -Fields $fields
    }
}

function Invoke-Logons {
    param($Events, [string]$OutDir)
    $rows = @(Get-LogonRows $Events)
    Write-Host ''
    Write-Host ("=== LOGONS ({0} rows) ===" -f $rows.Count)
    $rows | Sort-Object Time | Format-Table Time,EventId,LogonType,TargetUserName,IpAddress,IpPort,ProcessName -AutoSize |
        Out-String -Width 200 | Write-Host
    if ($OutDir -ne '') {
        $f = Join-Path $OutDir 'logons.csv'
        $rows | Sort-Object Time | Export-Csv -LiteralPath $f -NoTypeInformation -Encoding UTF8
        Write-Host ("[+] wrote {0}" -f $f)
    }
}

function Invoke-NetLogons {
    param($Events, [string]$OutDir)
    $rows = @(Get-LogonRows $Events | Where-Object {
        $_.IpAddress -and $_.IpAddress -ne '-' -and $_.IpAddress -ne '' -and
        $_.IpAddress -ne '::1' -and $_.IpAddress -ne '127.0.0.1'
    })
    Write-Host ''
    Write-Host ("=== REMOTE LOGONS ({0} rows, excluding loopback) ===" -f $rows.Count)
    $rows | Group-Object IpAddress, EventId, LogonType, TargetUserName | Sort-Object Count -Descending | ForEach-Object {
        $r = $_.Group | Sort-Object Time
        [PSCustomObject]@{
            Count     = $_.Count
            Ip        = $r[0].IpAddress
            EventId   = $r[0].EventId
            LogonType = $r[0].LogonType
            User      = $r[0].TargetUserName
            Domain    = $r[0].TargetDomainName
            First     = $r[0].Time
            Last      = $r[-1].Time
        }
    } | Sort-Object Last -Descending | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    if ($OutDir -ne '') {
        $f = Join-Path $OutDir 'netlogons.csv'
        $rows | Sort-Object Time | Export-Csv -LiteralPath $f -NoTypeInformation -Encoding UTF8
        Write-Host ("[+] wrote {0}" -f $f)
    }
}

function Invoke-Dump {
    param($Events, [int[]]$Want, [string]$OutDir)
    $sb = New-Object System.Text.StringBuilder
    $n = 0
    foreach ($e in ($Events | Sort-Object TimeCreated)) {
        if ($Want -notcontains $e.Id) { continue }
        $n++
        [void]$sb.AppendLine(("========== ID={0}  Time={1}  RecordId={2}  Channel={3} ==========" -f `
            $e.Id, $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $e.RecordId, $e.LogName))
        [void]$sb.AppendLine((Get-Msg $e))
        [void]$sb.AppendLine('')
    }
    Write-Host ''
    Write-Host ("=== DUMP ids [{0}] -> {1} events ===" -f ($Want -join ','), $n)
    Write-Host $sb.ToString()
    if ($OutDir -ne '') {
        Write-Text -File (Join-Path $OutDir ('dump_{0}.txt' -f ($Want -join '-'))) -Sb $sb
    }
}

function Invoke-Accounts {
    param($Events, [string]$OutDir)
    $want = @(4720,4721,4722,4723,4724,4725,4726,4728,4729,4732,4733,4734,4735,4738,4740,4756,4757,4767,4780,4781)
    $sb = New-Object System.Text.StringBuilder
    $n = 0
    foreach ($e in ($Events | Sort-Object TimeCreated)) {
        if ($want -notcontains $e.Id) { continue }
        $n++
        $d = Get-Data $e
        [void]$sb.AppendLine(("========== ID={0}  Time={1}  RecordId={2} ==========" -f `
            $e.Id, $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $e.RecordId))
        [void]$sb.AppendLine((Get-Msg $e))
        [void]$sb.AppendLine(("  [fields] subject={0}\{1} target={2}\{3} member={4} group={5}" -f `
            $d['SubjectDomainName'],$d['SubjectUserName'],$d['TargetDomainName'],$d['TargetUserName'],$d['MemberName'],$d['GroupName']))
        [void]$sb.AppendLine('')
    }
    Write-Host ''
    Write-Host ("=== ACCOUNT EVENTS ({0}) ===" -f $n)
    Write-Host $sb.ToString()
    if ($OutDir -ne '') { Write-Text -File (Join-Path $OutDir 'accounts.txt') -Sb $sb }
}

function Invoke-Tasks {
    param($Events, [string]$OutDir)
    $want = @(4698,4699,4700,4702,4697,7045,7000,7009,106,200,201)
    $sb = New-Object System.Text.StringBuilder
    $n = 0
    foreach ($e in ($Events | Sort-Object TimeCreated)) {
        if ($want -notcontains $e.Id) { continue }
        $n++
        $d = Get-Data $e
        [void]$sb.AppendLine(("========== ID={0}  Time={1}  Channel={2}  RecordId={3} ==========" -f `
            $e.Id, $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $e.LogName, $e.RecordId))
        [void]$sb.AppendLine((Get-Msg $e))
        if ($d['TaskContent']) {
            [void]$sb.AppendLine('  --- parsed TaskContent ---')
            try {
                $t = [xml]$d['TaskContent']
                foreach ($a in $t.Task.Actions.Exec) {
                    [void]$sb.AppendLine(("  Command : {0} {1}" -f $a.Command, $a.Arguments))
                }
                foreach ($tr in $t.Task.Triggers.TimeTrigger) {
                    [void]$sb.AppendLine(("  Trigger : {0}  interval={1}" -f $tr.StartBoundary, $tr.Repetition.Interval))
                }
                [void]$sb.AppendLine(("  Author  : {0}" -f $t.Task.RegistrationInfo.Author))
                [void]$sb.AppendLine(("  RunAs   : {0}" -f $t.Task.Principals.Principal.UserId))
            } catch { [void]$sb.AppendLine('  (task XML parse failed)') }
        }
        [void]$sb.AppendLine('')
    }
    Write-Host ''
    Write-Host ("=== TASK / SERVICE EVENTS ({0}) ===" -f $n)
    Write-Host $sb.ToString()
    if ($OutDir -ne '') { Write-Text -File (Join-Path $OutDir 'tasks.txt') -Sb $sb }
}

# ---------- main ----------

# Accept both "-Ids 4624,4648" (array) and "-Ids '4624,4648'" (single string via -File)
$wanted = New-Object System.Collections.ArrayList
foreach ($s in $Ids) {
    foreach ($p in ([string]$s -split '[,\s]+')) {
        $t = $p.Trim()
        if ($t -eq '') { continue }
        $n = 0
        if ([int]::TryParse($t, [ref]$n)) { [void]$wanted.Add($n) }
        else { Write-Warning ("ignoring invalid EventID: {0}" -f $t) }
    }
}

$files = Get-EvtxFiles -P $Path
if ($files.Count -eq 0) { Write-Error "No .evtx found at $Path"; exit 1 }
Write-Host ("[*] input: {0} file(s)" -f $files.Count)

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$events = Read-Evtx -Files $files -Cap $MaxEvents
$sw.Stop()
Write-Host ("[*] parsed: {0} events in {1:N2}s" -f $events.Count, $sw.Elapsed.TotalSeconds)
if ($events.Count -eq 0) { Write-Warning 'No events parsed. Check that the file is a valid .evtx (unzip first).'; exit 2 }

if ($Mode -eq 'all') {
    $dir = Resolve-OutDir -Requested $Out -Files $files
    Invoke-Summary -Events $events
    Invoke-NetLogons -Events $events -OutDir $dir
    Invoke-Logons -Events $events -OutDir $dir
    Invoke-Accounts -Events $events -OutDir $dir
    Invoke-Tasks -Events $events -OutDir $dir
    Invoke-Dump -Events $events -Want @(4624,4625,4648,4672,4688,1102) -OutDir $dir
    Write-Host ''
    Write-Host ("[*] all artifacts in {0}" -f $dir)
    exit 0
}

switch ($Mode) {
    'summary'   { Invoke-Summary   -Events $events }
    'logons'    { Invoke-Logons    -Events $events -OutDir '' }
    'netlogons' { Invoke-NetLogons -Events $events -OutDir '' }
    'accounts'  { Invoke-Accounts  -Events $events -OutDir '' }
    'tasks'     { Invoke-Tasks     -Events $events -OutDir '' }
    'dump'      { if ($wanted.Count -eq 0) { Write-Error '-Mode dump needs -Ids' }
                  Invoke-Dump -Events $events -Want $wanted.ToArray() -OutDir '' }
}
