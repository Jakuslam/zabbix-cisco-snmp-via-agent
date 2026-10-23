####################################################
#   SNMP v2c helper for Zabbix Agent 2 (Windows)   #
#   Template: "Cisco IOS via agent SNMP"           #
#                                                  #
#   Pure PowerShell - uses only .NET UdpClient,    #
#   nothing has to be installed.                   #
#   Works with Windows PowerShell 5.1 and 7.x      #
#                                                  #
#              Jakub Slama                         #
####################################################
#
# MODES
#   walk  <ip> <community> "<oid>,<oid>,..."
#         Walks every OID subtree (SNMP v2c GETBULK) and prints the result in the
#         same text format as Zabbix's own SNMP walk[] items:
#             .1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
#             .1.3.6.1.2.1.31.1.1.1.1.1 = STRING: "Gi1/0/1"
#         so the SNMP walk preprocessing steps (SNMP walk to JSON / SNMP walk value)
#         work unchanged.
#
#   get   <ip> <community> "<oid>,<oid>,..."
#         Reads exact OIDs (SNMP GET), same output format.
#
#   check <ip> <community>
#         Prints 1 if the device answers SNMP (sysUpTime.0), otherwise 0.
#
#   ping  <ip>
#         Sends 3 ICMP echo requests, prints JSON: {"up":1,"loss":0,"rtt":0.0012}
#         (rtt = average response time in seconds).
#
#   <ip> may also be written as <ip>:<port> for a non-standard SNMP port.
#
# ERRORS
#   Zabbix Agent 2 returns stdout + stderr as the item value and ignores the exit code,
#   so on failure the script prints ONE line starting with "SNMP ERROR:".
#   That line is not valid walk output, so the dependent items in Zabbix fail with an
#   error (instead of getting fake values) and the "SNMP polling status" item shows it.
#
# MANUAL TEST (PowerShell on the agent host)
#   .\zbx_snmp.ps1 check 192.168.189.166 public
#   .\zbx_snmp.ps1 get   192.168.189.166 public 1.3.6.1.2.1.1.5.0
#   .\zbx_snmp.ps1 walk  192.168.189.166 public 1.3.6.1.2.1.31.1.1.1.1
#   .\zbx_snmp.ps1 ping  192.168.189.166

param(
    [Parameter(Position = 0)] [string]$Mode,
    [Parameter(Position = 1)] [string]$Target,
    [Parameter(Position = 2)] [string]$Community = "public",
    [Parameter(Position = 3)] [string]$Oids = ""
)

# ---------------- SETTINGS ----------------
$Port           = 161
$TimeoutMs      = 2000   # wait for one SNMP response
$Retries        = 1      # resend a request this many times on timeout
$MaxRepetitions = 20     # rows per GETBULK request (halved automatically if the switch answers tooBig)
$TotalBudgetSec = 25     # stop walking after this time (keep below the Zabbix item timeout, 30s)
$PingCount      = 3
$PingTimeoutMs  = 1000
# ------------------------------------------

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

# ======================= OUTPUT =======================

# Write raw UTF-8 bytes to stdout (no BOM, independent of console code page)
function Write-Result([string]$Text) {
    $bytes  = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($bytes, 0, $bytes.Length)
    $stdout.Flush()
}

# ======================= BER ENCODING =======================

function ConvertTo-BerLength([int]$Length) {
    if ($Length -lt 128) { return ,([byte[]]@($Length)) }
    $tmp = New-Object System.Collections.Generic.List[byte]
    $l = $Length
    while ($l -gt 0) { $tmp.Insert(0, [byte]($l -band 0xFF)); $l = $l -shr 8 }
    $tmp.Insert(0, [byte](0x80 -bor $tmp.Count))
    return ,($tmp.ToArray())
}

function ConvertTo-BerTlv([byte]$Tag, [byte[]]$Content) {
    if ($null -eq $Content) { $Content = [byte[]]@() }
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add($Tag)
    $out.AddRange([byte[]](ConvertTo-BerLength $Content.Length))
    $out.AddRange($Content)
    return ,($out.ToArray())
}

function ConvertTo-BerInteger([long]$Value) {
    $le = [BitConverter]::GetBytes($Value)          # little endian, 8 bytes
    [Array]::Reverse($le)                           # big endian
    $start = 0
    while ($start -lt 7) {
        $b = $le[$start]; $next = $le[$start + 1]
        if (($b -eq 0x00 -and ($next -band 0x80) -eq 0) -or ($b -eq 0xFF -and ($next -band 0x80) -ne 0)) { $start++ }
        else { break }
    }
    $content = New-Object byte[] (8 - $start)
    [Array]::Copy($le, $start, $content, 0, 8 - $start)
    return ,(ConvertTo-BerTlv 0x02 $content)
}

function ConvertTo-BerOid([string]$Oid) {
    $parts = $Oid.Trim().TrimStart('.').Split('.') | ForEach-Object { [uint64]$_ }
    if ($parts.Count -lt 2) { throw "Invalid OID '$Oid'" }
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add([byte](40 * $parts[0] + $parts[1]))
    for ($i = 2; $i -lt $parts.Count; $i++) {
        [uint64]$v = $parts[$i]
        $chunk = New-Object System.Collections.Generic.List[byte]
        $chunk.Add([byte]($v -band 0x7F))
        $v = $v -shr 7
        while ($v -gt 0) {
            $chunk.Insert(0, [byte](0x80 -bor ($v -band 0x7F)))
            $v = $v -shr 7
        }
        $out.AddRange($chunk)
    }
    return ,(ConvertTo-BerTlv 0x06 $out.ToArray())
}

function Join-Bytes([object[]]$Arrays) {
    $out = New-Object System.Collections.Generic.List[byte]
    foreach ($a in $Arrays) { $out.AddRange([byte[]]$a) }
    return ,($out.ToArray())
}

# PDU types: 0xA0 GET, 0xA5 GETBULK
function New-SnmpRequest([byte]$PduType, [int]$RequestId, [string[]]$OidList, [int]$NonRepeaters, [int]$MaxRep) {
    $varbinds = @()
    foreach ($o in $OidList) {
        $varbinds += ,(ConvertTo-BerTlv 0x30 (Join-Bytes @((ConvertTo-BerOid $o), [byte[]]@(0x05, 0x00))))
    }
    $pdu = ConvertTo-BerTlv $PduType (Join-Bytes @(
        (ConvertTo-BerInteger $RequestId),
        (ConvertTo-BerInteger $NonRepeaters),     # GET: error-status 0, GETBULK: non-repeaters
        (ConvertTo-BerInteger $MaxRep),           # GET: error-index 0,  GETBULK: max-repetitions
        (ConvertTo-BerTlv 0x30 (Join-Bytes $varbinds))
    ))
    $commBytes = [System.Text.Encoding]::ASCII.GetBytes($Community)
    return ,(ConvertTo-BerTlv 0x30 (Join-Bytes @(
        (ConvertTo-BerInteger 1),                 # version: 1 = SNMP v2c
        (ConvertTo-BerTlv 0x04 $commBytes),
        $pdu
    )))
}

# ======================= BER DECODING =======================

# Reads tag + length at $Pos, returns @{Tag; Start; Length; End}
function Read-BerHeader([byte[]]$Buf, [int]$Pos) {
    $tag = $Buf[$Pos]; $Pos++
    $len = [int]$Buf[$Pos]; $Pos++
    if ($len -band 0x80) {
        $n = $len -band 0x7F; $len = 0
        for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $Buf[$Pos]; $Pos++ }
    }
    if ($Pos + $len -gt $Buf.Length) { throw "Malformed SNMP response (length out of range)" }
    return @{ Tag = $tag; Start = $Pos; Length = $len; End = $Pos + $len }
}

function Read-BerUnsigned([byte[]]$Buf, [int]$Start, [int]$Length) {
    $v = [bigint]0
    for ($i = 0; $i -lt $Length; $i++) { $v = $v * 256 + $Buf[$Start + $i] }
    return $v
}

function Read-BerSigned([byte[]]$Buf, [int]$Start, [int]$Length) {
    $v = Read-BerUnsigned $Buf $Start $Length
    if ($Length -gt 0 -and ($Buf[$Start] -band 0x80)) { $v = $v - [bigint]::Pow(2, 8 * $Length) }
    return $v
}

function Read-BerOid([byte[]]$Buf, [int]$Start, [int]$Length) {
    if ($Length -eq 0) { return "" }
    $sb = New-Object System.Text.StringBuilder
    $first = [int]$Buf[$Start]
    if ($first -lt 40)      { [void]$sb.Append(".0.$first") }
    elseif ($first -lt 80)  { [void]$sb.Append(".1.$($first - 40)") }
    else                    { [void]$sb.Append(".2.$($first - 80)") }
    [uint64]$v = 0
    for ($i = 1; $i -lt $Length; $i++) {
        $b = $Buf[$Start + $i]
        $v = ($v -shl 7) -bor [uint64]($b -band 0x7F)
        if (($b -band 0x80) -eq 0) { [void]$sb.Append(".$v"); $v = 0 }
    }
    return $sb.ToString()
}

# Formats an OCTET STRING the way Zabbix expects it:
# printable text -> STRING: "..."   (with \ and " escaped), binary -> Hex-STRING: AA BB CC
function Format-OctetString([byte[]]$Buf, [int]$Start, [int]$Length) {
    if ($Length -eq 0) { return 'STRING: ""' }
    $bytes = New-Object byte[] $Length
    [Array]::Copy($Buf, $Start, $bytes, 0, $Length)

    # ignore trailing NUL bytes (some devices pad strings with them)
    $textLen = $Length
    while ($textLen -gt 0 -and $bytes[$textLen - 1] -eq 0) { $textLen-- }

    $isText = $textLen -gt 0
    $text = $null
    if ($isText) {
        try {
            $strict = New-Object System.Text.UTF8Encoding($false, $true)   # throws on invalid UTF-8
            $text = $strict.GetString($bytes, 0, $textLen)
            # control characters (except tab, CR, LF) mean binary data
            if ($text -match '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]') { $isText = $false }
        } catch { $isText = $false }
    }

    if ($isText) {
        return 'STRING: "' + $text.Replace('\', '\\').Replace('"', '\"') + '"'
    }
    return 'Hex-STRING: ' + (($bytes | ForEach-Object { $_.ToString("X2") }) -join ' ')
}

# Returns the text after " = " for one value, or $null for "no such object / end of MIB"
function Format-SnmpValue([byte[]]$Buf, $H) {
    $s = $H.Start; $l = $H.Length
    switch ([int]$H.Tag) {
        0x02 { return "INTEGER: " + (Read-BerSigned $Buf $s $l).ToString() }
        0x04 { return Format-OctetString $Buf $s $l }
        0x05 { return "NULL" }
        0x06 { return "OID: " + (Read-BerOid $Buf $s $l) }
        0x40 { return "IpAddress: " + (($Buf[$s..($s + $l - 1)] | ForEach-Object { [int]$_ }) -join '.') }
        0x41 { return "Counter32: " + (Read-BerUnsigned $Buf $s $l).ToString() }
        0x42 { return "Gauge32: "   + (Read-BerUnsigned $Buf $s $l).ToString() }
        0x43 { return "Timeticks: " + (Read-BerUnsigned $Buf $s $l).ToString() }
        0x44 {
            if ($l -eq 0) { return "Opaque: Hex-STRING: " }
            return "Opaque: Hex-STRING: " + (($Buf[$s..($s + $l - 1)] | ForEach-Object { $_.ToString("X2") }) -join ' ')
        }
        0x46 { return "Counter64: " + (Read-BerUnsigned $Buf $s $l).ToString() }
        0x47 { return "UInteger32: " + (Read-BerUnsigned $Buf $s $l).ToString() }
        default { return $null }   # 0x80 noSuchObject, 0x81 noSuchInstance, 0x82 endOfMibView
    }
}

# Parses a response, returns @{RequestId; ErrorStatus; ErrorIndex; Varbinds = list of @{Oid; Tag; Text}}
function Read-SnmpResponse([byte[]]$Buf) {
    $msg = Read-BerHeader $Buf 0
    if ($msg.Tag -ne 0x30) { throw "Malformed SNMP response" }
    $h = Read-BerHeader $Buf $msg.Start          # version
    $h = Read-BerHeader $Buf $h.End              # community
    $pdu = Read-BerHeader $Buf $h.End            # PDU
    if ($pdu.Tag -ne 0xA2) { throw ("Unexpected PDU type 0x{0:X2}" -f $pdu.Tag) }

    $h = Read-BerHeader $Buf $pdu.Start;  $reqId  = [int](Read-BerSigned $Buf $h.Start $h.Length)
    $h = Read-BerHeader $Buf $h.End;      $errSt  = [int](Read-BerSigned $Buf $h.Start $h.Length)
    $h = Read-BerHeader $Buf $h.End;      $errIdx = [int](Read-BerSigned $Buf $h.Start $h.Length)
    $vbl = Read-BerHeader $Buf $h.End

    $varbinds = New-Object System.Collections.Generic.List[object]
    $pos = $vbl.Start
    while ($pos -lt $vbl.End) {
        $vb  = Read-BerHeader $Buf $pos
        $oh  = Read-BerHeader $Buf $vb.Start
        $vh  = Read-BerHeader $Buf $oh.End
        $varbinds.Add(@{
            Oid  = Read-BerOid $Buf $oh.Start $oh.Length
            Tag  = [int]$vh.Tag
            Text = Format-SnmpValue $Buf $vh
        })
        $pos = $vb.End
    }
    return @{ RequestId = $reqId; ErrorStatus = $errSt; ErrorIndex = $errIdx; Varbinds = $varbinds }
}

# ======================= TRANSPORT =======================

$script:Udp       = $null
$script:RequestId = Get-Random -Minimum 1000 -Maximum 2000000000
$script:Deadline  = (Get-Date).AddSeconds($TotalBudgetSec)

function Open-Snmp {
    # Target may be "ip" or "ip:port" (default port 161)
    $hostPart = $Target; $portNum = $Port
    if ($Target -match '^([^:]+):(\d+)$') { $hostPart = $Matches[1]; $portNum = [int]$Matches[2] }

    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($hostPart, [ref]$ip)) {
        $ip = ([System.Net.Dns]::GetHostAddresses($hostPart) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1)
        if ($null -eq $ip) { throw "Cannot resolve '$hostPart'" }
    }
    $script:Udp = New-Object System.Net.Sockets.UdpClient($ip.AddressFamily)
    $script:Udp.Client.ReceiveTimeout = $TimeoutMs
    $script:Udp.Connect($ip, $portNum)
}

function Close-Snmp {
    if ($null -ne $script:Udp) { $script:Udp.Close(); $script:Udp = $null }
}

# Sends a request and waits for the matching response (with retries)
function Invoke-SnmpRequest([byte]$PduType, [string[]]$OidList, [int]$NonRepeaters, [int]$MaxRep) {
    for ($attempt = 0; $attempt -le $Retries; $attempt++) {
        if ((Get-Date) -gt $script:Deadline) { throw "Time budget of $TotalBudgetSec s exceeded" }
        $script:RequestId++
        $req = New-SnmpRequest $PduType $script:RequestId $OidList $NonRepeaters $MaxRep
        [void]$script:Udp.Send($req, $req.Length)

        $waitUntil = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $waitUntil) {
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            try {
                $data = $script:Udp.Receive([ref]$remote)
            } catch [System.Net.Sockets.SocketException] {
                break   # timeout -> retry
            } catch {
                if ($_.Exception.InnerException -is [System.Net.Sockets.SocketException]) { break }
                throw
            }
            $resp = Read-SnmpResponse $data
            if ($resp.RequestId -eq $script:RequestId) { return $resp }
            # response to an older (retried) request -> ignore and keep waiting
        }
    }
    throw "Timeout while retrieving data from $Target (no SNMP response - check IP, community and ACL)"
}

$SnmpErrors = @{ 1 = "tooBig"; 2 = "noSuchName"; 3 = "badValue"; 4 = "readOnly"; 5 = "genErr"; 6 = "noAccess"
                 13 = "resourceUnavailable"; 16 = "authorizationError" }

# ======================= OPERATIONS =======================

function Get-OidList([string]$Text) {
    $list = @($Text.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" } | ForEach-Object { $_.TrimStart('.') })
    if ($list.Count -eq 0) { throw "No OID given" }
    foreach ($o in $list) { if ($o -notmatch '^\d+(\.\d+)+$') { throw "Invalid OID '$o' (use numeric OIDs like 1.3.6.1.2.1.1.5.0)" } }
    return $list
}

# Compares two numeric OIDs, returns -1 / 0 / 1
function Compare-Oid([string]$A, [string]$B) {
    $pa = $A.TrimStart('.').Split('.'); $pb = $B.TrimStart('.').Split('.')
    $n = [Math]::Min($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $x = [uint64]$pa[$i]; $y = [uint64]$pb[$i]
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    return [Math]::Sign($pa.Count - $pb.Count)
}

function Invoke-SnmpWalk([string[]]$Roots, [System.Text.StringBuilder]$Out) {
    $maxRep = $MaxRepetitions
    foreach ($root in $Roots) {
        $prefix = "." + $root + "."
        $current = $root
        while ($true) {
            $resp = Invoke-SnmpRequest 0xA5 @($current) 0 $maxRep
            if ($resp.ErrorStatus -eq 1 -and $maxRep -gt 1) {      # tooBig -> ask for fewer rows
                $maxRep = [Math]::Max(1, [int]($maxRep / 2))
                continue
            }
            if ($resp.ErrorStatus -ne 0) {
                $name = $SnmpErrors[$resp.ErrorStatus]; if (-not $name) { $name = "error $($resp.ErrorStatus)" }
                throw "SNMP error '$name' while walking $root"
            }
            if ($resp.Varbinds.Count -eq 0) { break }

            $done = $false
            foreach ($vb in $resp.Varbinds) {
                if ($vb.Tag -eq 0x82 -or -not $vb.Oid.StartsWith($prefix)) { $done = $true; break }
                if ((Compare-Oid $vb.Oid $current) -le 0) { $done = $true; break }   # agent loop protection
                if ($null -ne $vb.Text) { [void]$Out.Append($vb.Oid).Append(" = ").Append($vb.Text).Append("`n") }
                $current = $vb.Oid.TrimStart('.')
            }
            if ($done) { break }
        }
    }
}

function Invoke-SnmpGetList([string[]]$OidList, [System.Text.StringBuilder]$Out) {
    # request in small batches to stay under the switch's maximum message size
    for ($i = 0; $i -lt $OidList.Count; $i += 10) {
        $batch = @($OidList[$i..([Math]::Min($i + 9, $OidList.Count - 1))])
        $resp = Invoke-SnmpRequest 0xA0 $batch 0 0
        if ($resp.ErrorStatus -ne 0) {
            $name = $SnmpErrors[$resp.ErrorStatus]; if (-not $name) { $name = "error $($resp.ErrorStatus)" }
            throw "SNMP error '$name' in GET"
        }
        foreach ($vb in $resp.Varbinds) {
            if ($null -ne $vb.Text) { [void]$Out.Append($vb.Oid).Append(" = ").Append($vb.Text).Append("`n") }
        }
    }
}

# ======================= PING =======================

function Invoke-Ping {
    $pinger = New-Object System.Net.NetworkInformation.Ping
    $ok = 0; $sum = 0.0
    for ($i = 0; $i -lt $PingCount; $i++) {
        try {
            $r = $pinger.Send($Target, $PingTimeoutMs)
            if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $ok++; $sum += $r.RoundtripTime }
        } catch { }
    }
    $loss = [Math]::Round(100.0 * ($PingCount - $ok) / $PingCount, 2)
    $rtt  = 0.0
    if ($ok -gt 0) { $rtt = [Math]::Round(($sum / $ok) / 1000.0, 4) }   # ms -> s
    $up   = [int]($ok -gt 0)
    $inv  = [System.Globalization.CultureInfo]::InvariantCulture
    return '{"up":' + $up + ',"loss":' + $loss.ToString($inv) + ',"rtt":' + $rtt.ToString($inv) + '}'
}

# ======================= MAIN =======================

try {
    if (-not $Target) { throw "Usage: zbx_snmp.ps1 <walk|get|check|ping> <ip> [community] [oid,oid,...]" }

    switch ($Mode) {
        "walk" {
            $roots = Get-OidList $Oids
            $sb = New-Object System.Text.StringBuilder
            Open-Snmp
            try { Invoke-SnmpWalk $roots $sb } finally { Close-Snmp }
            if ($sb.Length -eq 0) { throw "Device answered, but none of the requested OIDs exist on it" }
            Write-Result $sb.ToString().TrimEnd("`n")
        }
        "get" {
            $list = Get-OidList $Oids
            $sb = New-Object System.Text.StringBuilder
            Open-Snmp
            try { Invoke-SnmpGetList $list $sb } finally { Close-Snmp }
            if ($sb.Length -eq 0) { throw "No such object on this device" }
            Write-Result $sb.ToString().TrimEnd("`n")
        }
        "check" {
            $result = "0"
            try {
                $sb = New-Object System.Text.StringBuilder
                Open-Snmp
                try { Invoke-SnmpGetList @("1.3.6.1.2.1.1.3.0") $sb } finally { Close-Snmp }
                if ($sb.ToString() -match 'Timeticks: \d+') { $result = "1" }
            } catch { $result = "0" }
            Write-Result $result
        }
        "ping" {
            Write-Result (Invoke-Ping)
        }
        default { throw "Unknown mode '$Mode' - use walk, get, check or ping" }
    }
}
catch {
    $msg = $_.Exception.Message -replace '[\r\n]+', ' '
    Write-Result "SNMP ERROR: $msg"
}
exit 0
