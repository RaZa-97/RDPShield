/*
    RDPShield v3.0  --  post_compromise.yar   (v3.1 hardened)
    Detection signatures for post-breach artifacts: reverse shells, web shells,
    encoded/obfuscated PowerShell, and generic backdoors.

    A match here after a successful login is strong evidence of an active
    compromise -- this is what drives the CRITICAL post-breach SMS alert.
    All rules are detection-only signatures (pattern matchers), not payloads.

    v3.1: Web_Shell, Encoded_PowerShell and Persistence were re-anchored to
    eliminate false positives during PROCESS-MEMORY scanning. The earlier
    versions matched short/substring tokens (e.g. "IEX", "wso") that occur in
    benign process memory. The hardened versions require longer, specific
    multi-token evidence.
*/

rule PostComp_Encoded_PowerShell : backdoor powershell
{
    meta:
        author      = "RDPShield"
        severity    = "CRITICAL"
        category    = "encoded_powershell"
        description = "Encoded / obfuscated PowerShell download-and-execute pattern"
    strings:
        // Long, specific tokens -- safe even in memory.
        $enc_cmd = "-EncodedCommand" ascii wide nocase
        // "-enc" / "-e" immediately followed by a long base64 blob (real payloads
        // are long; this avoids matching the bare word fragment).
        $enc_b64 = /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{50,}/ ascii wide nocase
        $frombase = "FromBase64String" ascii wide nocase
        // Download primitives require the method-call paren -> not a bare word.
        $dl_str  = ".DownloadString(" ascii wide nocase
        $dl_file = ".DownloadFile(" ascii wide nocase
        $iwr     = "Invoke-WebRequest" ascii wide nocase
        $net     = "Net.WebClient" ascii wide nocase
        // Execution sinks: require the invocation paren, or the full cmdlet name.
        $iex     = "IEX(" ascii wide nocase
        $iex_sp  = "IEX (" ascii wide nocase
        $iex2    = "Invoke-Expression" ascii wide nocase
        // Flags are long and distinctive.
        $bypass  = "-ExecutionPolicy Bypass" ascii wide nocase
        $hidden  = "-WindowStyle Hidden" ascii wide nocase
    condition:
        $enc_cmd or $enc_b64 or
        // a real download primitive paired with an execution sink
        ( any of ($dl_str, $dl_file, $iwr, $net) and
          any of ($iex, $iex_sp, $iex2) ) or
        // base64 decode feeding an execution sink
        ( $frombase and any of ($iex, $iex_sp, $iex2) ) or
        // stealth flags paired with a download/exec primitive (not flags alone)
        ( any of ($bypass, $hidden) and
          any of ($dl_str, $dl_file, $iwr, $iex, $iex_sp, $iex2) )
}

rule PostComp_Reverse_Shell : backdoor reverse_shell
{
    meta:
        author      = "RDPShield"
        severity    = "CRITICAL"
        category    = "reverse_shell"
        description = "Reverse / bind shell indicators (PowerShell, netcat, bash, python)"
    strings:
        // PowerShell TCP reverse shell skeleton
        $ps1 = "New-Object System.Net.Sockets.TCPClient" ascii wide nocase
        $ps2 = "GetStream()" ascii wide nocase
        $ps3 = "$sendback" ascii wide nocase
        // *nix style (seen in cross-platform droppers / WSL)
        $bash = "/dev/tcp/" ascii
        $py1  = "socket.socket(socket.AF_INET" ascii
        $py2  = "subprocess.call([\"/bin/sh\"" ascii
        // netcat
        $nc1  = "nc -e" ascii nocase
        $nc2  = "ncat -e" ascii nocase
    condition:
        ($ps1 and ($ps2 or $ps3)) or
        $bash or
        ($py1 and $py2) or
        any of ($nc1, $nc2)
}

rule PostComp_Web_Shell : backdoor webshell
{
    meta:
        author      = "RDPShield"
        severity    = "CRITICAL"
        category    = "webshell"
        description = "Web shell (PHP/ASPX/JSP) command-execution patterns"
    strings:
        // PHP: eval/exec bound to a user-input superglobal (real webshell shape).
        $php1 = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $php2 = /(system|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $php3 = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $php4 = /preg_replace\s*\(\s*["'].*\/e["']/ nocase
        // ASP / ASPX: eval/exec bound to Request, or shell objects.
        $asp1 = /eval\s*\(\s*Request\s*(\.|\()/ nocase
        $asp2 = "Server.CreateObject(\"WScript.Shell\")" ascii nocase
        $asp3 = /Process\.Start\(\s*"cmd(\.exe)?"/ nocase
        // JSP
        $jsp1 = "Runtime.getRuntime().exec(request.getParameter" ascii nocase
        // Known shell signatures -- LONG distinctive forms only (no 3-char frags).
        $name1 = "c99shell" ascii nocase
        $name2 = "r57shell" ascii nocase
        $name3 = "b374k" ascii nocase
        $name4 = "China Chopper" ascii nocase
        $name5 = "WSO 2." ascii nocase
        $name6 = "phpspy" ascii nocase
    condition:
        any of ($php*) or any of ($asp*) or $jsp1 or any of ($name*)
}

rule PostComp_Offensive_Framework : backdoor c2
{
    meta:
        author      = "RDPShield"
        severity    = "CRITICAL"
        category    = "c2_framework"
        description = "Indicators of common offensive/C2 frameworks staged on host"
    strings:
        $m1 = "meterpreter" ascii wide nocase
        $m2 = "metsrv" ascii wide nocase
        $cs1 = "beacon.dll" ascii nocase
        $cs2 = "ReflectiveLoader" ascii nocase
        $cs3 = "%s as %s\\%s: %d" ascii         // Cobalt Strike default fmt string
        $mimi1 = "sekurlsa::logonpasswords" ascii wide nocase
        $mimi2 = "mimikatz" ascii wide nocase
        $psexec = "PSEXESVC" ascii wide nocase
    condition:
        any of ($m*) or any of ($cs*) or any of ($mimi*) or $psexec
}

rule PostComp_Persistence : backdoor persistence
{
    meta:
        author      = "RDPShield"
        severity    = "HIGH"
        category    = "persistence"
        description = "Common persistence mechanisms dropped post-compromise"
    strings:
        // Sticky-keys / accessibility IFEO backdoor: the registry path with the
        // accessibility binary CONCATENATED (the actual attack artifact), not the
        // two strings floating separately (which winlogon legitimately holds).
        $ifeo_acc = /Image File Execution Options\\(sethc|utilman|osk|narrator|magnify|displayswitch)\.exe/ ascii wide nocase
        $dbg      = "Debugger" ascii wide nocase
        // Active persistence command lines (specific verbs).
        $task   = "schtasks /create" ascii wide nocase
        $svc    = "sc create" ascii wide nocase
        $regadd = "reg add" ascii wide nocase
        $runkey = "CurrentVersion\\Run" ascii wide nocase
    condition:
        ($ifeo_acc and $dbg) or
        ($regadd and $runkey) or
        ($svc and $runkey) or
        $task
}
