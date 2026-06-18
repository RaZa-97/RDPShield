/*
    RDPShield v3.0  --  bruteforce_tools.yar
    Detection signatures for common RDP / credential brute-force tooling.

    These rules flag the PRESENCE of attacker tooling on the protected host
    (e.g. a tool that was uploaded after a foothold, or staged on disk).
    They are detection-only signatures -- no offensive capability.

    Severity convention read by yara_scanner.py:  CRITICAL | HIGH | MEDIUM | LOW
    Brute-force tooling on a server is HIGH (strong indicator, not yet proof of breach).
*/

rule Tool_THC_Hydra : bruteforce tool
{
    meta:
        author      = "RDPShield"
        severity    = "HIGH"
        category    = "bruteforce_tool"
        description = "THC-Hydra parallel login brute-forcer"
        reference   = "https://github.com/vanhauser-thc/thc-hydra"
    strings:
        $banner1 = "Hydra v" ascii nocase
        $banner2 = "THC-Hydra" ascii nocase
        $banner3 = "by van Hauser" ascii nocase
        $usage1  = "hydra [[[-l LOGIN" ascii
        $mod1    = "hydra_rdp" ascii nocase
        $mod2    = "was reduced to" ascii          // hydra task-reduction message
    condition:
        $banner2 or
        ($banner1 and ($banner3 or $usage1)) or
        2 of ($mod*)
}

rule Tool_Medusa : bruteforce tool
{
    meta:
        author      = "RDPShield"
        severity    = "HIGH"
        category    = "bruteforce_tool"
        description = "Medusa parallel network login brute-forcer (Foofus)"
        reference   = "https://github.com/jmk-foofus/medusa"
    strings:
        $b1 = "Medusa v" ascii nocase
        $b2 = "JoMo-Kit" ascii
        $b3 = "foofus.net" ascii nocase
        $m1 = "ACCOUNT CHECK:" ascii          // medusa progress line
        $m2 = "ACCOUNT FOUND:" ascii
        $mod = "medusa.dylib" ascii nocase
    condition:
        $b1 or $b2 or
        (any of ($b3, $mod) and any of ($m*)) or
        2 of ($m*)
}

rule Tool_Crowbar : bruteforce tool
{
    meta:
        author      = "RDPShield"
        severity    = "HIGH"
        category    = "bruteforce_tool"
        description = "Crowbar brute-forcing tool (RDP/SSH/OpenVPN via xfreerdp/hydra wrappers)"
        reference   = "https://github.com/galkan/crowbar"
    strings:
        $s1 = "crowbar" ascii nocase
        $s2 = "RDP_brute" ascii nocase
        $s3 = "xfreerdp" ascii nocase
        $s4 = "crowbar.log" ascii nocase
        $s5 = "Brute forcing" ascii nocase
        $arg = "-b rdp" ascii nocase
    condition:
        ($s1 and 1 of ($s2, $s4, $arg)) or
        ($s3 and $s5 and $s1)
}

rule Tool_NLBrute : bruteforce tool
{
    meta:
        author      = "RDPShield"
        severity    = "HIGH"
        category    = "bruteforce_tool"
        description = "NLBrute / NLB RDP brute-forcer (commonly traded on underground forums)"
    strings:
        // v3.1: dropped short generic tokens ("NLB ", "combo", "Threads") that
        // false-matched browser/process memory. Anchor on the distinctive product
        // name, or on all three result-file names co-occurring (a benign process
        // is very unlikely to hold good.txt + bad.txt + rdp.txt together).
        $n1 = "NLBrute" ascii wide nocase fullword
        $banner = /NLBrute\s+[0-9]\.[0-9]/ ascii wide nocase
        $r1 = "good.txt" ascii wide nocase
        $r2 = "bad.txt" ascii wide nocase
        $r3 = "rdp.txt" ascii wide nocase
    condition:
        $n1 or $banner or
        all of ($r1, $r2, $r3)
}

rule Generic_RDP_Brute_Artifacts : bruteforce
{
    meta:
        author      = "RDPShield"
        severity    = "MEDIUM"
        category    = "bruteforce_artifact"
        description = "Generic indicators of an RDP brute-force result set staged on disk"
    strings:
        $h1 = "Host;Login;Password" ascii nocase
        $h2 = "ip:user:pass" ascii nocase
        $h3 = "Connecting to RDP" ascii nocase
        $combo = /[0-9]{1,3}(\.[0-9]{1,3}){3}:[A-Za-z0-9_.-]{1,32}:[^\r\n]{1,64}/
    condition:
        any of ($h*) and #combo > 5
}
