/*
    RDPShield v3.0  --  credential_files.yar
    Detection signatures for credential material staged on the host:
    wordlists, NTLM/SAM hash dumps, and saved RDP credential files.

    Finding these on a server usually means an attacker staged inputs for
    cracking, or dumped local credentials post-foothold.  Detection-only.
*/

rule Wordlist_Common_Passwords : credentials wordlist
{
    meta:
        author      = "RDPShield"
        severity    = "MEDIUM"
        category    = "wordlist"
        description = "Password wordlist (rockyou-style) staged on disk"
    strings:
        // A cluster of extremely common passwords strongly implies a wordlist,
        // not normal server data.  Each on its own line.
        $p1  = /\n123456\r?\n/
        $p2  = /\npassword\r?\n/ nocase
        $p3  = /\n12345678\r?\n/
        $p4  = /\nqwerty\r?\n/ nocase
        $p5  = /\nabc123\r?\n/ nocase
        $p6  = /\niloveyou\r?\n/ nocase
        $p7  = /\nadmin\r?\n/ nocase
        $p8  = /\nletmein\r?\n/ nocase
        $p9  = /\nmonkey\r?\n/ nocase
        $p10 = /\ndragon\r?\n/ nocase
        $marker = "rockyou" ascii nocase
    condition:
        $marker or 5 of ($p*)
}

rule Credential_NTLM_Hash_Dump : credentials hashes
{
    meta:
        author      = "RDPShield"
        severity    = "HIGH"
        category    = "hash_dump"
        description = "pwdump / secretsdump style NTLM hash dump (user:RID:LM:NT:::)"
        reference   = "Impacket secretsdump.py output format"
    strings:
        // username:RID:LMHASH:NTHASH:::    (LM/NT are 32 hex chars)
        $pwdump = /[^\s:]{1,40}:[0-9]{3,}:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::/
        $aad3b  = "aad3b435b51404eeaad3b435b51404ee" ascii nocase  // empty LM hash
        $hdr    = "secretsdump" ascii nocase
    condition:
        #pwdump > 2 or $hdr or (#aad3b > 1)
}

rule Credential_Kerberos_Ticket : credentials kerberos
{
    meta:
        author      = "RDPShield"
        severity    = "HIGH"
        category    = "kerberos"
        description = "Exported Kerberos tickets / kirbi material (pass-the-ticket staging)"
    strings:
        $k1 = ".kirbi" ascii nocase
        $k2 = "krbtgt" ascii nocase
        $k3 = "$krb5tgs$" ascii nocase     // kerberoast hash prefix
        $k4 = "$krb5asrep$" ascii nocase   // AS-REP roast hash prefix
    condition:
        any of ($k3, $k4) or ($k1 and $k2)
}

rule Credential_Saved_RDP_File : credentials rdp
{
    meta:
        author      = "RDPShield"
        severity    = "MEDIUM"
        category    = "rdp_credentials"
        description = "Saved .rdp connection file containing target/username (possible lateral-movement staging)"
    strings:
        $a = "full address:s:" ascii nocase
        $b = "username:s:" ascii nocase
        $c = "password 51:b:" ascii nocase   // DPAPI-encrypted saved RDP password
    condition:
        ($a and $b) or $c
}

rule Credential_Browser_Store_Theft : credentials exfil
{
    meta:
        author      = "RDPShield"
        severity    = "HIGH"
        category    = "credential_theft"
        description = "Known browser/credential-stealing tools staged on host"
    strings:
        // v3.1: the previous version matched browser-store PATHS ("Login Data",
        // "logins.json", "vaultcli.dll"), which a browser legitimately holds in
        // its OWN memory -> false positives on every msedge process. Now anchored
        // on the names of actual credential-harvesting TOOLS instead.
        $tool1 = "LaZagne" ascii wide nocase fullword
        $tool2 = "SharpChrome" ascii wide nocase
        $tool3 = "WebBrowserPassView" ascii wide nocase
        $tool4 = "SharpWeb" ascii wide nocase
        $tool5 = "BrowserGhost" ascii wide nocase
        $tool6 = "HackBrowserData" ascii wide nocase
        $tool7 = "mimikatz" ascii wide nocase     // dpapi::/ sekurlsa:: also steal browser creds
    condition:
        any of ($tool*)
}
