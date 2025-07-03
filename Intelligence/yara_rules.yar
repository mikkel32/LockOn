rule SuspiciousPE {
    meta:
        threat = "malware"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Eicar_Test_File {
    meta:
        description = "EICAR standard antivirus test file"
        threat = "test_virus"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule SuspiciousMacro {
    meta:
        threat = "macro"
    strings:
        $autoopen = /AutoOpen/i
        $cmd = /Shell\s*\(/i
    condition:
        $autoopen and $cmd
}

rule EncodedPowerShell {
    meta:
        threat = "malware"
    strings:
        $enc = /powershell(\.exe)?\s*-encodedcommand\s+[A-Za-z0-9+\/=]{20,}/i
    condition:
        $enc
}

rule ObfuscatedMacro {
    meta:
        threat = "macro"
    strings:
        $chr = /Chr\$/i
        $js = /fromCharCode\(/i
    condition:
        $chr or $js
}

rule ReverseShell_Bash {
    meta:
        threat = "reverse_shell"
    strings:
        $bash = /bash\s+-i\s+>&\s*\/dev\/tcp\//
    condition:
        $bash
}

rule Downloader_PowerShell {
    meta:
        threat = "malware_downloader"
    strings:
        $dl = /IEX\(New-Object\s+Net.WebClient\)\.DownloadString/i
    condition:
        $dl
}

rule Regsvr32_Command {
    meta:
        threat = "script_malware"
    strings:
        $r = /regsvr32\s+.*\.(dll|ocx)/i
    condition:
        $r
}

rule Zip_VBA_Project {
    meta:
        threat = "macro"
    strings:
        $vba = "vbaProject.bin"
    condition:
        $vba
}
rule Netcat_ReverseShell {
    meta:
        threat = "reverse_shell"
    strings:
        $nc = /nc(\.exe)?\s+-e\s+/i
    condition:
        $nc
}

rule Mimikatz_Detected {
    meta:
        threat = "credential_theft"
    strings:
        $m = "mimikatz"
    condition:
        $m
}

rule HTA_Scriptlet {
    meta:
        threat = "script_malware"
    strings:
        $hta = /mshta(\.exe)?\s+.*http/i
    condition:
        $hta
}

rule Meterpreter_String {
    meta:
        threat = "malware"
    strings:
        $met = "meterpreter"
    condition:
        $met
}

rule CobaltStrike_Beacon {
    meta:
        threat = "malware"
    strings:
        $cb = "cobaltstrike"
    condition:
        $cb
}

rule Certutil_Download {
    meta:
        threat = "malware_downloader"
    strings:
        $cu = /certutil(\.exe)?\s+-urlcache\s+-f/i
    condition:
        $cu
}

rule Rundll32_Command {
    meta:
        threat = "script_malware"
    strings:
        $rd = /rundll32(\.exe)?\s+.+\.dll/i
    condition:
        $rd
}

rule Suspicious_IP_Connection {
    meta:
        threat = "c2_communication"
    strings:
        $ip = /\b\d{1,3}(\.\d{1,3}){3}:\d{2,5}\b/
    condition:
        $ip
}

rule Invoke_Shellcode {
    meta:
        threat = "malware"
    strings:
        $sc = /Invoke-Shellcode/i
        $rpe = /Invoke-ReflectivePEInjection/i
    condition:
        $sc or $rpe
}

rule PowerView_Module {
    meta:
        threat = "reconnaissance"
    strings:
        $pv = /PowerView/i
    condition:
        $pv
}

rule DotNet_Base64Decode {
    meta:
        threat = "malware"
    strings:
        $b64 = /FromBase64String\(/i
    condition:
        $b64
}

rule Invoke_Obfuscation {
    meta:
        threat = "obfuscation"
    strings:
        $io = /Invoke-Obfuscation/i
    condition:
        $io
}

rule Empire_PS {
    meta:
        threat = "malware"
    strings:
        $emp = /\bEmpire\b/i
    condition:
        $emp
}

rule PsExec_Command {
    meta:
        threat = "lateral_movement"
    strings:
        $psx = /psexec\s+/i
    condition:
        $psx
}

rule MSBuild_Shell {
    meta:
        threat = "malware_loader"
    strings:
        $msb = /msbuild\.exe\s+.*\.csproj/i
    condition:
        $msb
}

rule InstallUtil_Command {
    meta:
        threat = "persistence"
    strings:
        $iu = /installutil(\.exe)?\s+/i
    condition:
        $iu
}

rule Shellcode_Loader {
    meta:
        threat = "malware_loader"
    strings:
        $alloc = "VirtualAllocEx"
        $wpm = "WriteProcessMemory"
    condition:
        $alloc and $wpm
}

rule njRAT_String {
    meta:
        threat = "rat"
    strings:
        $nj = "njrat"
    condition:
        $nj
}

rule DarkComet_String {
    meta:
        threat = "rat"
    strings:
        $dc = "darkcomet"
    condition:
        $dc
}

rule AgentTesla_String {
    meta:
        threat = "credential_theft"
    strings:
        $at = "agenttesla"
    condition:
        $at
}

rule AsyncRAT_String {
    meta:
        threat = "rat"
    strings:
        $ar = /async\s*rat/i
    condition:
        $ar
}

rule FormBook_String {
    meta:
        threat = "stealer"
    strings:
        $fb = "formbook"
    condition:
        $fb
}

rule UPX_Packed {
    meta:
        threat = "packed_executable"
    strings:
        $u = "UPX!"
    condition:
        $u
}

rule Process_Hollowing {
    meta:
        threat = "malware_loader"
    strings:
        $alloc = "VirtualAllocEx"
        $write = "WriteProcessMemory"
        $crt = "CreateRemoteThread"
        $unmap = "NtUnmapViewOfSection"
    condition:
        all of them
}

rule Netsh_Tunnel {
    meta:
        threat = "c2_communication"
    strings:
        $n1 = /netsh\s+interface\s+portproxy/i
        $n2 = /netsh\s+advfirewall/i
    condition:
        any of them
}

rule Webhook_URL {
    meta:
        threat = "data_exfiltration"
    strings:
        $dis1 = "discord.com/api/webhooks"
        $dis2 = "discordapp.com/api/webhooks"
        $paste = "pastebin.com/raw"
        $gh = "raw.githubusercontent.com"
    condition:
        any of them
}

rule AutoIt_Compiled {
    meta:
        threat = "malware"
    strings:
        $sig = "AU3!"
        $ver = "AutoIt v3" nocase
    condition:
        $sig or $ver
}

rule Keylogger_API {
    meta:
        threat = "keylogger"
    strings:
        $getkey = "GetAsyncKeyState"
        $hook = "SetWindowsHookEx"
    condition:
        $getkey or $hook
}

rule Discord_TokenStealer {
    meta:
        threat = "credential_theft"
    strings:
        $api = "discord.com/api"
        $auth = "Authorization:"
    condition:
        $api and $auth
}
