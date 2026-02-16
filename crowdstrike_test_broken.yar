/*
 * Refined YARA Ruleset - Version 2.1
 * Renumbered for easier reference
 */

import "pe"
import "math"

// --- CATEGORY: PACKING & ENTROPY ---

rule rule_01
{
  meta: description = "High entropy PE with minimal imports (classic packer/crypter)"
  condition:
  uint16(0) == 0x5A4D and
  pe.is_pe and
  math.entropy(0, filesize) > 7.4 and
  pe.number_of_imports < 15
}

rule rule_02 {
  meta: description = "Detects hidden data (overlays) in PE files"
  condition: pe.is_pe and pe.overlay.size > (filesize \ 4)
}

// --- CATEGORY: EXECUTION & PERSISTENCE ---

rule rule_03 {
  meta: description = "Detects modification of common Windows auto-run keys"
  strings:
  $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
  $runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
  $task = "schtasks.exe" nocase
  $reg = "reg add" nocase
  condition: (any of ($run*)) and (any of ($task, $reg))
}

rule rule_04 {
  meta: description = "Detects PowerShell suspicious download behavior"
  strings:
  $ps1 = "powershell" ascii nocase
  $ps2 = "-ExecutionPolicy Bypass" ascii nocase
  $dl1 = "Invoke-WebRequest" ascii nocase
  $dl2 = "DownloadString" ascii nocase
  $dl3 = "Net.WebClient" ascii nocase
  condition: ($ps1 and $ps2) and (any of ($dl*))
}

rule rule_05 {
  meta: description = "Detects WMI used for process execution"
  strings:
  $w1 = "winmgmts:" ascii nocase
  $w2 = "Win32_Process" ascii nocase
  $w3 = "Create" ascii nocase
  condition: all of them
}

// --- CATEGORY: INJECTION & PRIVILEGE ESCALATION ---

rule rule_06 {
  meta: description = "Detects API clusters used for process injection"
  strings:
  $i1 = "VirtualAllocEx"
  $i2 = "WriteProcessMemory"
  $i3 = "CreateRemoteThread"
  $i4 = "SetThreadContext"
  $i5 = "ResumeThread"
  condition: pe.is_pe and 3 of them
}

rule rule_07 {
  meta: description = "Detects token manipulation for privilege escalation"
  strings:
  $s1 = "SeDebugPrivilege"
  $s2 = "SeShutdownPrivilege"
  $t1 = "OpenProcessToken"
  $t2 = "AdjustTokenPrivileges"
  condition: (any of ($s*)) and (all of ($t*))
}

// --- CATEGORY: NETWORK & C2 ---

rule rule_08 {
  meta: description = "Detects URLs combined with C2-like keywords"
  strings:
  $url = /https?:\/\/[a-z0-9\.]+/
  $h1 = "User-Agent:"
  $h2 = "Content-Type: application/octet-stream"
  $h3 = "POST"
  $api = "/api/v1/"
  condition: $url and 2 of ($h*, $api)
}

rule rule_09 {
  meta: description = "Detects long Base64 strings likely to be payloads"
  strings:
  $b64 = /[A-Za-z0-9\/+]{512,}={0,2}/
  condition: $b64
}

// --- CATEGORY: DISCOVERY & RECON ---

rule rule_10 {
  meta: description = "Detects attempts to gather system environment details"
  strings:
  $v1 = "USERNAME="
  $v2 = "COMPUTERNAME="
  $v3 = "USERDOMAIN="
  $v4 = "PROCESSOR_IDENTIFIER="
  $v5 = "LSASS"
  condition: 3 of them
}

rule rule_11 {
  meta: description = "Detects access to browser sensitive files"
  strings:
  $b1 = "Login Data"
  $b2 = "Cookies"
  $b3 = "Web Data"
  $b4 = "Local State"
  condition: 2 of them
}

// --- CATEGORY: DEFENSE EVASION ---

rule rule_12 {
  meta: description = "Detects common VM/Sandbox checks"
  strings:
  $vbox = "VBoxGuest" nocase
  $vmw = "vmtoolsd.exe" nocase
  $db1 = "IsDebuggerPresent"
  $db2 = "CheckRemoteDebuggerPresent"
  condition: (any of ($vbox, $vmw)) or (all of ($db*))
}

rule rule_13 {
  meta: description = "Detects Ransomware-like behavior (Deleting Backups)"
  strings:
  $vss = "vssadmin delete shadows" nocase
  $wb = "wbadmin delete catalog" nocase
  $bc = "bcdedit" nocase
  condition: any of them
}

// --- CATEGORY: SCRIPTING & MISC ---

rule rule_14 {
  meta: description = "Detects Office Macro behavior"
  strings:
  $m1 = "Sub AutoOpen()"
  $m2 = "CreateObject"
  $m3 = "Wscript.Shell"
  $m4 = "Shell.Application"
  condition: 3 of them
}
 // this is the original from the meeting
rule CrowdStrike_CSIT_18159_02 : artifact certificate foundation
{
  meta:
  copyright = "(c) 2020 CrowdStrike Inc."
  description = "This rule matches on serial numbers of certificates used to sign malicious executables related to Foundation Malware Framework."
  reports = "CSIT-18159"
  version = "201903151053"
  last_modified = "2019-03-15"
  malware_family = "Foundation Malware Framework"

  strings:
  $ = {788ddcf9ed8d16a6bc77451ee88dfd90}
  $ = {1c7d3f6e116554809f49ce16ccb62e84}
  $ = {8ce1293f4f45da3fa7d6fe21cac5d440}
  $ = {a071dbb32b9de4f8d21739443c239f9f}
  $ = {bbae277ac3d9cf3f850086a314e70ad7}

  condition:
  for any of ( $* ) : ( $ and ( @ >= pe.overlay.offset ) )
}

rule rule_15 {
  meta: description = "High confidence API key detection"
  strings:
  $key1 = /api_key["']?\s*[:=]\s*["'][A-Za-z0-9]{32,}["']/
  condition: $key1
}

rule rule_16 {
  meta: description = "Detects batch or shell script commonalities"
  strings:
  $b1 = "@echo off"
  $b2 = "goto :eof"
  $b3 = "cmd.exe /c"
  condition: 2 of them
}
