# PrivKit

A collection of Beacon Object Files (BOFs) for Windows Local Privilege Escalation Checks.

<p align="center">
  <img width="350" height="350" src="/Pictures/PrivKit-Logo.png"><br /><br />
  <img alt="GitHub License" src="https://img.shields.io/github/license/mertdas/PrivKit?style=social&logo=GitHub&logoColor=purple">
  <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/mertdas/PrivKit?logoColor=yellow"><br />
  <img alt="GitHub forks" src="https://img.shields.io/github/forks/mertdas/PrivKit?logoColor=red">
  <img alt="GitHub watchers" src="https://img.shields.io/github/watchers/mertdas/PrivKit?logoColor=blue">
  <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/mertdas/PrivKit?style=social&logo=GitHub&logoColor=green">
</p>

## Description

PrivKit is an open-source tool that empowers red teamers and penetration testers to quickly identify common Windows local privilege escalation vectors using Cobalt Strike Beacon Object Files (BOFs).

![Static Badge](https://img.shields.io/badge/C-lang-cyan?style=flat&logoSize=auto)
![Static Badge](https://img.shields.io/badge/Make-purple?style=flat&logoSize=auto)
![Static Badge](https://img.shields.io/badge/Version-2.0-red)
![Static Badge](https://img.shields.io/badge/Cobalt%20Strike-4.x-blue)
![Static Badge](https://img.shields.io/badge/Windows-Platform-lightgrey)

For command-line usage and examples, please refer to the <a href="#usage">Usage</a> section.

> If you find any bugs, don't hesitate to [report them](https://github.com/mertdas/PrivKit/issues). Your feedback is valuable in improving the quality of this project!

## Disclaimer

The authors and contributors of this project are not liable for any illegal use of the tool. It is intended for educational and authorized security testing purposes only. Users are responsible for ensuring lawful usage.

## Table of Contents
- [PrivKit](#PrivKit)
  - [Description](#description)
  - [Disclaimer](#disclaimer)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement](#acknowledgement)
  - [Features](#features)
  - [Instalation](#installation)
  - [Usage](#usage)
  - [Examples](#examples)
  - [References](#references)

## Acknowledgement

Speacial thanks to my friend [@nickvourd](https://x.com/nickvourd) for all his contributions.

Special thanks to the [TrustedSec](https://x.com/trustedsec) team for their excellent [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) project, which served as an inspiration for this tool.

Grateful acknowledgment to the [Cobalt Strike](https://www.cobaltstrike.com/) team for their comprehensive BOF documentation and examples.

PrivKit was created with :heart: by [@merterpreter](https://x.com/merterpreter).

## Features

PrivKit offers a comprehensive suite of privilege escalation checks, including:

| Check | Description |
|-------|-------------|
| **AlwaysInstallElevatedCheck** | Checks for AlwaysInstallElevated misconfiguration in HKCU and HKLM |
| **AutologonCheck** | Enumerates stored Autologon credentials in Winlogon registry |
| **CredentialManagerCheck** | Dumps credentials from Windows Credential Manager |
| **HijackablePathCheck** | Identifies writable directories in system PATH |
| **ModifiableAutorunCheck** | Finds writable autorun executables in Run/RunOnce keys |
| **ModifiableSVCCheck** | Finds services with modifiable permissions (DACL) |
| **TokenPrivilegesCheck** | Enumerates current process token privileges |
| **UnquotedSVCPathCheck** | Detects unquoted service paths with spaces |
| **PowerShellHistoryCheck** | Checks for PowerShell PSReadLine history file |
| **UACStatusCheck** | Checks UAC status, integrity level, and admin group membership |

### Why BOFs?

- ✅ **In-memory execution** - No files dropped to disk
- ✅ **Lightweight** - Minimal beacon footprint
- ✅ **Fast** - Native execution speed
- ✅ **Stealthy** - Runs within beacon's process context
- ✅ **Cross-architecture** - Supports both x64 and x86

PrivKit is written in C and compiled as Beacon Object Files, making it compatible with Cobalt Strike 4.x on Windows targets.

## Installation

⚠️ Please ensure that MinGW-w64 is installed on your system.

ℹ️ For Linux platforms (Ubuntu/Debian) install the following package:
```
sudo apt update && sudo apt install mingw-w64 -y
```

ℹ️ For MacOS platforms install the following package:
```
brew install mingw-w64
```

1) Clone the repository by executing the following command:
```
git clone https://github.com/mertdas/PrivKit.git
```

2) Once the repository is cloned, navigate into the PrivKit directory:
```
cd PrivKit
```

3) Use the `make_all.sh` script compiles all BOFs for both x64 and x86 architectures:
```
./make_all.sh
```

4) Load the aggressor script in Cobalt Strike:
```
Cobalt Strike -> Script Manager -> Load -> PrivCheck.cna
```

5) Verify installation in beacon:
```
beacon> help
```

## Usage

### Run All Checks

Execute all privilege escalation checks at once:
```
beacon> PrivCheck
```

### Run Individual Checks

Run specific checks as needed:
```
beacon> AlwaysInstallElevatedCheck
beacon> AutologonCheck
beacon> CredentialManagerCheck
beacon> HijackablePathCheck
beacon> ModifiableAutorunCheck
beacon> ModifiableSVCCheck
beacon> TokenPrivilegesCheck
beacon> UnquotedSVCPathCheck
beacon> PowerShellHistoryCheck
beacon> UACStatusCheck
```

## Examples

### AlwaysInstallElevatedCheck
```
beacon> AlwaysInstallElevatedCheck
[*] BOF by @merterpreter && @nickvourd
[*] Checking AlwaysInstallElevated privilege escalation vulnerability...

=== AlwaysInstallElevated Check ===

[*] HKCU\...\Installer\AlwaysInstallElevated = 1
[*] HKLM\...\Installer\AlwaysInstallElevated = 1

[+] VULNERABLE: AlwaysInstallElevated is set in both HKCU and HKLM
```

### UACStatusCheck
```
beacon> UACStatusCheck
[*] BOF by @merterpreter && @nickvourd
[*] Checking UAC status, integrity level, and admin membership...

=== UAC Status Check ===

[11/27 15:08:08] [+] received output:
[*] UAC Enabled (EnableLUA): Yes

[11/27 15:08:08] [+] received output:
[*] ConsentPromptBehaviorAdmin: 5 
[11/27 15:08:08] [+] received output:
(Prompt for consent for non-Windows binaries)

[11/27 15:08:08] [+] received output:
[*] PromptOnSecureDesktop: Yes

[11/27 15:08:08] [+] received output:


[11/27 15:08:08] [+] received output:
[*] Integrity Level: 
[11/27 15:08:08] [+] received output:
Medium

[11/27 15:08:08] [+] received output:
[*] Local Admin Group Member: Yes

[11/27 15:08:08] [+] received output:

[*] Summary:

[11/27 15:08:08] [+] received output:
[+] User is local admin but NOT elevated (UAC filtered token)

[11/27 15:08:08] [+] received output:
[+] UAC bypass may be possible
```

## References

- [Cobalt Strike BOF Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm)
- [TrustedSec CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
- [TrustedSec CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF)
- [Windows-Local-Privilege-Escalation-Cookbook GitHub by nickvourd](https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/)
- [Windows Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [WIN32 APIs Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/)
- [Offensive Coding by Mr.Un1k0der](https://mr.un1k0d3r.world/portal/)
- [MALDEV Academy](https://maldevacademy.com/)
- [Sektor7 Institute](https://institute.sektor7.net/)