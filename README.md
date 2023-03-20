# PrivKit
PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.

## PrivKit detects following misconfigurations

```
 Checks for Unquoted Service Paths
 Checks for Autologon Registry Keys
 Checks for Always Install Elevated Registry Keys
 Checks for Modifiable Autoruns
 Checks for Hijackable Paths
 Enumerates Credentials From Credential Manager
 Looks for current Token Privileges
 ```
 
 ## Usage
 
 Simply load the cna file and type "privcheck"<br>
 If you want to compile by yourself you can use:<br>
```x86_64-w64-mingw32-gcc -c cfile.c -o ofile.o```

If you want to look for just one you can use object file with "inline-execute" for example<br>
``` inline-execute /path/tokenprivileges.o```

 ## Acknowledgement
 
 Mr.Un1K0d3r - Offensive Coding Portal <br>
https://mr.un1k0d3r.world/portal/

Outflank - C2-Tool-Collection<br>
https://github.com/outflanknl/C2-Tool-Collection

dtmsecurity - Beacon Object File (BOF) Creation Helper
https://github.com/dtmsecurity/bof_helper

Microsoft :) <br>
https://learn.microsoft.com/en-us/windows/win32/api/

![privcheck1](https://user-images.githubusercontent.com/48562581/226249192-84da03d5-435a-4da0-a6e6-4c451d2403e4.PNG)

![privcheck2](https://user-images.githubusercontent.com/48562581/226249135-a2444998-8c4f-4783-9b60-726c887032e4.PNG)


