---
title: Practical Malware Analysis - Identifying Malicious Behavior via Static Analysis
date: 2026-02-06 16:00:00
description: In this post, I continue my studies of the book "Practical Malware Analysis" and begin working on Lab 5.
categories:
  - Practical Malware Analysis
tags:
  - Book
cover: pma-chapter5/cover.jpg
---

In this post, I continue my studies of the book "Practical Malware Analysis" and begin working on Lab 5. The goal is to apply practical static and dynamic analysis techniques to understand the behavior of real samples, reinforcing fundamental concepts used in malware analysis environments. This content is part of my study routine and documentation of the learning steps.

---

## 1.1 LAB 5-1
```
Lab05-01.dll
```

### 1.1.1 Question 1
```
What is the address of DllMain?
```
When loading the DLL in IDA, we will navigate to the DllMain function, and then it is possible to locate its address.

![alt text](pma-chapter5/DllMain.png)

```Answer 
1000D02E
```
---

### 1.1.2 Question 2
```
Use the import window to navigate to gethostbyname. Where is the import located?
```
Searching for the imports, find gethostbyname and then locate the address.

![alt text](pma-chapter5/gethostbyname.png)

Imports

![alt text](pma-chapter5/gethostbyname-imports.png)

```Answer 
100163CC
```
---

### 1.1.3 Question 3
```
How many functions call gethostmyname?
```
Using the jump list cross-references to, we can view the subroutines/functions.

![alt text](pma-chapter5/xrefs.png)

---

### 1.1.4 Question 4
```
Focusing on the call to gethostbyname at 0x10001757. Can you figure out which DNS request will be made?
```

After navigating to the provided address, looking above before the function call, it is possible to see that an address offset is being moved to EAX before 0Dh is added.

![alt text](pma-chapter5/u7WKkGF.png)

E possivel identificar que EAX agora aponta para 0x10019194, dentro dos dados contem: [This is RDO]pics.practicalmalwareanalysis.com

![alt text](pma-chapter5/Qpjnb5F.png)

```Answer
pics.practicalmalwareanalysis.com
```
---

### 1.1.5 Question 5
```
How many local variables did IDA recognize for the subroutine at 0x10001656?
```

Navigating to the address 0x10001656, IDA identified the following variables;

![alt text](pma-chapter5/XBMb9le.png)

---

### 1.1.6 Question 6
```
How many parameters did IDA recognize for the subroutine at 0x10001656?
```

Looking at the last image provided above, it is possible to see that IpThreadParameter was identified, indicating that 1 parameter was expected in this subroutine.

---

### 1.1.7 Question 7
```
Use the strings window to locate the string \cmd.exe /c in the disassembly. Where is it located?
```

![alt text](pma-chapter5/cmdexe.png)

```Answer
10095B34
```
---

### 1.1.8 Question 8
```
What's going on in the area of the code that references \cmd.exe /c?
```

Analyzing the function, it is possible to identify a character array 'HiMasterDDDDDD' that mentions 'Remote Shell Session', which leads one to think that it might possibly be a remote shell session function.

![alt text](pma-chapter5/remoteshell.png)
---

### 1.1.9 Question 9
```
In the same area, at 0x100101C8, it looks like dword_1008E5C4 is a global variable that helps decide which path to take. How does the malware set dword_1008E5C4? (Hint: Use dword_1008E5C4’s cross-references.)
```
Navigating to the address 0x100101C8, it is possible to identify a comparison instruction, comparing ebx with the value dword_1008E5C4. As a hint for the question, when analyzing the cross-references of dword_1008E5C4, it is possible to see that one of them contains the mov instruction to assign the value.

![alt text](pma-chapter5/yE0Gzhw.png)
It is possible to see that the output of sub_10003695 will be moved to dword_1008E5C4.

![alt text](pma-chapter5/RVc5CPK.png)
Let's analyze what this routine is about. Upon analysis, it is possible to verify that it is comparing the platform ID dw with the value 2; -> this indicates that the operating system is Windows NT or later.

![alt text](pma-chapter5/WspNXJd.png)

So, the malware will possibly follow a different path depending on whether the operating system is Windows NT or later.
---

### 1.1.10 Question 10
```
A few hundred lines into the subroutine at 0x1000FF58, a series of comparisons use memcmp to compare strings. What happens if the string comparison to robotwork is successful (when memcmp returns 0) 
```

First, let's navigate to the subroutine at 0x1000FF58 and look for the string comparisons that are being made. The buffer is comparing the string 'robotword' found, analyzing the code, it checks if a buffer contains exactly the string 'robotwork', if it does, it executes the function sub_100052A2 passing the value taken from the stack; if not, it jumps to the next flow, loc_10010468.

![alt text](pma-chapter5/robotwork.png)

In sub_100052A2, we will see that it is opening a registry key at: HKLMSOFTWAREMicrosoftWindowsCurrentVersion. In jz, it checks whether the registry was opened successfully or not. If the registry is opened successfully, it will be = 0 and will proceed to loc_10005209.

![alt text](pma-chapter5/reg.png)

In loc_10005309 it is possible to see that it is querying the worktime registry key. In the previous code where the registry key was opened, it is possible to see that a type of argument called socket is being passed with the value s. Going back to the beginning of the question, we can see that this pushes ebp+s, which indicates that this information is sent back through the passed network socket.

![alt text](pma-chapter5/worktime.png)
---

### 1.1.11 Question 11
```
What does the PSLIST export command do?
```

After analysis, it is possible to identify that we will have two different paths that will be followed according to the result of sub_100036C3. So let's dive deeper.

![alt text](pma-chapter5/pslist.png)

In subroutine 100036C3, it uses the Windows APIs: GetVersionExA and OSVERSIONINFOA, clearly used to detect the Windows version and return 1 or 0 depending on whether the system meets a specific condition.

![alt text](pma-chapter5/a694BGq.png)

Points to analyze: sub_10006518 and sub_1000664C, the two different paths that will be followed according to the result of the operating system version check.

sub_10006518: with analysis on the API call to CreateToolhelp32Snapshot, from the strings, it will probably allow them to access processes.

![alt text](pma-chapter5/sS.png)

sub_1000664C makes use of the same calls.
---

### 1.1.12 Question 12
```
Use the graphical mode to graphically represent the cross-references of sub_100004E79. Which API functions could be called when inserting this function? Considering only the API functions, what alternative name would you give to this function?
```

![alt text](pma-chapter5/xjtEGOW.png)

When viewing it, it is possible to notice that GetSystemDefaultLangID is used, which is used to return the language identifier. The send function is also used, probably to send information about the system language. We can name it LanguageIdentify.
---

### 1.1.13 Question 13
```
How many Windows API functions does DllMain call directly? How many at a depth of 2?
```

![alt text](pma-chapter5/dllmain1.png)

![alt text](pma-chapter5/dllmain2.png)

![alt text](pma-chapter5/dllmain3.png)
---

### 1.1.14 Question 14
```
At address 0x10001358, there is a call to Sleep (an API function that takes a parameter containing a number of milliseconds to wait). Analyzing the code backwards, how long will the program wait if this code is executed?
```

![alt text](pma-chapter5/WiRnCGR.png)

Let's analyze the pseudocode now,

![alt text](pma-chapter5/hZizCpJ.png)

It is possible to notice that Sleep is set with the value: "1000 (1 second) * v14", but what would this v14 value be? Let's take a closer look:

![alt text](pma-chapter5/XzKPMS4.png)

![alt text](pma-chapter5/VUFCrMm.png)

```Answer
Sleep(1000 * 30) = 30 seconds
```
---


### 1.1.15 Question 15
```
At address 0x10001701 there is a call to a socket. What are the three parameters?
```

![alt text](pma-chapter5/YjeyyLn.png)

![alt text](pma-chapter5/YYkcsKF.png)
---

### 1.1.16 Question 16
```
Using the MSDN page on sockets and the functionality of named symbolic constants in IDA Pro, can you make the parameters more meaningful? What are the parameters after applying the changes?
```

Let's go to the MSDN page to get more information about this function.

```c++
SOCKET WSAAPI socket(
  [in] int af,
  [in] int type,
  [in] int protocol
);
```

![alt text](pma-chapter5/jWZDZZW.png)

![alt text](pma-chapter5/oAv6vRg.png)

![alt text](pma-chapter5/F9avT24.png)

![alt text](pma-chapter5/p2WNVup.png)
---

### 1.1.17 Question 17
```
Search for usage of the in instruction (opcode 0xED). This instruction is used with a magic string VMXh to perform VMware detection. Is that in use in this malware? Using the cross-references to the function that executes the in instruction, is there further evidence of VMware detection?
```

![alt text](pma-chapter5/7toB4yh.png)

Analyzing this function, it is possible to identify that it checks the VMXh value, which is an anti-VM technique.

![alt text](pma-chapter5/xR9UTBK.png)

Function Xrefs:

![alt text](pma-chapter5/MKZBs3n.png)

In one of the references, it is possible to see that it performs a VM check, and if one is found, it cancels the installation.
---

### 1.1.18 Question 18
```
Move the cursor to 0x1001D988. What do you find?
```

Apparently, random data.

![alt text](pma-chapter5/Zk5Q08N.png)
---

### 1.1.19 Question 19
```
If you have the IDA Python plug-in installed (including the package with the commercial version of IDA PRO), run Lab05-01.py, a Python script in IDA Pro provided with the malware from this book. (Make sure the cursor is at 0x1001D998). What happened after running the script?
```

At the moment, I am using the free version of IDA Pro.
---

Completed.