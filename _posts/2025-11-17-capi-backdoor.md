---
title: "CAPI Backdoor: .NET Stealer Targeting Russian Auto-Commerce"
date: 2025-11-17 14:00:00 -0300
layout: post
categories: [Malware]
tags: [reverse, malware-analysis]
image: "/assets/img/Post_1/virus-malware.jpg"
---
Recently, the SEQRITE Labs published an analysis on a campaign targeted at the Russian automotive trade sector. After direct contact with the researcher Subhajeet Singha, I received the main sample to carry out an in-depth reverse analysis, focusing on the internal behavior of backdoor and in the architecture of functionalities.

The initial vector comes in a ZIP file, named in Russian as:
```
Перерасчет заработной платы 01.10.2025.zip
```
The ZIP file contains an LNK file named Перерасчет заработной платы 01.10.2025.lnk. Analysis shows that its sole purpose is to invoke rundll32.exe to load and execute the malicious payload adobe.dll, which is a .NET-based DLL implant.

## .NET Reconnaissance
![alt text](/assets/img/Post_1/pe.png)

The PE metadata immediately confirms that the sample is a .NET assembly, allowing the use of tools like dnSpy or ILSpy for full method-level inspection. This also indicates that traditional unpacking or native disassembly is not necessary, since most of the logic resides in managed code.

## Analyze Functions
Now, upon analyzing the binary, we identified a robust set of functionalities implemented within the .NET implant known as **CAPI Backdoor**. Each mapped function reveals a specific operational behavior, forming the complete architecture for data collection, persistence, environment detection, and communication with the command and control server.
![alt text](/assets/img/functions.png)
Next, we will analyze the functions

### connect()
![alt text](/assets/img/connect.png)
This function establishes the initial connection with the Command and Control (C2) server.
The routine uses a `TcpClient` to attempt to connect to the remote address defined by the operator, usually over port **443**, simulating legitimate HTTPS traffic. 
Once connected, the function initializes the communication stream (`NetworkStream`) that will be used to send and receive instructions. This is the core of the backdoor communication: without `connect()`, no other remote functionality can be triggered.