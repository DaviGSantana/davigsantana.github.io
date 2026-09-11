---
title: Practical Malware Analysis - Data coding
date: 2026-09-01 16:00:00
description: In this post, I continue my studies of the book "Practical Malware Analysis" and begin working on Lab 13.
categories:
  - Practical Malware Analysis
tags:
  - Book
cover: pma-chapter13/cover.jpg
---

In this post, I continue my studies of the book "Practical Malware Analysis" and begin working on Lab 13. The goal is to apply practical static and dynamic analysis techniques to understand the behavior of real samples, reinforcing fundamental concepts used in malware analysis environments. This content is part of my study routine and documentation of the learning steps.

## LAB 12-01

Analyze the malware found in the file Lab13-01.exe

```
Lab13-01.exe
```

### Question 1
```
Compare the character sequences in the malware (obtained from the output of the strings command) with the information available through dynamic analysis. Based on this comparison, which elements might be encoded?
```

Looking at the binary strings, you can see glimpses of a possible GET request that the malware makes when it is executed.

```
Mozilla/4.0
http://%s/%s/
```

And using 'FakeNet' to see the request that the malware makes, we can actually see a GET request to the domain: www[.]practicalmalwareanalysis[.]com.

![alt text](pma-chapter12/tyhsA4E.png)

---

### Question 2
```
Use IDA Pro to look for possible encodings by searching for the string xor. What kind of encoding do you find?
```

Along with the 'xor' instruction that we found interesting, we see a hexadecimal value '3Bh' being used, which could give clues about the encryption key used...

![alt text](pma-chapter12/JwD0U1X.png)

Entering the function 'sub_401190' where we have the xor instruction above, we can see that there is a for loop here, which uses the key '3Bh' = 59 for encryption, and the key is the same for every encoded byte.

![alt text](pma-chapter12/HbQE4wB.png)

---

### Question 3
```
What is the key used for encoding and what content does it encode?
```

As we saw in the previous question, the key is: '59'.

When examining the cross-references of the function used for the encryption, we find one in 'sub_401300' where this function retrieves a resource using the functions 'LoadResource', 'SizeofResourceA', 'LockResource', and the encryption function 'sub_401190' is called with the retrieved resource and the specified size.

![alt text](pma-chapter12/HSzgvsr.png)

To decrypt the content in resources, I first extracted the resource to a .bin file, dropped it into 010 Editor, and got the following:

![alt text](pma-chapter12/9bP4fcj.png)

Now let's use the binary XOR tool to be able to reverse the content with the hexadecimal key '3Bh'. And then we have the decrypted content:

![alt text](pma-chapter12/aWWE6m4.png)

---

### Question 4
```
Use the static tools FindCrypt2, Krypto ANALyzer (KANAL), and the IDA Entropy plugin to identify any other encoding mechanisms. What do you find?
```

Using the Krypto ANALyzer (KANAL) plugin, we can see that Base64 encryption usage was found at 0x004050E8.

![alt text](pma-chapter12/BHETgYZ.png)

