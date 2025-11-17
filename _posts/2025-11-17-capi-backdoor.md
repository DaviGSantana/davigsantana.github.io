---
title: "CAPI Backdoor: .NET Stealer Targeting Russian Auto-Commerce"
date: 2025-11-17 14:00:00 -0300
layout: post
categories: [Malware]
tags: [reverse, malware-analysis]
image: "/assets/img/Post_1/virus-malware.jpg"
---

Recently, the SEQRITE Labs published an analysis on a campaign targeted at the Russian automotive trade sector. After direct contact with the researcher Subhajeet Singha, I received the main sample to carry out an in-depth reverse analysis, focusing on the internal behavior of backdoor and in the architecture of functionalities.
---
---
The initial vector comes in a ZIP file, named in Russian as:
```
Перерасчёт заработной платы 01.10.2025.zip
```
## Binary Reconnaissance