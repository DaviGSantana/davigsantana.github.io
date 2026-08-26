---
title: Analysis of a RAR File Leading to Malicious GitHub Repositories Distributing LummaC2
date: 2026-08-28 15:00:00
description: This analysis begins with a seemingly harmless RAR archive and follows the infection chain to uncover malicious GitHub repositories used to distribute LummaC2, a notorious information stealer. The investigation examines the archive, the associated files and repositories, and the techniques used to deliver the malware to victims.
categories:
  - Malware Analysis
tags:
  - Stealer
  - Malware
cover: LummaC2/cover.png
---

# Introduction

The analyzed malware disguises itself as a supposed TurboTax activation software, taking advantage of the brand's familiarity to trick the user into running the malicious file. TurboTax is a commercially available software widely used in the United States to help with filling out and filing income taxes.

# Static Analysis - Setup PE Informations

Dentro da pasta zip do download fornecido do software, alem de termos arquivos dll, temos um arquivo de setup, com o nome 'Setup_v1.8.2.exe', vamos analisar seu cabecalho PE.

