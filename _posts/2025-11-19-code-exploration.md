---
title: "Exploration of C Code"
date: 2025-11-20 17:00:00 -0300
layout: post
categories: [Debuggers]
tags: [reverse, exploit-development, windows-internals]
image: "/assets/img/Post_4/seh.png"
---

## Introduction
In this class, I explored the SEH mechanism in Windows, a fundamental feature for exception control in applications written in C. In addition to the legitimate approach of SEH, I also analyzed how this structure can be exploited in offensive security scenarios—especially in vulnerabilities that allow the redirection of execution flow. This study is part of my development in debugging, reverse engineering, and understanding the internal mechanisms of Windows that can be both protection tools and attack vectors.
---

## SEH

SEH (Structured Exception Handling) e uma lista encadeada (estrutura de dados) para lidar com excecao.
O C++ tem uma estrutura chamada "try... catch" para lidar com erros
A Microsoft criou uma estrutura semelhante para o C no Visual Studio.

### Oque e uma excecao?
Uma excecao e todo erro que acontece e nao seria previsto, seja por um erro do programador, do cliente...

