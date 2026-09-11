---
title: Reverse Engineering for Beginners - Hands-On Labs
date: 2026-09-10 11:00:00
description: In this post, I continue my studies of the "Reverse Engineering for Beginners" course by completing the hands-on cracking challenges from Lesson 11.
categories:
  - CrackMe
tags:
  - Reverse Engineering
  - Assembly
cover: re-beginners-lesson11-linux/cover.jpg
---

## Introduction

In this post, I continue my studies of the course 'Reverse Engineering for Beginners' from Red Team Leaders, putting into practice some of the concepts presented throughout the lessons.

In this lesson, I worked with the practical cracking labs for Linux, analyzing different CrackMe-type challenges. The exercises cover everything from simple password checks to multi-step validations, involving techniques like string analysis, debugging, and identifying the logic used by the program to validate the input provided.

The goal was to solve the challenges by analyzing the behavior of the binaries, aiming to understand their internal logic and identify the information needed to overcome each step of the validation.

# crackme1
## Objetivo
Encontre a senha hardcoded e insira-a para ver a mensagem de sucesso.

## Recon

```bash
> file crackme1

crackme1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f1294f71e847254866d0b014f85e3124ea8d65a8, for GNU/Linux 3.2.0, not stripped
```

Aqui sabemos que e um binário ELF 64-bits.

Vamos ver todas as strings possíveis no binário com o comando strings(irei deixar apenas as interessantes):
```bash
r3vers1ng_101
=== CrackMe Level 1 ===
Enter the password: 
[+] Access Granted! You cracked it!
[+] Flag: FLAG{strings_are_your_friend}
[-] Access Denied. Try again.
check_password
```
Aqui possivelmente ja temos a senha e a flag obtida que precisamos para concluir o desafio, mais vamos mais a fundo.

---
## Analise estática

Podemos analisar também algumas seções interessantes(.rodata) do binário para vermos um poucos de seus dados e funcionalidades.
```bash
 402000 01000200 00000000 72337665 7273316e  ........r3vers1n
 402010 675f3130 31003d3d 3d204372 61636b4d  g_101.=== CrackM
 402020 65204c65 76656c20 31203d3d 3d00456e  e Level 1 ===.En
 402030 74657220 74686520 70617373 776f7264  ter the password
 402040 3a20000a 00000000 5b2b5d20 41636365  : ......[+] Acce
 402050 73732047 72616e74 65642120 596f7520  ss Granted! You 
 402060 63726163 6b656420 69742100 00000000  cracked it!.....
 402070 5b2b5d20 466c6167 3a20464c 41477b73  [+] Flag: FLAG{s
 402080 7472696e 67735f61 72655f79 6f75725f  trings_are_your_
 402090 66726965 6e647d00 5b2d5d20 41636365  friend}.[-] Acce
 4020a0 73732044 656e6965 642e2054 72792061  ss Denied. Try a
 4020b0 6761696e 2e00                        gain.. 
```

Analisando as funções do binário, claramente encontramos aonde e feito a verificação da senha fornecida pelo usuário(check_password), vamos ver oque possivelmente ela faz:
```bash
> objdump -M intel -d crackme1 | grep -A 20 "<check_password>:"
  401176:       55                      push   rbp
  401177:       48 89 e5                mov    rbp,rsp
  40117a:       48 83 ec 20             sub    rsp,0x20
  40117e:       48 89 7d e8             mov    QWORD PTR [rbp-0x18],rdi
  401182:       48 8d 05 7f 0e 00 00    lea    rax,[rip+0xe7f]        # 402008 <_IO_stdin_used+0x8>
  401189:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  40118d:       48 8b 55 f8             mov    rdx,QWORD PTR [rbp-0x8]
  401191:       48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]
  401195:       48 89 d6                mov    rsi,rdx
  401198:       48 89 c7                mov    rdi,rax
  40119b:       e8 d0 fe ff ff          call   401070 <strcmp@plt>
  4011a0:       85 c0                   test   eax,eax
  4011a2:       0f 94 c0                sete   al
  4011a5:       0f b6 c0                movzx  eax,al
  4011a8:       c9                      leave
  4011a9:       c3                      ret
```
Dentro da função ele utiliza 'strcmp' para comparar a senha fornecida com o usuário(rdi) com a senha correta(rsi) e esperada pelo programa.

---
## Analise dinâmica

De cara vamos diretamente aonde sabemos que iremos encontrar a senha correta em 'strcmp' dentro da função 'check_password':
```bash
 →   0x40119b <check_password+0025> call   0x401070 <strcmp@plt>
  strcmp@plt (
   $rdi = 0x00007fffffffdc80 → 0x0000000069766164 ("test"?),
   $rsi = 0x0000000000402008 → "r3vers1ng_101",
   $rdx = 0x0000000000402008 → "r3vers1ng_101"
  )

```

Executando o binário fornecendo a senha correta:

```bash
./crackme1
=== CrackMe Level 1 ===
Enter the password: r3vers1ng_101
[+] Access Granted! You cracked it!
[+] Flag: FLAG{strings_are_your_friend}
```
# crackme2

Encontre a senha codificada com XOR no binário. A senha não está armazenada
em texto claro -- você precisa encontrar o esquema de codificação e revertê-lo.

O binario faz a mesma funcao do crackme1, so que utilizando criptografia XOR, assim temos a funcao check_password que irei explicar codigo por codigo:

![alt text](re-beginners-lesson11-linux/XbF9fuu.png)

1. Cria as variáveis locais
```asm
push rbp
mov rbp, rsp
sub rsp, 0x40
```
Reserva 0x40 = 64 bytes na stack para a função.

Os principais locais usados são:
```
[rbp-0x38] -> input (senha fornecida pelo usuario)
[rbp-0x30] -> buffer (senha decodificada)
[rbp-0x04] -> contador 'i'
```

---

2.  Salva o input e inicializa o contador
```asm
mov QWORD PTR [rbp-0x38], rdi
mov DWORD PTR [rbp-0x04], 0x0
```
Como `RDI` contem o primeiro argumento que foi passado ao chamar esta função `check_password`:
```asm
[rbp-0x38] = input
```
E:
```asm
[rbp-0x04] = 0
```
Então:
```c
i = 0;
```

---

3. Pega um caractere de `encoded`
```asm
mov eax, DWORD PTR [rbp-0x4]
cdqe
lea rdx, [rip-0x2ea9]       # encoded
movzx eax, BYTE PTR [rax+rdx]
```
Aqui ele usa o contador para acessar:
```c
encoded[i];
```
Então, conceitualmente:
```c
i = 0;
encoded[0];
```
Depois 
```c
i = 1;
encoded[1];
```
e assim em diante...

---

4. Decodifica com XOR
```asm
xor eax, 0x37
```
Faz:
```c
encoded[i] ^ 0x37;
```
Esse e o processo de decodificação.

---

5. Colocar o resultado no buffer
```asm
mov edx, eax
mov eax, DWORD PTR [rbp-0x4]
cdqe
mov BYTE PTR [rbp+rax*1-0x30], dl
```
O resultado do XOR e colocado em:
```c
buffer[i];
```
Lembrando:
```
buffer comeca em [rbp-0x30]
```
Então:
```c
buffer[0] = encoded[0] ^ 0x37;
buffer[1] = encoded[1] ^ 0x37;
buffer[2] = encoded[2] ^ 0x37;
```

---

6. Incrementa o contador
```asm
add DWORD PTR [rbp-0x4], 0x1
```
E simplesmente:
```c
i++;
```

---

7. Verifica se chegou ao final de `encoded`:
```asm 
mov eax, DWORD PTR [rbp-0x4]
cdqe
lea rdx, [rip+0x2e87]
movzx eax, BYTE PTR [rax+rdx]
test al, al
jne 0x40118b
```
Verifica:
```c
encoded[i] != '\0'
```
Se ainda não chegou ao final, volta para o inicio do loop:
```
-> pega encoded[i]
-> XOR 0x37
-> colocar em buffer[i]
-> i++
-> verifica novamente
```

---

8. Finaliza o buffer
```asm 
mov BYTE PTR [rbp+rax*1-0x30], 0x0
```
Colocar `\0` no final:
```c
buffer[i] = '\0';
```
Agora `buffer` e uma string valida.

---

9. Compara com o input
```asm  
mov rsi, rdx
mov rdi, rax
call strcmp@plt
```
Prepara:
```
RDI -> input
RSI -> buffer
```
e chama:
```c
strcmp(input, buffer);
```

---

10. Retorna 1 ou 0
```asm 
test eax, eax
sete al
movzx eax, al
``` 
Se `strcmp()` retornar `0`:
```
input == buffer
```
então retorna:
```
1     caso contrario ->  0
```

Como sabemos, na chamada para `strcmp()` ira ser passado o buffer de criptografado para comparar com a string fornecida pelo usuário, e assim conseguimos ver em texto claro a string esperada.

![alt text](re-beginners-lesson11-linux/sH7oMRD.png)

Então, passando a senha correta:
```bash
./crackme2 
=== CrackMe Level 2 ===
Enter the password: xorm4Ecs2r
[+] Access Granted! XOR decryption mastered!
[+] Flag: FLAG{x0r_is_r3v3rsible}
```

---

# crackme3

Passe por todos os três estágios de validação. A senha possui um formato, comprimento e
restrições de caracteres específicos. Você deve fazer engenharia reversa de cada estágio separadamente.

Neste binário a verificação da senha passa por 3 estágios: `stage1`, `stage2` e `stage3`.

## stage1
Vamos ver o código de `stage1`:

![alt text](re-beginners-lesson11-linux/6KwHNKe.png)

1. Cria o stack frame:
```asm
push rbp 
mov rbp, rsp
sub rsp, 0x10
```
Reserva `0x10` = 16 bytes na stack.

Aqui temos:
```
[rbp-0x8] -> input
```

---

2. Salva o input
```asm
mov QWORD PTR [rbp-0x8], rdi
```
`RDI` contem o primeiro argumento da função.

Então:
```
[rbp-0x8] = input
```

---

3. Prepara o input para `strlen`
```asm
mov rax, QWORD PTR [rbp-0x8]
mov rdi, rax
call strlen@plt
```
Recupera o `input` e coloca em `RDI`.

Depois chama:
```c
strlen(input);
```
O resultado de `strlen()` fica em `RAX`.

---

4. Compara o tamanho com `0xc` = 12.
```asm
cmp rax, 0xc
```

---

5. Converte o resultado em verdadeiro/falso
```asm 
sete al
movzx eax, al
```
`sete` significa ***Set if Equal***.

Se:
```
RAX == 12
```
então:
```
AL = 1
```
Caso contrario:
```
AL = 0
```
Depois `movzx` transforma isso em um valor inteiro:
```
EAX = 1
ou
EAX = 0
```

---

6. Retorno
```asm
leave 
ret
```
A chamada para a função `stage1` retorna em `RAX` :
```
1 -> input possui exatamente 12 caracteres
0 -> input possui tamanho diferente de 12
```


## stage2
Vamos ver o código de `stage2`:

![alt text](re-beginners-lesson11-linux/Ty3ABgd.png)

1. Salva o input
```asm
push rbp 
mov rbp, rsp
mov QWORD PTR [rbp-0x8], rdi
```
`RDI` contem o argumento da função, então:
```
[rbp-0x8] -> input
```
Nao ha contador explicito, ela acessa diretamente as posições `0`,`1`,`2` e `3`.

---

2. Verifica o primeiro caractere
```asm
mov rax, QWORD PTR [rbp-0x8]
movzx eax, BYTE PTR [rax]
cmp al, 0x52
jne 0x4011e1
```
`[rax]` significa"
```c
input[0];
```
E compara com:
```
0x52 = 'R'
```
Então:
```
input[0] == 'R'
```
Se for diferente, `jne` pula para o final e retorna `0`.

---

3. Verifica o seguindo caractere
```asm
mov rax, QWORD PTR [rbp-0x8]
add rax, 0x1
movzx eax, BYTE PTR [rax]
cmp al, 0x45
jne 0x4011e1
```
Aqui:
```
rax = input + 1
```
Portanto:
```c
input[1];
```
e comparado com:
```
0x45 = 'E'
```
Então:
```
input[1] == 'E'
```

---

4. Verifica o terceiro caractere
```asm
mov rax, QWORD PTR [rbp-0x8]
add rax, 0x2
movzx eax, BYTE PTR [rax]
cmp al, 0x5f
jne 0x4011e1
```
Agora acessa:
```c
input[2];
```
E compara com:
```
0x5f = '_'
```
Então:
```
input[2] == '_'
```

---

5. Verifica o quarto caractere
```asm
mov rax, QWORD PTR [rbp-0x8]
add rax, 0x3
movzx eax, BYTE PTR [rax]
cmp al, 0x7b
jne 0x4011e1
```
Acessa:
```c
input[3];
```
e compara com:
```
0x7b = '{'
```
Então:
```
input[3] == '{'
```

---

6. Se tudo estiver correto:
```asm
mov eax, 0x1
jmp 0x4011e6
```
Retorna:
```
1
```
Se ***qualquer uma*** das comparações falhar:
```asm
mov eax, 0x0
```
Retorna:
```
0
```

 > Agora, sabemos que o `stage2` verifica se os primeiros 4 caracteres da strings de 12 caracteres fornecida começam com 'RE_{'.

---
## stage3
Vamos ver o código de `stage3`:

![alt text](re-beginners-lesson11-linux/4FqvmSE.png)

1. Inicializa as variáveis
```asm
mov QWORD PTR [rbp-0x18], rdi
mov QWORD PTR [rbp-0x4], 0x0
mov QWORD PTR [rbp-0x8], 0x4
```
 Temos:
```
 [rbp-0x18] -> input
 [rbp-0x04] -> soma = 0
 [rbp-0x08] -> contador = 4
```
Ou seja:
```c
int sum = 0;
int i = 4;
```
O contador começa em `4`, porque a `stage2` ja verificou as posições `0` a `3`.

---

2. Pega `input[i]`
```asm
mov eax, DWORD PTR [rbp-0x8]
movsxd rdx, eax
mov rax, QWORD PTR [rbp-0x18]
add rax, rdx
movzx eax, BYTE PTR [rax]
movsx eax, al
```
Aqui ele calcula:
```
input[i]
```
Como `i` começa em 4:
```
input[4]
input[5]
input[6]
...
```
`movzx` pega o caractere como ***1 byte***, e `movsx` transforma esse byte em um inteiro com sinal.

Na pratica, para caracteres ASCII normais, podemos pensar em simplesmente:
```c
int value = input[i];
```

---

3.  Soma o caractere
```asm
add DWORD PTR [rbp-0x4], eax
```
Adiciona o valor ASCII a variavel `sum`:
```c
sum += input[i];
```
Ex:
```
'A' = 65
'B' = 66
'C' = 48
```

---

4. Incrementando o contador
```asm
add DWORD PTR [rbp-0x8], 0x1
```
E:
```c
i++;
```
Então o loop vai processar:
```
i = 4
i = 5
i = 6
i = 7
i = 8
i = 9
i = 10
```

---

5. Condição do loop
```asm
cmp DWORD PTR [rbp-0x8], 0xa
jle 0x401200
```
`0xa` em hexadecimal e `10`.

Enquanto:
```
i <= 10
```
ele continua.

Portanto, sao 7 caracteres:
```
input[4] ate input[10]
```
Podemos imaginar o loop da seguinte forma:
```c
for (i = 4; i ,+ 10; i++)
	sum += input[i];
```

---

6.  Verifica a soma
```asm
cmp DWORD PTR [rbp-0x4], 0x2c0
jne 0x40123f
```
`0x2c0` em decimal:
```
0x2c0 = 704
```
Entao:
```c
if (sum != 704)
	return 0;
```
Ou seja:

> A soma dos valores ASCII de `input[4]` ate `input[10]` precisa ser 704.

---

7. Verifica o ultimo caractere
	Se a soma estiver correta: 
```asm
mov rax, QWORD PTR [rbp-0x18]
add rax, 0xb
movzx eax, BYTE PTR [rax]
cmp al, 0x7d
jne 0x40123f
```
`0xb` = 11

Então ele verifica:
```
input[11]
```
conta:
``` 
0x7d = '}'
```
Portanto:
```
input[11] == '}'
```

---

8. Retorno
	Se tudo estiver correto:
```asm
mov eax, 0x1
```
Retorna:
```
1
```
Se a soma estiver errada ***ou*** `input[11]` não for `}`.
```
mov eax, 0x0
```
Retornando:
```
0
```

***Resumindo***
 ```
 [0] [1] [2] [3] [4] [5] [6] [7] [8] [9] [10] [11]
  R   E   _   {   ?   ?   ?   ?   ?   ?    ?    }
 └────────────┘  └──────────────────────────┘ └───┘
     stage2              soma = 704           stage3

 ```


Então, juntando com as etapas anteriores, ja sabemos que o formato e:

```
RE_{???????}
```
onde os ***7*** precisam ter soma ASCII = 704, e o ultimo caractere e `}`.

Neste caso utilizei : `d d d d d d h` . Explicacao:
```
d = 100
h = 104

6 * 100 + 104 = 704
```

Executando o `crackme3` fornecendo a string correta:

```bash
./crackme3 
=== CrackMe Level 3 ===
Enter the password: RE_{ddddddh}
[*] Stage 1: Length check... PASSED
[*] Stage 2: Format check... PASSED
[*] Stage 3: Value check... PASSED
[+] All stages passed! Excellent work!
[+] Flag: FLAG{multi_stage_cracker}
```

