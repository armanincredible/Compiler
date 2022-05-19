# Compiler
Hello. This is compiler. Recently a programming [language](https://github.com/armanincredible/Language), the main words of which are from Dora's song. Now I imagine a compiler that will convert the tree into translatable code.
## Background
The last project in @ded32 "Computer Architecture" course held in MIPT
## How to run program
!You need to have your code in input folder code.txt!   <br/> 
Just run program in folders tree generate and code generate. Then your executable file will be in output.
## Example
```
  #x = 4;
  #y = 8;
  #z = #x * #y;
```
This code in assembler (nasm) file will look like this:
```
  push rbp
  mov rbp, rsp
  sub rsp, 40
  push rax
  xor rax, rax
  mov rax, 4
  mov [rbp - 8], rax
  pop rax
  push rax
  xor rax, rax
  mov rax, 8
  mov [rbp - 16], rax
  pop rax
  push rax
  xor rax, rax
  mov rax, [rbp - 8]
  push rcx
  push rax
  mov rax, [rbp - 16]
  mov rcx, rax
  pop rax
  mul rcx
  pop rcx
  mov [rbp - 24], rax
  pop rax
  mov rsp, rbp
  pop rbp
```
## Language
I don't think it would be superfluous to know my language. This so easily, because it's similar to c language.
+ if     <=> VTURILAS
+ else   <=> VKRASHILAS
+ while  <=> VLYAPALAS
+ {}     <=> DORA DURA
+ return <=> POSHLU

example of program that calculates factorial:
```
#x = scanf (#x);
#x = fact (#x);
fact (#x)
DORA
    VTURILAS (#x == 0)
    DORA
        POSHLU 1;
    DURA
    POSHLU #x * fact (#x - 1);
DURA;
printf (#x);$
```
## Results
the main task of the project was not only to write a compiler, but also to see how much faster the file is executed on a real processor compared to a virtual one ([click it](https://github.com/armanincredible/CPU)). After test (cycle in 1000000 times what calculates factorial (5)) acceleration was 2172 times.
