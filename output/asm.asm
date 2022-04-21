section .text
global _start
_start:
push rbp
mov rbp, rsp
sub rsp, 56
push rax
xor rax, rax
mov rax, 3
mov [rbp - 8], rax
pop rax
push rax
xor rax, rax
mov rax, [rbp - 8]
push rax
call fact
pop rbx
mov [rbp - 8], rax
pop rax
jmp skipfact
fact :
push rbp
mov rbp, rsp
sub rsp, 32
mov rax, [rbp + 16]
mov rcx, rax
mov rax, 0
cmp rcx, rax
jne skipall1
mov rax, 1
mov rsp, rbp
pop rbp
ret
skipall1:
mov rax, [rbp + 16]
push rcx
push rax
mov rax, [rbp + 16]
push rcx
push rax
mov rax, 1
mov rcx, rax
pop rax
sub rax, rcx
pop rcx
push rax
call fact
pop rbx
mov rcx, rax
pop rax
mul rcx
pop rcx
mov rsp, rbp
pop rbp
ret
skipfact:
mov rsp, rbp
pop rbp
mov rax, 1
xor rbx, rbx
int 0x80
