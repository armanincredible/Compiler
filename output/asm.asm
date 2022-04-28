section .text
global _start
_start:
push rbp
mov rbp, rsp
sub rsp, 72
push rax
xor rax, rax
push rbp
mov rax, [rbp - 8]
push rax
call pop rbx
pop rbp
mov [rbp - 8], rax
pop rax
push rax
xor rax, rax
push rbp
mov rax, [rbp - 8]
push rax
call fact
pop rbx
pop rbp
mov [rbp - 8], rax
pop rax
jmp skipfact
fact:
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
push rbp
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
pop rbp
mov rcx, rax
pop rax
mul rcx
pop rcx
mov rsp, rbp
pop rbp
ret
skipfact:
push rbp
mov rax, [rbp - 8]
push rax
call pop rbx
pop rbp
mov rsp, rbp
pop rbp
mov rax, 1
xor rbx, rbx
int 0x80
