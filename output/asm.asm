section .text
global _start
_start:
push rbp
mov rbp, rsp
sub rsp, 448
push rax
xor rax, rax
mov rax, 0
mov [rbp - 8], rax
pop rax
push rax
xor rax, rax
mov rax, 0
mov [rbp - 16], rax
pop rax
push rax
xor rax, rax
mov rax, 0
mov [rbp - 24], rax
pop rax
push rax
xor rax, rax
mov rax, [rbp - 8]
push rax
call pop rbx
mov [rbp - 8], rax
pop rax
push rax
xor rax, rax
mov rax, [rbp - 16]
push rax
call pop rbx
mov [rbp - 16], rax
pop rax
push rax
xor rax, rax
mov rax, [rbp - 24]
push rax
call pop rbx
mov [rbp - 24], rax
pop rax
push rax
xor rax, rax
mov rax, [rbp - 24]
push rax
mov rax, [rbp - 16]
push rax
mov rax, [rbp - 8]
push rax
call CalcDiscr
pop rbx
pop rbx
pop rbx
mov [rbp - 32], rax
pop rax
mov rax, [rbp - 32]
push rax
call pop rbx
mov rax, [rbp - 32]
mov rcx, rax
mov rax, 0
cmp rcx, rax
jne else1
push rax
xor rax, rax
mov rax, [rbp - 16]
push rax
mov rax, [rbp - 8]
push rax
call CalcOnlyOneRoot
pop rbx
pop rbx
mov [rbp - 40], rax
pop rax
mov rax, [rbp - 40]
push rax
call pop rbx
jmp skipall1
else1:
mov rax, [rbp - 32]
mov rcx, rax
mov rax, 0
cmp rcx, rax
jbe skipall2
push rax
xor rax, rax
mov rax, [rbp - 32]
push rax
call pop rbx
mov [rbp - 48], rax
pop rax
mov rax, [rbp - 48]
push rax
call pop rbx
push rax
xor rax, rax
mov rax, [rbp - 48]
push rax
mov rax, [rbp - 16]
push rax
mov rax, [rbp - 8]
push rax
call CalcFirstRoot
pop rbx
pop rbx
pop rbx
mov [rbp - 56], rax
pop rax
push rax
xor rax, rax
mov rax, [rbp - 48]
push rax
mov rax, [rbp - 16]
push rax
mov rax, [rbp - 8]
push rax
call CalcSecRoot
pop rbx
pop rbx
pop rbx
mov [rbp - 64], rax
pop rax
mov rax, [rbp - 56]
push rax
call pop rbx
mov rax, [rbp - 64]
push rax
call pop rbx
skipall2:
skipall1:
jmp skipCalcDiscr
CalcDiscr:
push rbp
mov rbp, rsp
sub rsp, 32
mov rax, [rbp + 24]
push rcx
push rax
mov rax, [rbp + 24]
mov rcx, rax
pop rax
mul rcx
pop rcx
push rcx
push rax
mov rax, 4
push rcx
push rax
mov rax, [rbp + 16]
mov rcx, rax
pop rax
mul rcx
pop rcx
push rcx
push rax
mov rax, [rbp + 32]
mov rcx, rax
pop rax
mul rcx
pop rcx
mov rcx, rax
pop rax
sub rax, rcx
pop rcx
mov rsp, rbp
pop rbp
ret
skipCalcDiscr:
jmp skipCalcOnlyOneRoot
CalcOnlyOneRoot:
push rbp
mov rbp, rsp
sub rsp, 16
mov rax, 0
push rcx
push rax
mov rax, [rbp + 24]
push rcx
push rax
mov rax, 1000
mov rcx, rax
pop rax
mul rcx
pop rcx
push rcx
push rax
mov rax, 2
push rcx
push rax
mov rax, [rbp + 16]
mov rcx, rax
pop rax
mul rcx
pop rcx
mov rcx, rax
pop rax
xor rdx, rdx
div rcx
pop rcx
mov rcx, rax
pop rax
sub rax, rcx
pop rcx
mov rsp, rbp
pop rbp
ret
skipCalcOnlyOneRoot:
jmp skipCalcFirstRoot
CalcFirstRoot:
push rbp
mov rbp, rsp
sub rsp, 24
mov rax, 0
push rcx
push rax
mov rax, [rbp + 24]
push rcx
push rax
mov rax, [rbp + 32]
mov rcx, rax
pop rax
add rax, rcx
pop rcx
push rcx
push rax
mov rax, 1000
mov rcx, rax
pop rax
mul rcx
pop rcx
push rcx
push rax
mov rax, 2
push rcx
push rax
mov rax, [rbp + 16]
mov rcx, rax
pop rax
mul rcx
pop rcx
mov rcx, rax
pop rax
xor rdx, rdx
div rcx
pop rcx
mov rcx, rax
pop rax
sub rax, rcx
pop rcx
mov rsp, rbp
pop rbp
ret
skipCalcFirstRoot:
jmp skipCalcSecRoot
CalcSecRoot:
push rbp
mov rbp, rsp
sub rsp, 24
mov rax, 0
push rcx
push rax
mov rax, [rbp + 24]
push rcx
push rax
mov rax, [rbp + 32]
mov rcx, rax
pop rax
sub rax, rcx
pop rcx
push rcx
push rax
mov rax, 1000
mov rcx, rax
pop rax
mul rcx
pop rcx
push rcx
push rax
mov rax, 2
push rcx
push rax
mov rax, [rbp + 16]
mov rcx, rax
pop rax
mul rcx
pop rcx
mov rcx, rax
pop rax
xor rdx, rdx
div rcx
pop rcx
mov rcx, rax
pop rax
sub rax, rcx
pop rcx
mov rsp, rbp
pop rbp
ret
skipCalcSecRoot:
mov rsp, rbp
pop rbp
mov rax, 1
xor rbx, rbx
int 0x80
