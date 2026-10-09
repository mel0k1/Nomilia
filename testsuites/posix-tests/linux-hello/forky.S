/* Nomilia: Linux-ABI fork/wait4 test inside the Linux personality. */

        .section .note.ABI-tag, "a"
        .p2align 2
        .long 4
        .long 16
        .long 1
        .asciz "GNU"
        .long 0
        .long 0
        .long 0
        .long 0

        .section .text
        .globl _start
_start:
        mov $57, %eax           /* SYS_fork */
        syscall
        cmp $0, %rax
        jl .Lfail
        je .Lchild

        /* parent: wait4(-1, &status, 0, NULL) */
        mov $61, %eax
        mov $-1, %edi
        lea .Lstatus(%rip), %rsi
        xor %edx, %edx
        xor %r10d, %r10d
        syscall
        cmp $0, %rax
        jl .Lfail

        /* WEXITSTATUS(status) == 44 -> exit 45 */
        mov .Lstatus(%rip), %eax
        shr $8, %eax
        and $0xff, %eax
        cmp $44, %eax
        jne .Lfail

        mov $231, %eax
        mov $45, %edi
        syscall

.Lchild:
        /* child: write(1, msg, len) then exit(44) */
        mov $1, %eax
        mov $1, %edi
        lea .Lcmsg(%rip), %rsi
        mov $.Lcmsglen, %edx
        syscall
        mov $231, %eax
        mov $44, %edi
        syscall

.Lfail:
        mov $231, %eax
        mov $1, %edi
        syscall

        .section .rodata
.Lcmsg: .ascii "linux-abi: child of a Linux fork\n"
        .equ .Lcmsglen, . - .Lcmsg

        .section .bss
.Lstatus: .space 4

        .section .note.GNU-stack, "", @progbits
