/* Nomilia: Linux-ABI file syscall test (openat/write/read/lseek/close). */

        .section .note.ABI-tag, "a"
        .p2align 2
        .long 4                 /* namesz: "GNU\0" */
        .long 16                /* descsz */
        .long 1                 /* type: NT_VERSION */
        .asciz "GNU"
        .long 0                 /* desc: OS number 0 = Linux */
        .long 0
        .long 0
        .long 0

        .section .text
        .globl _start
_start:
        /* openat(AT_FDCWD, path, O_RDWR|O_CREAT|O_TRUNC, 0644) */
        mov $257, %eax
        mov $-100, %edi
        lea .Lpath(%rip), %rsi
        mov $578, %edx          /* 2 | 0100 | 01000 */
        mov $0644, %r10d
        syscall
        cmp $0, %rax
        jl .Lfail
        mov %rax, %rbx          /* fd */

        /* write(fd, msg, len) */
        mov $1, %eax
        mov %rbx, %rdi
        lea .Lmsg(%rip), %rsi
        mov $.Lmsglen, %edx
        syscall
        cmp $.Lmsglen, %rax
        jne .Lfail

        /* close(fd) */
        mov $3, %eax
        mov %rbx, %rdi
        syscall
        cmp $0, %rax
        jl .Lfail

        /* openat(AT_FDCWD, path, O_RDONLY, 0) */
        mov $257, %eax
        mov $-100, %edi
        lea .Lpath(%rip), %rsi
        xor %edx, %edx
        xor %r10d, %r10d
        syscall
        cmp $0, %rax
        jl .Lfail
        mov %rax, %rbx

        /* read(fd, buf, 64) == msglen (position is 0 after open) */
        mov $0, %eax
        mov %rbx, %rdi
        lea .Lbuf(%rip), %rsi
        mov $64, %edx
        syscall
        cmp $.Lmsglen, %rax
        jne .Lfail

        /* verify the roundtrip byte by byte */
        lea .Lbuf(%rip), %rsi
        lea .Lmsg(%rip), %rdi
        xor %ecx, %ecx
.Lcmp:
        mov (%rsi), %dl
        cmp (%rdi), %dl
        jne .Lfail
        inc %rsi
        inc %rdi
        inc %rcx
        cmp $.Lmsglen, %rcx
        jne .Lcmp

        /* lseek(fd, 0, SEEK_END) == msglen */
        mov $8, %eax
        mov %rbx, %rdi
        xor %esi, %esi
        mov $2, %edx
        syscall
        cmp $.Lmsglen, %rax
        jne .Lfail

        /* close */
        mov $3, %eax
        mov %rbx, %rdi
        syscall

        mov $231, %eax          /* SYS_exit_group */
        mov $43, %edi
        syscall

.Lfail:
        mov $231, %eax
        mov $1, %edi
        syscall

        .section .rodata
.Lpath: .asciz "/tmp/nomilia-linux-file"
.Lmsg:  .ascii "linux-abi: file roundtrip\n"
        .equ .Lmsglen, . - .Lmsg

        .section .bss
        .p2align 3
.Lbuf:  .space 64

        .section .note.GNU-stack, "", @progbits
