/* Nomilia: static Linux-ABI test binary (raw musl-style syscalls, no libc). */

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
        .type _start, @function
_start:
        mov $1, %eax            /* SYS_write */
        mov $1, %edi            /* stdout */
        lea .Lmsg(%rip), %rsi
        mov $.Lmsglen, %edx
        syscall
        mov $231, %eax          /* SYS_exit_group */
        mov $42, %edi
        syscall
        mov $60, %eax           /* SYS_exit, unreachable */
        xor %edi, %edi
        syscall

        .section .rodata
.Lmsg:  .ascii "linux-abi: hello from an unmodified Linux syscall persona\n"
        .equ .Lmsglen, . - .Lmsg

        .section .note.GNU-stack, "", @progbits
