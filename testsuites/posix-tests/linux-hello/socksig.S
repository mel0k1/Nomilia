/* Nomilia: Linux-ABI test for socketpair roundtrip and rt_sigaction/
 * rt_sigprocmask with a handler delivered through an rt_sigframe and
 * returned from via rt_sigreturn. Exit codes: 47 = success, otherwise
 * the failing step: 65 socketpair, 66 write, 67 read, 68 payload,
 * 69 close, 70 rt_sigaction, 71 rt_sigprocmask, 72 kill,
 * 73 handler timeout, 74 getsockname, 75 sockname family. */

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
        /* socketpair(AF_UNIX, SOCK_STREAM, 0, sv) */
        mov $53, %eax
        mov $1, %edi
        mov $1, %esi
        xor %edx, %edx
        lea .Lsv(%rip), %r10
        syscall
        test %rax, %rax
        jnz .Lf65

        /* write(sv[0], "ping", 4) */
        mov $1, %eax
        movl .Lsv(%rip), %edi
        lea .Lmsg(%rip), %rsi
        mov $4, %edx
        syscall
        cmp $4, %rax
        jne .Lf66

        /* read(sv[1], buf, 16) */
        mov $0, %eax
        movl .Lsv+4(%rip), %edi
        lea .Lbuf(%rip), %rsi
        mov $16, %edx
        syscall
        cmp $4, %rax
        jne .Lf67
        cmpl $0x676e6970, .Lbuf(%rip)   /* "ping" */
        jne .Lf68

        /* getsockname(sv[1], addr, &addrlen): unnamed unix socket */
        mov $51, %eax
        movl .Lsv+4(%rip), %edi
        lea .Laddr(%rip), %rsi
        lea .Laddrlen(%rip), %rdx
        syscall
        test %rax, %rax
        jnz .Lf74
        cmpw $1, .Laddr(%rip)           /* AF_UNIX */
        jne .Lf75

        /* close both ends */
        mov $3, %eax
        movl .Lsv(%rip), %edi
        syscall
        test %rax, %rax
        jnz .Lf69
        mov $3, %eax
        movl .Lsv+4(%rip), %edi
        syscall
        test %rax, %rax
        jnz .Lf69

        /* rt_sigaction(SIGUSR1, {handler, SA_RESTORER, restore, 0}, 0, 8) */
        mov $13, %eax
        mov $10, %edi
        lea .Lact(%rip), %rsi
        xor %edx, %edx
        mov $8, %r10
        syscall
        test %rax, %rax
        jnz .Lf70

        /* rt_sigprocmask(SIG_SETMASK, {0}, &old, 8) */
        mov $14, %eax
        mov $2, %edi
        lea .Lempty(%rip), %rsi
        lea .Lold(%rip), %rdx
        mov $8, %r10
        syscall
        test %rax, %rax
        jnz .Lf71

        /* kill(getpid(), SIGUSR1): the handler bumps .Lflag */
        mov $39, %eax
        syscall
        mov %eax, %r15d
        mov $62, %eax
        mov %r15d, %edi
        mov $10, %esi
        syscall
        test %rax, %rax
        jnz .Lf72

        /* bounded wait for the handler */
        mov $500000, %r13
.Lwait:
        cmpq $0, .Lflag(%rip)
        jne .Lhandok
        mov $24, %eax           /* sched_yield */
        syscall
        dec %r13
        jnz .Lwait
        jmp .Lf73

.Lhandok:
        mov $47, %edi
        jmp .Lexit

.Lf65:
        mov $65, %edi
        jmp .Lexit
.Lf66:
        mov $66, %edi
        jmp .Lexit
.Lf67:
        mov $67, %edi
        jmp .Lexit
.Lf68:
        mov $68, %edi
        jmp .Lexit
.Lf69:
        mov $69, %edi
        jmp .Lexit
.Lf70:
        mov $70, %edi
        jmp .Lexit
.Lf71:
        mov $71, %edi
        jmp .Lexit
.Lf72:
        mov $72, %edi
        jmp .Lexit
.Lf73:
        mov $73, %edi
        jmp .Lexit
.Lf74:
        mov $74, %edi
        jmp .Lexit
.Lf75:
        mov $75, %edi
.Lexit:
        mov $60, %eax           /* exit_group */
        syscall

        /* Linux signal handler: write(1, "H", 1), set flag, return to the
         * SA_RESTORER trampoline which issues rt_sigreturn. */
.Lhandler:
        mov $1, %eax
        mov $1, %edi
        lea .LmsgH(%rip), %rsi
        mov $1, %edx
        syscall
        movq $1, .Lflag(%rip)
        ret
.Lrestore:
        mov $15, %eax
        syscall

        .section .rodata
.Lmsg:  .ascii "ping"
.LmsgH: .ascii "H"
.Lact:  .quad .Lhandler
        .quad 0x04000000        /* SA_RESTORER */
        .quad .Lrestore
        .quad 0

        .section .data
        .align 8
.Lsv:   .space 8
.Lbuf:  .space 16
.Laddr: .space 16
.Laddrlen: .long 16
.Lempty: .quad 0
.Lold:  .quad 0
.Lflag: .quad 0
