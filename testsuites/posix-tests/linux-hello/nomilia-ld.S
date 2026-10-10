/* Nomilia: minimal Linux-ABI ELF interpreter for the dynamic-binary test.
 * Reads the initial stack (argc, argv, envp, auxv), takes AT_ENTRY and
 * jumps to the main program's entry point. No syscalls on the happy path. */

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
        cld
        mov %rsp, %rsi
        add $8, %rsi            /* skip argc, rsi = &argv[0] */
.Lscan1:
        lodsq
        test %rax, %rax
        jnz .Lscan1             /* end of argv */
.Lscan2:
        lodsq
        test %rax, %rax
        jnz .Lscan2             /* end of envp */
.Lauxv:
        lodsq                   /* a_type */
        test %rax, %rax
        jz .Lnoentry            /* AT_NULL */
        mov %rax, %r8
        lodsq                   /* a_val */
        cmp $9, %r8             /* AT_ENTRY */
        jne .Lauxv
        jmp *%rax

.Lnoentry:
        mov $49, %edi
        mov $60, %eax
        syscall
