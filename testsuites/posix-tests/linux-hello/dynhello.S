/* Nomilia: minimal dynamic Linux ELF (PT_INTERP + PT_DYNAMIC, no deps,
 * no relocations). The interpreter (nomilia-ld.so) jumps straight to the
 * entry point; this program only proves the chain: write + exit_group. */

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

        .section .interp, "a"
        .asciz "/tmp/nomilia-ld.so"

        .section .dynamic, "aw"
        .p2align 3
        .quad 0                 /* DT_NULL */
        .quad 0

        .section .text
        .globl _start
_start:
        mov $1, %eax            /* write(1, msg, 12) */
        mov $1, %edi
        lea .Lmsg(%rip), %rsi
        mov $12, %edx
        syscall

        mov $48, %edi           /* exit_group(48) */
        mov $231, %eax
        syscall

        .section .rodata
.Lmsg:  .ascii "dyn hello\n"
