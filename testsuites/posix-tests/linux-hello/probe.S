/* Nomilia: Linux-ABI startup probe. Raw syscalls in the order musl's static
   startup issues them, each preceded by a "pNN" marker on stdout so a system
   death in CI names the killer syscall. Exits 49 when everything passes. */

        .section .text
        .globl _start
        .type _start, @function
_start:
        /* p1: set_tid_address(&lock) — posix upcall */
        lea .Lm1(%rip), %rsi
        call .Lmark
        mov $218, %eax
        lea .Ltidbuf(%rip), %edi
        syscall

        /* p2: arch_prctl(ARCH_SET_FS, tcb) — thor */
        lea .Lm2(%rip), %rsi
        call .Lmark
        mov $158, %eax
        mov $0x1002, %edi
        lea .Ltcb(%rip), %rsi
        syscall
        movq $0x1234, %fs:0     /* TLS write sanity */

        /* p3: mmap(NULL, 0x40000, RW, PRIVATE|ANON, -1, 0) — thor */
        lea .Lm3(%rip), %rsi
        call .Lmark
        mov $9, %eax
        xor %edi, %edi
        mov $0x40000, %esi
        mov $3, %edx
        mov $0x22, %r10d
        mov $-1, %r8
        xor %r9d, %r9d
        syscall
        mov %rax, .Lmapptr(%rip)

        /* p4: mprotect(map, 0x1000, PROT_READ) — thor */
        lea .Lm4(%rip), %rsi
        call .Lmark
        mov $10, %eax
        mov .Lmapptr(%rip), %rdi
        mov $0x1000, %esi
        mov $1, %edx
        syscall

        /* p5: munmap(map+0x20000, 0x20000) — thor */
        lea .Lm5(%rip), %rsi
        call .Lmark
        mov $11, %eax
        mov .Lmapptr(%rip), %rdi
        add $0x20000, %rdi
        mov $0x20000, %esi
        syscall

        /* p6: brk(0) then brk(cur + 0x4000) — thor */
        lea .Lm6(%rip), %rsi
        call .Lmark
        mov $12, %eax
        xor %edi, %edi
        syscall
        add $0x4000, %rax
        mov $12, %eax
        mov %rax, %rdi
        syscall

        /* p7: writev(1, iov{2}) — posix upcall */
        lea .Lm7(%rip), %rsi
        call .Lmark
        mov $20, %eax
        mov $1, %edi
        lea .Lwiov(%rip), %rsi
        mov $2, %edx
        syscall

        /* p8: openat(AT_FDCWD, "/dev/null") — posix upcall */
        lea .Lm8(%rip), %rsi
        call .Lmark
        mov $257, %eax
        mov $-100, %edi
        lea .Ldevnull(%rip), %rsi
        xor %edx, %edx
        xor %r10d, %r10d
        syscall
        mov %eax, %r15d         /* fd */

        /* p9: readv(fd, iov{1}) — posix upcall */
        lea .Lm9(%rip), %rsi
        call .Lmark
        mov $19, %eax
        mov %r15d, %edi
        lea .Lriov(%rip), %rsi
        mov $1, %edx
        syscall

        /* p10: close(fd) — posix upcall */
        lea .Lm10(%rip), %rsi
        call .Lmark
        mov $3, %eax
        mov %r15d, %edi
        syscall

        /* p11: uname(&uts) — thor */
        lea .Lm11(%rip), %rsi
        call .Lmark
        mov $63, %eax
        lea .Luts(%rip), %rdi
        syscall

        /* p12: clock_gettime(CLOCK_REALTIME, &ts) — thor */
        lea .Lm12(%rip), %rsi
        call .Lmark
        mov $228, %eax
        xor %edi, %edi
        lea .Lts(%rip), %rsi
        syscall

        /* p13: getrandom(&buf, 16, 0) — thor */
        lea .Lm13(%rip), %rsi
        call .Lmark
        mov $318, %eax
        lea .Lrnd(%rip), %rdi
        mov $16, %esi
        xor %edx, %edx
        syscall

        /* p14: ioctl(1, TCGETS, &termios) — posix upcall */
        lea .Lm14(%rip), %rsi
        call .Lmark
        mov $16, %eax
        mov $1, %edi
        mov $0x5401, %esi
        lea .Ltermios(%rip), %rdx
        syscall

        lea .Ldone(%rip), %rsi
        call .Lmark
        mov $231, %eax          /* SYS_exit_group */
        mov $49, %edi
        syscall
        mov $60, %eax           /* SYS_exit, unreachable */
        xor %edi, %edi
        syscall

        /* .Lmark: write(1, %rsi, 4); clobbers rax/rcx/r11/rdi/rdx */
.Lmark:
        mov $1, %eax
        mov $1, %edi
        mov $4, %edx
        syscall
        ret

        .section .rodata
.Lm1:   .ascii "p1\n"
.Lm2:   .ascii "p2\n"
.Lm3:   .ascii "p3\n"
.Lm4:   .ascii "p4\n"
.Lm5:   .ascii "p5\n"
.Lm6:   .ascii "p6\n"
.Lm7:   .ascii "p7\n"
.Lm8:   .ascii "p8\n"
.Lm9:   .ascii "p9\n"
.Lm10:  .ascii "pa\n"
.Lm11:  .ascii "pb\n"
.Lm12:  .ascii "pc\n"
.Lm13:  .ascii "pd\n"
.Lm14:  .ascii "pe\n"
.Ldone: .ascii "probe-done\n"
.Ldevnull: .asciz "/dev/null"

        .section .bss
        .align 64
.Ltcb:  .skip 64
.Ltidbuf: .skip 8
.Lmapptr: .skip 8
.Luts:  .skip 400
.Lts:   .skip 16
.Lrnd:  .skip 16
.Ltermios: .skip 64

        .section .data
        .align 16
.Lwiov: .quad .Ldone, 11, .Lm1, 3
.Lriov: .quad .Lrnd, 16

        .section .note.GNU-stack, "", @progbits
