/* Nomilia: Linux-ABI test for getdents64/ioctl/statx/pipe2/faccessat. */

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
        /* openat(AT_FDCWD, "/tmp", O_RDONLY|O_DIRECTORY, 0) */
        mov $257, %eax
        mov $-100, %edi
        lea .Ldir(%rip), %rsi
        mov $0x10000, %edx
        xor %r10d, %r10d
        syscall
        cmp $0, %rax
        jl .Lfail
        mov %rax, %rbx          /* dirfd */

        /* getdents64(fd, buf, 2048) > 0 */
        mov $217, %eax
        mov %rbx, %rdi
        lea .Ldbuf(%rip), %rsi
        mov $2048, %edx
        syscall
        cmp $0, %rax
        jle .Lfail
        mov %rax, %r12          /* packed bytes */

        /* walk the dirent64 chain: reclen >= 24, 8-aligned, covers ret */
        xor %r13, %r13          /* offset */
        lea .Ldbuf(%rip), %r14
.Lwalk:
        cmp %r12, %r13
        jge .Lwalkdone
        movzwl 16(%r14,%r13,1), %r15d   /* d_reclen */
        cmp $24, %r15d
        jl .Lfail
        test $7, %r15d
        jnz .Lfail
        add %r15, %r13
        cmp %r12, %r13
        jg .Lfail
        jmp .Lwalk
.Lwalkdone:
        /* first entry must carry a nonzero inode */
        cmpq $0, (%r14)
        je .Lfail

        /* close(dirfd) */
        mov $3, %eax
        mov %rbx, %rdi
        syscall
        cmp $0, %rax
        jl .Lfail

        /* ioctl(1, TIOCGWINSZ, ws): 0 with ws_col==80 on the console, or ENOTTY */
        mov $16, %eax
        mov $1, %edi
        mov $0x5413, %esi
        lea .Lws(%rip), %edx
        syscall
        cmp $0, %rax
        je .Lwsok
        cmp $-25, %rax
        jne .Lfail
        jmp .Lwsdone
.Lwsok:
        lea .Lws(%rip), %rax
        movzwl 2(%rax), %ecx    /* ws_col */
        cmp $80, %ecx
        jne .Lfail
.Lwsdone:

        /* pipe2(fds, 0) == 0 */
        mov $293, %eax
        lea .Lpfd(%rip), %rdi
        xor %esi, %esi
        syscall
        cmp $0, %rax
        jne .Lfail

        /* ioctl(pipe fd, TIOCGWINSZ) == -ENOTTY */
        mov $16, %eax
        mov .Lpfd(%rip), %edi
        mov $0x5413, %esi
        lea .Lws(%rip), %edx
        syscall
        cmp $-25, %rax
        jne .Lfail

        /* write(fds[1], "x", 1) == 1 */
        mov $1, %eax
        mov .Lpfd+4(%rip), %edi
        lea .Lmsg(%rip), %rsi
        mov $1, %edx
        syscall
        cmp $1, %rax
        jne .Lfail

        /* read(fds[0], buf, 1) == 1 and buf == 'x' */
        mov $0, %eax
        mov .Lpfd(%rip), %edi
        lea .Lbuf(%rip), %rsi
        mov $1, %edx
        syscall
        cmp $1, %rax
        jne .Lfail
        lea .Lbuf(%rip), %rax
        cmpb $'x', (%rax)
        jne .Lfail

        /* close both pipe fds */
        mov $3, %eax
        mov .Lpfd(%rip), %edi
        syscall
        cmp $0, %rax
        jl .Lfail
        mov $3, %eax
        mov .Lpfd+4(%rip), %edi
        syscall
        cmp $0, %rax
        jl .Lfail

        /* faccessat(AT_FDCWD, "/tmp", F_OK, 0) == 0 */
        mov $269, %eax
        mov $-100, %edi
        lea .Ldir(%rip), %rsi
        xor %edx, %edx
        xor %r10d, %r10d
        syscall
        cmp $0, %rax
        jne .Lfail

        /* faccessat(AT_FDCWD, "/tmp/missing-xyz", F_OK, 0) == -ENOENT */
        mov $269, %eax
        mov $-100, %edi
        lea .Lnope(%rip), %rsi
        xor %edx, %edx
        xor %r10d, %r10d
        syscall
        cmp $-2, %rax
        jne .Lfail

        /* statx(AT_FDCWD, "/tmp", 0, 0xFFF, stbuf) == 0 */
        mov $332, %eax
        mov $-100, %edi
        lea .Ldir(%rip), %rsi
        xor %edx, %edx
        mov $0xfff, %r10d
        lea .Lstbuf(%rip), %r8
        syscall
        cmp $0, %rax
        jne .Lfail

        /* stx_ino != 0, stx_mask has STATX_INO, stx_mode is S_IFDIR */
        lea .Lstbuf(%rip), %rax
        cmpq $0, 0x20(%rax)
        je .Lfail
        testw $0x100, 0(%rax)
        je .Lfail
        movzwl 0x1c(%rax), %ecx
        and $0xF000, %cx
        cmp $0x4000, %cx
        jne .Lfail

        /* exit(46) */
        mov $60, %eax
        mov $46, %edi
        syscall

.Lfail:
        mov $60, %eax
        mov $1, %edi
        syscall

        .section .rodata
.Ldir:  .asciz "/tmp"
.Lnope: .asciz "/tmp/missing-xyz"
.Lmsg:  .ascii "x"

        .section .bss
        .align 8
.Lbuf:  .space 16
.Lws:   .space 8
.Lpfd:  .space 8
.Lstbuf: .space 256
.Ldbuf: .space 2048
