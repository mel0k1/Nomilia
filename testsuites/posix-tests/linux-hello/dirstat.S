/* Nomilia: Linux-ABI test for getdents64/ioctl/statx/pipe2/faccessat.
 * Exit codes: 46 = success, otherwise the failing step:
 * 50 openat, 51 getdents64 ret, 52 dirent chain, 53 first d_ino,
 * 54 close, 55 ioctl console, 56 pipe2, 57 ioctl pipe, 58 write,
 * 59 read, 60 pipe close, 61 faccessat existing, 62 faccessat missing,
 * 63 statx call, 64 statx fields. */

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
        jl .Lf50
        mov %rax, %rbx          /* dirfd */

        /* getdents64(fd, buf, 2048) > 0 */
        mov $217, %eax
        mov %rbx, %rdi
        lea .Ldbuf(%rip), %rsi
        mov $2048, %edx
        syscall
        cmp $0, %rax
        jle .Lf51
        mov %rax, %r12          /* packed bytes */

        /* walk the dirent64 chain: reclen >= 24, 8-aligned, covers ret */
        xor %r13, %r13          /* offset */
        lea .Ldbuf(%rip), %r14
.Lwalk:
        cmp %r12, %r13
        jge .Lwalkdone
        movzwl 16(%r14,%r13,1), %r15d   /* d_reclen */
        cmp $24, %r15d
        jl .Lf52
        test $7, %r15d
        jnz .Lf52
        add %r15, %r13
        cmp %r12, %r13
        jg .Lf52
        jmp .Lwalk
.Lwalkdone:
        /* first entry must carry a nonzero inode */
        cmpq $0, (%r14)
        je .Lf53

        /* close(dirfd) */
        mov $3, %eax
        mov %rbx, %rdi
        syscall
        cmp $0, %rax
        jl .Lf54

        /* ioctl(1, TIOCGWINSZ, ws): 0 with ws_col==80 on the console, or ENOTTY */
        mov $16, %eax
        mov $1, %edi
        mov $0x5413, %esi
        lea .Lws(%rip), %edx
        syscall
        cmp $0, %rax
        je .Lwsok
        cmp $-25, %rax
        jne .Lf55
        jmp .Lwsdone
.Lwsok:
        lea .Lws(%rip), %rax
        movzwl 2(%rax), %ecx    /* ws_col */
        cmp $80, %ecx
        jne .Lf55
.Lwsdone:

        /* pipe2(fds, 0) == 0 */
        mov $293, %eax
        lea .Lpfd(%rip), %rdi
        xor %esi, %esi
        syscall
        cmp $0, %rax
        jne .Lf56

        /* ioctl(pipe fd, TIOCGWINSZ) == -ENOTTY */
        mov $16, %eax
        mov .Lpfd(%rip), %edi
        mov $0x5413, %esi
        lea .Lws(%rip), %edx
        syscall
        cmp $-25, %rax
        jne .Lf57

        /* write(fds[1], "x", 1) == 1 */
        mov $1, %eax
        mov .Lpfd+4(%rip), %edi
        lea .Lmsg(%rip), %rsi
        mov $1, %edx
        syscall
        cmp $1, %rax
        jne .Lf58

        /* read(fds[0], buf, 1) == 1 and buf == 'x' */
        mov $0, %eax
        mov .Lpfd(%rip), %edi
        lea .Lbuf(%rip), %rsi
        mov $1, %edx
        syscall
        cmp $1, %rax
        jne .Lf59
        lea .Lbuf(%rip), %rax
        cmpb $'x', (%rax)
        jne .Lf59

        /* close both pipe fds */
        mov $3, %eax
        mov .Lpfd(%rip), %edi
        syscall
        cmp $0, %rax
        jl .Lf60
        mov $3, %eax
        mov .Lpfd+4(%rip), %edi
        syscall
        cmp $0, %rax
        jl .Lf60

        /* faccessat(AT_FDCWD, "/tmp", F_OK, 0) == 0 */
        mov $269, %eax
        mov $-100, %edi
        lea .Ldir(%rip), %rsi
        xor %edx, %edx
        xor %r10d, %r10d
        syscall
        cmp $0, %rax
        jne .Lf61

        /* faccessat(AT_FDCWD, "/tmp/missing-xyz", F_OK, 0) == -ENOENT */
        mov $269, %eax
        mov $-100, %edi
        lea .Lnope(%rip), %rsi
        xor %edx, %edx
        xor %r10d, %r10d
        syscall
        cmp $-2, %rax
        jne .Lf62

        /* statx(AT_FDCWD, "/tmp", 0, 0xFFF, stbuf) == 0 */
        mov $332, %eax
        mov $-100, %edi
        lea .Ldir(%rip), %rsi
        xor %edx, %edx
        mov $0xfff, %r10d
        lea .Lstbuf(%rip), %r8
        syscall
        cmp $0, %rax
        jne .Lf63

        /* stx_ino != 0, stx_mask has STATX_INO, stx_mode is S_IFDIR */
        lea .Lstbuf(%rip), %rax
        cmpq $0, 0x20(%rax)
        je .Lf64
        testw $0x100, 0(%rax)
        je .Lf64
        movzwl 0x1c(%rax), %ecx
        and $0xF000, %cx
        cmp $0x4000, %cx
        jne .Lf64

        /* exit(46) */
        mov $60, %eax
        mov $46, %edi
        syscall

.Lf50:
        mov $50, %edi
        jmp .Lexit
.Lf51:
        mov $51, %edi
        jmp .Lexit
.Lf52:
        mov $52, %edi
        jmp .Lexit
.Lf53:
        mov $53, %edi
        jmp .Lexit
.Lf54:
        mov $54, %edi
        jmp .Lexit
.Lf55:
        mov $55, %edi
        jmp .Lexit
.Lf56:
        mov $56, %edi
        jmp .Lexit
.Lf57:
        mov $57, %edi
        jmp .Lexit
.Lf58:
        mov $58, %edi
        jmp .Lexit
.Lf59:
        mov $59, %edi
        jmp .Lexit
.Lf60:
        mov $60, %edi
        jmp .Lexit
.Lf61:
        mov $61, %edi
        jmp .Lexit
.Lf62:
        mov $62, %edi
        jmp .Lexit
.Lf63:
        mov $63, %edi
        jmp .Lexit
.Lf64:
        mov $64, %edi
.Lexit:
        mov $60, %eax
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
