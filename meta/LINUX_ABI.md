# Linux ABI: слой linux-sysdeps (v1 + v2 + v3 + v4)

Цель — исполнять **немодифицированные** Linux-бинарники (в первую очередь статические musl: busybox)
без пересборки и без патчей к бинарникам. v1 — диспетчер в ядре thor: «сырой» Linux-номер
исполняется поверх внутренних примитивов thor (`AllocatedMemory`, `VirtualSpace`, `FutexRealm`,
MSR FS/GS, PRNG). v2 (фаза 2) — файловые и процессные сисколлы через upcall в posix-подсистему
(см. раздел «Фаза 2» ниже).

## Как работает

### 1. Детект Linux-ELF на exec (posix-подсистема)

`posix/subsystem/src/exec.cpp`, `loadElfImage()` при разборе program headers помечает образ:

- `PT_INTERP` начинается с `ld-linux-` (glibc) или `ld-musl-` (musl) → Linux;
- `PT_NOTE` содержит note с name `GNU`, type `NT_VERSION` (1) и первым словом дескриптора `0`
  (OS number = Linux, формат `.note.ABI-tag`) → Linux.

Динамические Linux-бинарники пока отвергаются (`badExecutable`) — их ld.so требует файловых
сисколлов, которых в v1 нет. Статические идут дальше.

### 2. Personality-флаг процесса (Hel ABI)

Новый `kHelAbiLinux = 2` (рядом с `kHelAbiSystemV`). Новый Hel-верб не понадобился: у
`helCreateThread()` всегда был параметр `abi`, который thor игнорировал — теперь при
`abi == kHelAbiLinux` на поток ставится флаг `Thread::kFlagLinuxPersonality` (бит 2 в публичном
поле `Thread::flags`). `exec.cpp` передаёт этот abi для детектированных Linux-образов
(только x86_64; вход в программу — собственный `e_entry`, без ld.so).

Флаг на потоке, а не на «процессе»: в thor процесса нет (это конвенция posix-подсистемы из
universe + VmContext + потоков). Для v1 (однопоточные Linux-программы) этого достаточно;
наследование при clone — пункт фазы 2.

### 3. Диспетчер сисколлов (thor)

`kernel/thor/generic/main.cpp`, `handleSyscall()`: сразу после чтения текущего потока —

```cpp
if(this_thread->flags & Thread::kFlagLinuxPersonality) {
    linuxHandleSyscall(image);
    Thread::handleConditions(image);
    return;
}
```

Вся реализация — новый файл `kernel/thor/generic/linux-abi.cpp` (+ `thor-internal/linux-abi.hpp`).

### Регистровая конвенция

Managarm-Hel и Linux x86_64 по-разному кладут аргументы syscall'а, поэтому чтение идёт по
слотам `SyscallImageAccessor`:

| Смысл              | Hel          | Linux x86_64 | Слот аксессора |
|--------------------|--------------|--------------|----------------|
| номер              | RDI          | RAX          | `in2()`        |
| arg0               | RSI          | RDI          | `number()`     |
| arg1               | RDX          | RSI          | `in0()`        |
| arg2               | RAX          | RDX          | `in1()`        |
| arg3               | R8           | R10          | `in5()`        |
| arg4               | R9           | R8           | `in3()`        |
| arg5               | R10          | R9           | `in4()`        |

Результат (или `-errno`) возвращается в RAX (`*image.in2()`); rcx/r11 портятся, как и положено
в Linux. Оба соглашения сосуществуют без конфликтов номеров, потому что различаются по флагу
personality, а не по диапазону номеров.

## Реализованные сисколлы (v1, x86_64)

| nr  | сисколл       | статус | примечание |
|-----|---------------|--------|------------|
| 1   | write         | v2 | fd-путь через posix-подсистему (upcall) |
| 9   | mmap          | да | анонимные private-маппинги; MAP_FIXED уважается; file-backed → `-ENOSYS` |
| 10  | mprotect      | да | через `VirtualSpace::protect` |
| 11  | munmap        | да | |
| 12  | brk           | да | per-AS состояние, база 0x10000000, лимит 128 МиБ; при ошибке — текущий brk (семантика Linux) |
| 24  | sched_yield   | да | `Thread::deferCurrent()` |
| 28  | madvise       | да | no-op |
| 39/186 | getpid/gettid | v2 | настоящие pid/tid через posix (upcall) |
| 63  | uname         | да | `Linux/nomilia/6.1.0-nomilia/x86_64` — совместимо с mlibc-форком |
| 96  | gettimeofday  | частично | monotonic-время; wall-clock смещение — TODO |
| 102–108 | getuid/euid/gid/egid | заглушка | 0 |
| 60/231 | exit/exit_group | да | `Thread::dispose()` → terminate-условие → `handleConditions()` |
| 158 | arch_prctl    | да | ARCH_SET_FS/GET_FS/SET_GS через MSR; FS base корректно сохраняется при вытеснении |
| 201 | time          | частично | как gettimeofday |
| 202 | futex         | да | WAIT (с относительным таймаутом), WAKE, REQUEUE, CMP_REQUEUE — поверх `FutexRealm` (включая нашу `helFutexRequeue`); PRIVATE/REALTIME флаги разбираются |
| 218 | set_tid_address | заглушка | адрес запоминается, возврат 1 |
| 228/229 | clock_gettime/getres | частично | REALTIME/MONOTONIC/RAW/BOOTTIME; wall-clock — TODO |
| 273 | set_robust_list | да | no-op |
| 318 | getrandom     | да | `generateRandomBytes`, ≤128 байт за вызов |
| остальное | — | `-ENOSYS` | с логом `linux-abi: unimplemented syscall N` |

## Приёмочный тест

`testsuites/posix-tests/src/linux-abi.cpp` + `linux-hello/hello.S` (собирается freestanding-ELF
тем же кросс-компилятором, `-nostdlib -static -no-pie -Ttext=0x400000`, с GNU ABI-tag note) —
бинарник без единого байта libc. Тест: запись блоба в `/tmp`, `chmod 0755`, `fork` + `execve`,
родитель ждёт `exit(42)`. Проверяет всю цепочку: детект → personality → свой entry → write →
exit_group → waitpid. Запускается в QEMU как часть `ci-posix-tests`.

## Фаза 2: файловые и процессные сисколлы через upcall в posix (v2)

VFS posix-подсистемы уже умеет всё нужное (PathResolver, file table, pipe/tty/socket-файлы), поэтому
второй вертикальный срез не дублирует её в ядре, а делегирует ей операции. Канал — **не** новое
bragi-сообщение, а штатный observe-канал, которым thor и posix уже обмениваются событиями потоков:

1. thor (`linux-abi.cpp`): файловые/процессные Linux-номера попадают в passthrough-блок — регистры
   **не трогаются** (nr остаётся в RAX, аргументы в RDI/RSI/RDX/R10/R8/R9), поток прерывается
   `Thread::interruptCurrent(kIntrSuperCall + posix::superLinuxSyscall)` и уходит в суперколл-состояние;
2. posix (`observations.cpp`): `observeThread` получает `kHelObserveSuperCall + superLinuxSyscall`,
   читает gprs (`kHelRegArg2` = nr и т.д.) и вызывает `handleLinuxSyscall()`
   (`posix/subsystem/src/linux-abi.cpp`);
3. обработчик транслирует вызов в обычные POSIX/VFS API процесса (`fileContext()`, `fsContext()`,
   `PathResolver`, `helix_ng::readMemory/writeMemory` для буферов/путей) и возвращает
   `LinuxSyscallOutcome{resume, value}`;
4. posix пишет `gprs[kHelRegArg2] = value` (Linux-результат или `-errno` в RAX),
   `gprs[kHelRegError] = kHelErrNone` и делает `helStoreRegisters` + `helResume` — поток
   продолжается с возврата из сисколла.

Особые пути: `fork/vfork` клонируют процесс (`Process::fork`), копируют program/thread-регистры
ребёнку, ставят ребёнку RAX=0, резюмят обоих (родитель получает pid); `execve` читает path/argv/envp
из памяти процесса и запускает `Process::exec` (он сам убивает старый поток, строит новый образ и
резюмит — при успехе upcall-резюм не нужен); `wait4` блокирует волокно observeThread процесса на
`Process::wait` (штатный notify-механизм, дети других процессов не блокируются).

Personality наследуется: `Process` хранит `linuxPersonality` (поле + `isLinuxPersonality()`), её
проставляет `ExecuteResult.isLinux` из детекта в `exec.cpp`; `Process::fork`/`Process::clone`
создают поток ребёнка с `kHelAbiLinux` вместо `kHelAbiSystemV`, ядро выставляет
`Thread::kFlagLinuxPersonality` — и Linux-потоки переживают fork/clone без особых путей.

Реализовано (x86_64): open(2)/openat(257) с Linux-флагами (O_CREAT/O_EXCL/O_TRUNC/O_APPEND/
O_NONBLOCK/O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC/O_PATH), read/write/close, lseek, stat/lstat/fstat/
fstatat (Linux `struct stat`, 144 байта), pread64/pwrite64, dup/dup2/dup3, getpid/getppid/gettid,
getcwd, fork/vfork/execve/wait4. Ошибки — Linux-errno (отрицательные значения в RAX).

Приёмочные тесты: `linux_abi_files` — немодифицированный Linux-ELF делает openat(O_CREAT|O_RDWR) →
write → close → openat(O_RDONLY) → read → побайтовая сверка → lseek(SEEK_END) → exit 43;
`linux_abi_fork_exec` — fork(57) внутри Linux-персоны, ребёнок пишет и выходит с 44, родитель
wait4(-1) проверяет `WEXITSTATUS == 44` → exit 45.

## Фаза 2 v3: getdents64/ioctl/statx/pipe/faccessat

Третий срез добирает то, без чего busybox не стартует и не работает `ls`/`sh`:

- **getdents64(217)** — `File::readEntries()` posix отдаёт по одной записи; обработчик пакует их в
  uapi-`linux_dirent64` (d_ino/d_off/d_reclen/d_type/d_name, reclen выровнен на 8) в bounce-буфер,
  пока влезает в `count` пользователя; EOF возвращается как 0, «не влезла даже одна запись» — EINVAL.
  d_type маппится из `managarm::fs::FileType` (DT_REG/DT_DIR/DT_LNK/DT_SOCK/DT_CHR/DT_BLK/DT_FIFO).
- **ioctl(16)** — только терминальные команды: TCGETS/TCSETS (termios в сыром Linux-формате
  x86_64 — 36 байт, c_cc[19]) и TIOCGWINSZ/TIOCSWINSZ (winsize 8 байт). Для этого у `File`
  появились новые виртуальные методы `getTermios/setTermios/getWinsize/setWinsize` с дефолтом
  `Error::notTerminal`; переопределены в pts.cpp (Master/Slave: `Channel::activeSettings`,
  `width/height/pixel*`, TIOCSWINSZ-семантика с SIGWINCH) и devices/ttyn.cpp (консоль: 80x24,
  `_activeSettings`). Всё остальное — `-ENOTTY` (как в Linux у файлов).
- **statx(332)** — полный uapi `struct statx` (256 байт, static_assert) из `FileStats`;
  `stx_mask` = STATX_TYPE|MODE|NLINK|UID|GID|ATIME|MTIME|CTIME|INO|SIZE|BLOCKS; поддержан
  `AT_EMPTY_PATH` (stat по fd — так glibc делает fstat()); layout проверен юнит-сниппетом
  (офсеты 0x10/0x1c/0x20/0x40/0x70/0x80/0x90).
- **pipe(22)/pipe2(293)** — `fifo::createPair()` + attach обоих концов, `int pipefd[2]` копируется
  в память процесса; O_NONBLOCK/O_CLOEXEC поддержаны, лишние флаги — EINVAL.
- **faccessat(269)/faccessat2(439)** — разрешение пути через общий хелпер `statsAt()` (dirfd +
  PathResolver, AT_SYMLINK_NOFOLLOW) и unix-проверка прав против euid/egid процесса (root: всё,
  кроме X_OK при полном отсутствии x-битов); F_OK — просто существование.

Приёмочный тест `linux_abi_dirstat` (немодифицированный Linux-ELF, exit 46): openat("/tmp",
O_DIRECTORY) → getdents64 с валидацией цепочки записей (reclen ≥ 24, выравнивание, покрытие
ret, ненулевой d_ino) → ioctl(1, TIOCGWINSZ) == 0 и ws_col == 80 на консоли (или ENOTTY) →
pipe2 → write/read через канал → ioctl на pipe fd == -ENOTTY → faccessat("/") == 0 и
faccessat на отсутствующий путь == -ENOENT → statx("/tmp"): stx_ino ≠ 0, STATX_INO в mask,
S_IFDIR в stx_mode.

## Фаза 2 v4: socket-сисколлы + rt_sigaction/rt_sigprocmask

Sockets and signals complete the busybox syscall surface. Same transport
(superLinuxSyscall upcall, Linux registers decoded in the observe loop).

**Sockets (17 номеров).** `socket`(41), `socketpair`(53), `bind`(49),
`connect`(42), `listen`(50), `accept`(43)/`accept4`(288), `sendto`(44),
`recvfrom`(45), `sendmsg`(46), `recvmsg`(47), `shutdown`(48),
`getsockname`(51), `getpeername`(52), `setsockopt`(54), `getsockopt`(55).
Реализация переиспользует штатную сокетную машинерию posix: AF_UNIX —
`un_socket::createSocketFile/createSocketPair`, AF_INET/AF_PACKET/NETLINK_ROUTE —
`extern_socket::createSocket` (netserver), прочие netlink-протоколы —
`netlink::nl_socket`. Адреса передаются как сырые байты (Linux-раскладка
sockaddr совпадает с managarm-mlibc); sendmsg/recvmsg работают с iovec-цепочками
(гатеринг/скаттеринг через bounce-буфер) и поддерживают msg_name; msg_control
(cmsg) пока не поддерживается — EINVAL.

**Сигналы.** `rt_sigaction`(13), `rt_sigprocmask`(14), `rt_sigreturn`(15),
плюс `kill`(62) и `tgkill`(234) для самотестирования и busybox kill.
- rt_sigaction читает/пишет Linux `struct rt_sigaction` (handler/flags/restorer/
  mask, sigsetsize=8) и отображает его на штатную таблицу `SignalContext`
  posix: SIG_DFL/SIG_IGN → none/ignore, SA_SIGINFO/SA_ONSTACK/SA_RESETHAND/
  SA_NODEFER → signalInfo/signalOnStack/signalOnce/signalReentrant,
  SA_RESTORER → restorerIp.
- rt_sigprocmask (SIG_BLOCK=0/SIG_UNBLOCK=1/SIG_SETMASK=2) работает с маской
  потока (`Process::signalMask`), биты SIGKILL/SIGSTOP снять нельзя.
- **Доставка обработчиков**: `SignalContext::raiseContext` для Linux-персоны
  строит **Linux rt_sigframe** (pretcode=SA_RESTORER, siginfo 128 байт,
  ucontext 304 байта с gregs[23] в порядке musl, хвост — блоб SIMD от ядра)
  и входит в обработчик с Linux-конвенцией (rdi=signo, rsi=siginfo,
  rdx=ucontext). Возврат — через `rt_sigreturn`(15): posix восстанавливает
  gregs/SIMD/маску из фрейма и отвечает outcome'ом `committed` (observe-цикл
  только делает helResume, не трогая регистры).
- Асинхронная доставка работает через штатный `serveSignals` →
  helInterruptThread → kHelObserveInterrupt — сигнал, выданный во время
  upcall (например SIGPIPE из sendMsg), обрабатывается сразу после resume.

**Исправление v2-регистров.** observe-цикл больше не пишет `kHelRegError`
(RDI=0) при возврате из Linux-сисколла: в Linux-ABI RDI несёт a0, а слот
ошибки Hel клиенту не виден. Раньше это молча портило RDI (на простых тестах
не проявлялось, для скомпилированного кода опасно).

**Сброс SignalGuard-флага при exec.** `Process::exec` обнуляет
`ThreadPage::globalSignalFlag`: у форк-клина, выросшего из нативного mlibc,
флаг мог остаться 1 (SignalGuard активен) — тогда posix «паркует» все сигналы
как delayedSignal, а клиента, который должен вызвать superSigRaise, у
Linux-процесса больше нет. Симптом: сигналы не доставляются вообще.

**Синхронный проход по отложенным сигналам.** serveSignals не может
прервать поток, припаркованный на resume после upcall, — уведомление о
сигнале, выданном во время upcall (kill в себя, SIGPIPE из sendMsg),
терялось. observe-цикл теперь после записи результата делает неблокирующий
проход `handlePendingSignalsFromObservation` перед helResume (зеркало
нативного kill-пути).

## Ограничения v1, фаза 2, v3 и v4

- **ioctl** покрывает только TCGETS/TCSETS/TIOCG(W)INSZ; FIONREAD/FIONBIO/TIOCGPGRP и прочие —
  ENOTTY.
- **cmsg** в sendmsg/recvmsg не поддерживается (SCM_RIGHTS/SCM_CREDENTIALS) — EINVAL;
  AF_INET6 и broadcast kill(-1) — EAFNOSUPPORT/-EPERM; SA_NOCLDSTOP/SA_NOCLDWAIT/SA_RESTART
  принимаются, но не имеют побочных эффектов.
- **faccessat** проверяет права по euid/egid (без AT_EACCESS-семантики реальных id) — для
  busybox-сценариев достаточно.
- **Отмена операций**: Linux-потоки не подключены к `CancelEventRegistry` — блокирующий read/wait
  не прерывается сигналом (EINTR не эмулируется).
- **Динамические Linux-бинарники** всё ещё отвергаются: ld.so требует расширенной таблицы сисколлов
  (v4 закрыл socket/signal-часть этой потребности; следующим заходом — vDSO и загрузка PT_INTERP).
- **CLOCK_REALTIME** в ядре пока boot-relative; для mlibc-программ точное время даёт vDSO/tracker.
- **pids/uid** — getpid/getppid/gettid настоящие; uid-семейство пока заглушки в ядре.
- Детект по ABI-tag/интерпретатору покрывает glibc-статик, musl-динамик и наш тест; glibc-динамик
  и «голый» musl-статик (без note) пока не различить — будет явный маркер на этапе файлового слоя.

## Карта изменений (аддитивно к upstream)

| файл | изменение |
|------|-----------|
| `hel/include/hel.h` | `kHelAbiLinux = 2` |
| `kernel/thor/generic/thor-internal/thread.hpp` | `kFlagLinuxPersonality = 2` |
| `kernel/thor/generic/hel.cpp` | учёт `abi` в `helCreateThread` (3 строки) |
| `kernel/thor/generic/main.cpp` | include + 7-строчный хук диспетчера |
| `kernel/thor/generic/linux-abi.cpp` `.hpp` | новые (таблица Linux-сисколлов) |
| `kernel/thor/meson.build` | +1 источник |
| `posix/subsystem/src/exec.cpp` | детект Linux-ELF, guard ld.so, abi/entry, `ExecuteResult.isLinux` |
| `posix/subsystem/src/linux-abi.cpp` `.hpp` | новые (v2: обработчик upcall, VFS-трансляция) |
| `posix/subsystem/src/observations.cpp` | ветка `superLinuxSyscall` в observeThread |
| `posix/subsystem/src/process.{hpp,cpp}` | `linuxPersonality`, наследование в fork/clone, коммит в exec |
| `protocols/posix/include/protocols/posix/supercalls.hpp` | `superLinuxSyscall = 19` |
| `kernel/thor/generic/linux-abi.cpp` | v2: passthrough-блок файловых/процессных номеров |
| `posix/subsystem/src/file.hpp` | v3: виртуальные getTermios/setTermios/getWinsize/setWinsize |
| `posix/subsystem/src/pts.cpp` | v3: терминальные оверрайды (termios/winsize + SIGWINCH) |
| `posix/subsystem/src/devices/ttyn.cpp` | v3: терминальные оверрайды консоли (80x24) |
| `posix/subsystem/src/linux-abi.cpp` | v4: socket-сисколлы, rt_sigaction/rt_sigprocmask/rt_sigreturn, raiseLinuxContext (rt_sigframe) |
| `posix/subsystem/src/observations.cpp` | v4: режим `committed` + отказ от записи kHelRegError (сохранение RDI) |
| `posix/subsystem/src/process.cpp` | v4: ветка Linux-персоны в SignalContext::raiseContext |
| `kernel/thor/generic/linux-abi.cpp` | v4: passthrough socket/signal номеров (13–15, 41–55, 62, 234, 288) |
| `testsuites/posix-tests/*` | тесты + hello.S/dirstat.S/socksig.S + gen-hello-blob.py |
