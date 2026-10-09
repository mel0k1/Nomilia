# Linux ABI: слой linux-sysdeps (v1)

Цель — исполнять **немодифицированные** Linux-бинарники (в первую очередь статические musl: busybox)
без пересборки и без патчей к бинарникам. Слой живёт в ядре thor: Linux-сисколл принимается по
«сырому» Linux-номеру и исполняется поверх внутренних примитивов thor (`AllocatedMemory`,
`VirtualSpace`, `FutexRealm`, MSR FS/GS, PRNG). Это первый вертикальный срез; файловые операции и
форк — фаза 2 (см. конец документа).

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
| 1   | write         | частично | fd 1/2 → kernel log (сниппет в QEMU-лог); остальные fd → `-EBADF` |
| 9   | mmap          | да | анонимные private-маппинги; MAP_FIXED уважается; file-backed → `-ENOSYS` |
| 10  | mprotect      | да | через `VirtualSpace::protect` |
| 11  | munmap        | да | |
| 12  | brk           | да | per-AS состояние, база 0x10000000, лимит 128 МиБ; при ошибке — текущий brk (семантика Linux) |
| 24  | sched_yield   | да | `Thread::deferCurrent()` |
| 28  | madvise       | да | no-op |
| 39/186 | getpid/gettid | заглушка | всегда 1 (в ядре нет pids) |
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

## Ограничения v1 и фаза 2

- **Файловые сисколлы** (openat/read/close/stat/…) — ключевой пробел. План: upcall из thor в
  posix-подсистему (новое bragi-сообщение «LinuxSyscall»), posix исполняет их своей штатной
  машинерией (fd-таблицы уже там) — это и есть полная таблица «Linux nr → bragi» из роадмапа.
- **clone/fork внутри Linux-персональности**: posix должен наследовать abi при создании потоков
  fork-путём; после этого execve внутри Linux-процесса открывает busybox-апплеты.
- **execve из Linux-программы**: требует файлового upcall (см. выше).
- **CLOCK_REALTIME** в ядре пока boot-relative; для mlibc-программ точное время даёт vDSO/tracker.
- **exit_group** завершает только текущий поток (в thor нет списка потоков процесса) — для v1
  Linux-программы однопоточные; полный kill-group делает posix.
- **pids/uid** — заглушки; придут вместе с файловым upcall.
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
| `posix/subsystem/src/exec.cpp` | детект Linux-ELF, guard ld.so, abi/entry |
| `testsuites/posix-tests/*` | тест + hello.S + gen-hello-blob.py |
