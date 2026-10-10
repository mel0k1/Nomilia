# Дорожная карта Nomilia

Каждый этап имеет измеримый критерий готовности (Definition of Done). Этапы не жёстко линейны: внутри этапа задачи можно распараллеливать, но зависимость «Linux ABI v2 → после v1» принципиальна.

## Этап 0 — Фундамент (текущий)

Модель разработки и база знаний.

- [x] Изучение кодовой базы Managarm, фиксация точек расширения (`docs/ANALYSIS.md`)
- [x] Репозиторий, документация, лицензия (MIT, с атрибуцией Managarm)
- [x] Определить модель отслеживания upstream: импорт снапшотов в `main` + политика синхронизации (`meta/UPSTREAM.md`)
- [x] Выбрать стратегии по инфраструктуре: сохранён xbstrap-пайплайн (пин bootstrap-managarm в CI)

**DoD**: новый разработчик за один вечер понимает, что такое Nomilia, чем она отличается от Managarm и где начинается работа.

## Этап 1 — Работающая сборка

- [x] Сборочный слой: upstream `bootstrap-managarm` (закреплён в CI) + `ci/bootstrap-site-*.yml` из дерева
- [x] CI: сборка ядра и userspace для x86_64 (`.github/workflows/ci.yml`; aarch64/riscv64 — по мере надобности)
- [x] QEMU-образ в CI: загрузка через limine / Multiboot2 / UEFI / virtio (цели `ci-boot-*` из bootstrap-managarm)
- [x] Прогон kernel-tests и posix-tests в CI (`xbstrap run ci-all` под QEMU)
- [x] Бейдж сборки в README

**DoD**: `git clone` + одна команда → загружающаяся в QEMU система с башней серверов sif → posix-subsystem.

## Этап 2 — Linux ABI v1: статические бинарники

Первая настоящая фича Nomilia. Цель — **немодифицированный статический musl-бинарник (busybox) запускается и работает**.

- [x] `exec.cpp`: `AT_RANDOM` в auxv — 16 случайных байт через `helGetRandomBytes` (проверено QEMU-бутом; важно: `copyArrayToStack` возвращает адрес в window posix-подсистемы — для auxv нужен `stackBase + d`)
- [x] `exec.cpp`: `AT_CLKTCK`, `AT_HWCAP`, `AT_UID/EUID/GID/EGID` (`AT_PLATFORM` — позже: нужен маппинг строки в образ процесса)
- [x] Ядро: переочередь фьютексов `helFutexRequeue` (Hel ABI №72: wake N + перенос M в другой слот; cmp-проверка как в `FUTEX_CMP_REQUEUE`); PI-варианты пока не нужны (kernel-test `futexRequeueSanity` проходит в QEMU; sysdep-хук `FutexRequeue` заведён в mlibc-форке)
- [x] procfs: `cpuinfo` (cpuid+kerncfg), `meminfo` (kerncfg), `loadavg`, `version`, `/proc/[pid]/environ`, `/proc/[pid]/cmdline`; `status`/`maps` уже есть upstream; глобальный `/proc/cmdline` тоже уже есть upstream
- [~] mlibc: форк [mel0k1/mlibc](https://github.com/mel0k1/mlibc) (ветка `nomilia`, база — пиннутый `880b1ce7`); сделано: `AT_CLKTCK` в `abis/managarm/auxv.h`, sysdep-хук `FutexRequeue` (wiring на `helFutexRequeue`), Linux-совместимый `uname`; CI собирает mlibc из форка
- [~] linux-sysdeps v1 (ядро): personality-флаг процесса (`kHelAbiLinux` в `helCreateThread`) + диспетчер Linux-сисколлов в thor (`linux-abi.cpp`): write→klog, brk/mmap/mprotect/munmap, uname, futex WAIT/WAKE/REQUEUE, clock_gettime/gettimeofday/time, getrandom, arch_prctl, exit_group; детект Linux-ELF в exec.cpp (PT_INTERP `ld-linux*`/`ld-musl*`, GNU ABI-tag)
- [x] тест `linux_abi_static_hello`: fork + execve немодифицированного статического Linux-ELF (raw syscalls, без libc) → exit 42
- [x] linux-sysdeps v2 (фаза 2): файловые/процессные Linux-сисколлы через upcall `superLinuxSyscall` (штатный observe-канал posix): open/openat/read/write/close/lseek/stat/lstat/fstat/fstatat/pread64/pwrite64/dup/dup2/dup3/getpid/getppid/gettid/getcwd, fork/vfork/execve/wait4; personality наследуется при fork/clone (abi в `helCreateThread` fork/clone-путей, `ExecuteResult.isLinux`)
- [x] тесты `linux_abi_files` (open/write/read/lseek roundtrip → exit 43) и `linux_abi_fork_exec` (fork/wait4 внутри Linux-персоны → exit 45)
- [x] linux-sysdeps v3: getdents64 (linux_dirent64), ioctl (TCGETS/TCSETS/TIOCGWINSZ/TIOCSWINSZ), statx (+AT_EMPTY_PATH), pipe/pipe2, faccessat/faccessat2; синтез S_IF*-битов типа файла в stat-режимах
- [x] тест `linux_abi_dirstat` (getdents64-цепочка, ioctl-консоль, pipe2-roundtrip, faccessat, statx → exit 46)
- [x] linux-sysdeps v4: socket-сисколлы поверх штатной сокетной машинерии posix (AF_UNIX/AF_INET/AF_PACKET/AF_NETLINK) и сигналы: rt_sigaction/rt_sigprocmask на штатной SignalContext-таблице, доставка обработчиков через Linux rt_sigframe + rt_sigreturn (режим `committed`), kill/tgkill; фикс: observe-цикл не затирает RDI (kHelRegError) при возврате из Linux-сисколла
- [x] тест `linux_abi_socksig` (socketpair-roundtrip + getsockname, sigaction/sigprocmask, доставка SIGUSR1-обработчика с возвратом через rt_sigreturn → exit 47)
- [x] uname: Linux-совместимое `utsname` (имя ядра, версия в формате Linux)
- [ ] Тест-матрица: busybox (sh, ls, ps, top), статические утилиты

**DoD**: `qemu: nomilia /bin/busybox sh` — интерактивная сессия без падений. (v1+v2+v3+v4 выполнены: execve Linux-ELF, файловые сисколлы и fork/exec/wait4, getdents64/ioctl(TCGETS/TCSETS/TIOCGWINSZ)/statx/pipe2/faccessat, socket-семейство (socket/socketpair/bind/connect/listen/accept4/sendto/recvfrom/sendmsg/recvmsg/shutdown/sockname/peername/sockopt) и сигналы (rt_sigaction/rt_sigprocmask/rt_sigreturn с Linux rt_sigframe + kill/tgkill) внутри Linux-персональности; остальное — vDSO-публикация в auxv Linux-процессов и динамические бинарники)

## Этап 3 — Linux ABI v2: динамические программы

- [x] vDSO: freestanding DSO (`posix/subsystem/vdso/`) с `__vdso_clock_gettime`/`clock_getres`/`gettimeofday`/`time`/`getcpu` (версионируемые символы `LINUX_2.6`, оба hash-стиля); блоб встраивается в posix-subsystem; `execute()` маппит фиксированный регион `[clock-страница ядра][страница clocktracker][vdso.so]` и публикует `AT_SYSINFO_EHDR`; данные — уже существующие `HelClockPage` (TSC+seqlock) и tracker-страница; приёмочный тест `vdso_*` в posix-tests (QEMU)
- [x] Загрузка `PT_INTERP`-интерпретаторов для Linux-бинарников в `exec.cpp` (тот же shared loader base, Linux-совместимый auxv `AT_BASE`/`AT_PHDR`/`AT_ENTRY`/`AT_EXECFN`); тест `linux_abi_dyn` (минимальный `nomilia-ld.so` + PT_INTERP/PT_DYNAMIC-hello, exit 48)
- [x] CI-payloads: workflow `payloads.yml` собирает musl из исходников + busybox (static и dynamic) + `hello-dynamic`, smoke-тесты на хосте, артефакт `linux-payloads-x86_64` (`ci/payloads/build-musl-busybox.sh`)
- [ ] Доставка payloads в QEMU-образ Nomilia и запуск `hello-dynamic`/`busybox-dynamic` через `ld-musl` (PT_INTERP `/lib/ld-musl-x86_64.so.1`) в CI
- [ ] mlibc: vDSO wiring — `sys_clock_get`/`gettimeofday` через `AT_SYSINFO_EHDR` (сейчас vDSO потребляют Linux-бинарники; mlibc ходит syscall'ом)
- [ ] Поверхность сисколлов для настоящего `ld-musl`: writev/readv и остальное, что линкер тянет до точки входа
- [ ] Обработка `PT_TLS` и arch_prctl-эквиваленты → динамический `ld-linux`/glibc
- [ ] Linux socket ABI: трансляция sockopt/sockaddr в `requests/socket.cpp` и netserver; протокол IPv6
- [ ] inotify: свести поведение с Linux-семантикой (masked-события, IN_EXCL_UNLINK и пр.)
- [ ] Приоритеты errno: полная таблица соответствия Linux errno в linux-sysdeps
- [ ] LTP-подмножество как регрессионный фильтр (ltp-smoke)
- [ ] Целевые динамические приложения: bash, coreutils, python

**DoD**: динамический glibc-программный стек (python) работает в QEMU без патчей бинарников.

## Этап 4 — Экосистема

- [ ] GPU: стабилизация DRM-драйверов (bochs/vmware/virtio-gpu), mesa/vulkan-порты
- [ ] Wi-Fi: userspace-драйверы на базе linux-портированных firmware-интерфейсов
- [ ] Пакетная база: пересборка портов Managarm против Nomilia-mlibc, репозиторий пакетов
- [ ] Инсталлятор: загрузочный USB-образ с установкой на диск
- [ ] Железный CI (hwci) для плат aarch64

**DoD**: live-USB, который грузится на реальном железе и ставит систему с пакетным репозиторием.

## Этап 5 — Дифференциация

Долгосрочные направления, где Nomilia может стать больше, чем «Linux-совместимый Managarm»:

- [ ] Namespaces + cgroups v2 → контейнеры Linux-приложений без виртуализации
- [ ] io_uring-подобный нативный API поверх асинхронного ядра (Hel уже асинхронен — уникальное преимущество)
- [ ] Аппаратная виртуализация как штатная фича (VMX/SVM/H-extension уже в ядре): запуск Linux-гостей
- [ ] Растущая роль Rust в критичных userspace-серверах (по пути, начатому upstream: sif/devserver)

**DoD**: определяется по результатам этапов 2–4.
