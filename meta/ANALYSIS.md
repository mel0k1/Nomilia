# Анализ кодовой базы Managarm

> Срез: upstream-коммит `85fd43c8d` (октябрь 2026). Все пути указаны относительно корня репозитория Managarm. Анализ выполнен как фундамент для Nomilia: сначала понимаем, как устроен исходный проект, затем определяем точки расширения.

## 1. Общая характеристика

Managarm — асинхронная операционная система с ядром `thor`, написанная на C++20 (сборка в режиме `gnu++26`) с растущей Rust-частью в userspace. Лицензия — MIT. Отличительная черта проекта: единая асинхронная модель на всех уровнях — от планировщика ядра до клиентских библиотек libc. POSIX реализован не в ядре, а отдельным userspace-сервером, общающимся с приложениями через типизированный IPC-протокол bragi. Ядро при этом не является «чистым» микроядром: boot-критичная дисковерия (ACPI, PCI, DTB) и минимум драйверов живут в ядре, всё остальное — в userspace.

Кодовая база представляет собой монорепозиторий без сабмодулей: примерно **190 000 строк C++/H** и **23 000 строк Rust**.

## 2. Состав репозитория

| Каталог | Строк (C++/H/Rust) | Назначение |
|---|---:|---|
| `kernel/thor` | 62 661 | Ядро: планировщик, память, IPC, драйверы загрузки, виртуализация |
| `kernel/eir` | — | Пре-ядерный загрузчик (Multiboot2, Limine, UEFI, Linux boot protocol) |
| `drivers/` | 46 341 | Userspace-драйверы: блочные, NIC, графика, USB, звук |
| `posix/subsystem` | 28 044 | POSIX-сервер: VFS, exec, сокеты, epoll/inotify/... |
| `sif/` | 10 083 (Rust) | Дисковерия устройств: uACPI, Device Tree, PCI → mbus |
| `servers/` | 8 443 | netserver (TCP/IP), kernletcc (Rust-компилятор kernlet'ов) |
| `protocols/` | 8 897 | IDL-схемы bragi: fs, posix, mbus, hw, usb, svrctl, clock, ... |
| `hel/` | 6 880 | C-заголовки и C++-обвязка системного ABI ядра |
| `core/` | 8 332 | Общие библиотеки: core/drm (DRM-фреймворк), core/virtio |
| `rust/` | 7 704 | hel-sys, hel (async-рантайм), managarm (клиенты протоколов), arch |
| `mbus/` | 536 | Сервер имён и устройств |
| `testsuites/` | — | kernel-tests/torture/bench, posix-tests (34 файла), virt-test |

## 3. Путь загрузки

Загрузчик `eir` поддерживает четыре протокола, включая неожиданный — **загрузку в качестве Linux-ядра** (`kernel/eir/boot/linux/entry.cpp`), что открывает прямой kexec/QEMU direct kernel boot без эмуляции прошивки. Состояние передаётся ядру через ELF-notes (командная строка, initrd, карта памяти).

`thorMain()` (`kernel/thor/generic/main.cpp`) запускает декларативный граф инициализации `initgraph` со статически зарегистрированными стадиями (83 точки по ядру): от `tasking-available` до `pci.devices-enumerated`. Затем из initrd-CPIO в строгом порядке стартуют userspace-серверы: `sif` → `kernletcc` → `posix-devserver` → `clocktracker` → `netserver` → `posix-subsystem` → tty. Порядок жёсткий: sif должна опубликовать устройства до того, как драйверы начнут их искать через mbus.

## 4. Ядро thor

### Асинхронность

Три вида исполнителей: пользовательские `Thread`, stackful `KernelFiber` (`generic/fiber.cpp`) и C++20-корутины (`thor-internal/coroutine.hpp`, 659 строк) со своими WorkQueue-аффинными awaiter'ами. У каждого исполнителя есть `WorkQueue` (`generic/work-queue.cpp`) с тремя очередями (pending/local для прерываний/locked для чужих CPU). Вместо простых флагов прерываний — уровни IPL (`generic/ipl.cpp`), вместо сырых spinlock'ов — kernel-mutexes с IPL-протоколом. RCU (`generic/rcu.cpp`) используется повсеместно.

### Планировщик

Per-CPU планировщики (`generic/schedule.cpp`) с приоритетами и «метрикой несправедливости»: `scheduleBefore()` предпочитает задачу с большей `baseUnfairness - refProgress` — гарантия прогресса без классического fair-share. Нагрузка отслеживается EWMA с полураспадом ~537 мс, таблица затухания вычислена в compile-time через consteval-Тейлора (`thor-internal/load-tracking.hpp`). Балансировка (`generic/load-balancing.cpp`, 536 строк) — detached-корутины на каждом CPU, миграция с гистерезисом (`dstLoad + movedLoad + movedLoad/8 <= srcLoad`), поддержка аффинити.

### Память

Центральная абстракция — иерархия `MemoryView` (`generic/memory-view.cpp`, 3 975 строк): `ZeroMemory`, `HardwareMemory` (MMIO), `AllocatedMemory` (анонимная), **`ManagedMemory`** (страничный кэш с dirty-списком и writeback), `IndirectMemory`, `SliceView`. Реализованы эвикция страниц (`EvictionQueue`, `MemoryReclaimer`) и **swap с бюджетом** (`SwapSpace`, `helSetSwapBudget`) — редкость для хобби-ОС. Адресные пространства с red-black деревом маппингов, batched TLB-shootdown через IPI, менеджер ASID/PCID (`generic/asid.cpp`).

### IPC и сисколлы

`Hel` — capability-based ABI: ~80 вербов (`hel.cpp`, 4 894 строки), диспетчер в `main.cpp`. Объекты — дескрипторы в `Universe` с правами (`kHelRightInvoke/Manage/Signal`) и передачей между процессами. Транспорт: lock-free `HelQueue` (ядро↔userspace в общем кольце) и двусторонние `Stream` с lane'ами. Supercalls (`kHelCallSuper`) — механизм svrctl для регистрации серверов.

### Прочее

futex с семантикой WAIT/WAKE (`FutexRealm`); GDB-remote stub в ядре; структурированная трассировка ostrace; kernlet — «кernлеты», компилируемые в userspace из Fafnir IR в ELF-DSO и вшиваемые в IRQ-обработку; **аппаратная виртуализация**: VMX/SVM с EPT/NPT и VT-d на x86, RISC-V H-extension; аппаратный генератор случайности с подмешиванием энтропии из IRQ.

## 5. POSIX-подсистема

Каждый syscall приложения mlibc превращает в bragi-сообщение протокола `posix.bragi` (199 сообщений — крупнейший протокол). Цикл диспетчеризации — `posix/subsystem/src/requests.cpp`, обработчики по темам: `requests/filesystem.cpp` (1 848 строк), `fd.cpp`, `process.cpp`, `memory.cpp`, `socket.cpp`, `special-files.cpp`, `uid-gid.cpp`, `system.cpp`, `timer.cpp`.

Реализовано и протестировано: **epoll, inotify, eventfd, timerfd, signalfd, pidfd, memfd**, pipes/fifo, pty, netlink (generic + uevent + nlctrl), AF_UNIX (STREAM/DGRAM/SEQPACKET), AF_INET через netserver. VFS: tmpfs (root/devfs), extern_fs (клиент внешних FS-серверов), **procfs** (self, fd, fdinfo, maps, stat, uptime, mounts), **cgroupfs** (минимальный), Linux-подобный **sysfs** в Rust-сервере `posix-devserver` (15 подсистем: block, pci, usb, net, drm, ...).

### exec: критично для Linux-совместимости

`exec.cpp` (395 строк) обрабатывает shebang (до 8 рекурсий), `PT_LOAD`, `PT_PHDR` и **`PT_INTERP` — интерпретатор открывается как обычный путь через VFS**. PIE грузится на базу 0x200000, динамический загрузчик — на фикс 0x40000000. В auxv кладутся только `AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM, AT_EXECFN, AT_SECURE, AT_BASE, AT_PAGESZ, AT_NULL`. **Чего нет**: `AT_RANDOM` (обязателен для стек-канарейки ld.so glibc/musl!), `AT_HWCAP`, `AT_CLKTCK`, `AT_UID/EUID/GID/EGID`, `AT_PLATFORM`, `AT_SYSINFO_EHDR` (vDSO отсутствует), обработка `PT_TLS`.

## 6. Драйверы и графика

Все драйверы — userspace-процессы. Типовой цикл: найти устройство в mbus (опубликовано ядром или sif), работать через протокол `hw` (BAR, IRQ, DMA-пространство с IOMMU), зарегистрироваться через svrctl, экспортировать `/dev` через fs-протокол. Состав: блочные (ATA, AHCI, NVMe, virtio-blk), сетевые (rtl8168, e1000, igc, bcmgenet, virtio, USB-сеть), USB (UHCI/EHCI/xHCI + HID/storage/serial), графика поверх `core/drm` (bochs, vmware, plainfb; intel-lil и nvidia-open — экспериментальные), звук (HDA). Для virtio есть общий транспорт `core/virtio`.

## 7. Сеть

`servers/netserver` — userspace TCP/IP-стек: IPv4 (795), TCP (1 291), UDP (796), ICMP, ARP, netlink RTM-запросы, PHY-драйверы (realtek, broadcom). NIC-драйверы вкомпилированы в netserver. IPv6 не подтверждён в диспетчере сокетов.

## 8. Rust-миграция

Этажность: `hel-sys` (bindgen-FFI) → `hel` (безопасная обвязка + async-рантайм на `async_task`) → `managarm` (клиенты протоколов mbus/fs/hw/usb/posix). Уже на Rust: **sif, posix-devserver, kernletcc** — три из семи стартовых серверов. Ядро остаётся полностью C++.

## 9. Сборка и CI

Двухуровневая: meson собирает компоненты монорепо (flavor'ы `build_kernel` / `build_drivers`, кросс-компиляция обязательна), xbstrap+cbuildrt собирают весь дистрибутив через отдельный репозиторий `bootstrap-managarm` (тулчейн, mlibc, порты, образ диска). Итого 4 внешних репозитория на полную сборку. CI — GitHub Actions с матрицей x86_64/aarch64/riscv64, запуск тестов в QEMU через `utils/ci-boot`.

## 10. Сильные стороны

1. Единая асинхронная модель (fiber + корутины + WorkQueue + IPL) без «зонного» подхода.
2. Capability-модель с правами и userspace-драйверы за IOMMU — малый TCB.
3. Продвинутая память: страничный кэш, эвикция, swap-бюджет, COW/fork.
4. Теоретически обоснованный планировщик с честным load-tracking.
5. Три архитектуры в CI; виртуализация на x86 и RISC-V.
6. Наблюдаемость: ostrace, два GDB-сервера, профилировщик, coredump в Linux-формате.
7. Осмысленная Rust-миграция с чистой FFI-этажностью.
8. Типизированный IDL (bragi) с генерацией C++ и Rust.

## 11. Слабые стороны

1. Message-per-syscall: POSIX-сисколл = сетевой ход через bragi — накладные расходы и жёсткая привязка совместимости к mlibc.
2. Нет vDSO и AT_RANDOM — даже собственные программы платят сисколлом за clock/getpid; Linux-бинарники не стартуют вовсе.
3. futex беднее Linux: нет REQUEUE/PI — pthread condvars Linux-программ работать не будут.
4. sys-arch документация — заглушки; вход только через чтение кода.
5. Сеть: userspace-стек, IPv6 не подтверждён, io_uring отсутствует.
6. GPU-стек ограничен, Wi-Fi нет.
7. Тяжёлая кросс-сборка (4 репозитория) — порог входа для форков высок.
8. coredump только x86_64; namespaces/LSM отсутствуют.

## 12. Точки расширения для Linux-совместимости

Минимальный дифф с максимальным эффектом:

1. `posix/subsystem/src/exec.cpp` — auxv: AT_RANDOM/AT_HWCAP/AT_CLKTCK/AT_UID/...; локализовано в одной функции.
2. `protocols/posix/posix.bragi` + `requests.cpp` — аддитивные Linux-семейства сообщений, per-process personality.
3. `hel/include/hel.h`, `generic/hel.cpp`, `thor-internal/futex.hpp` — FUTEX_REQUEUE/PI.
4. `posix/subsystem/src/procfs.cpp` — cpuinfo/meminfo/status/environ/cmdline по готовым образцам UptimeNode/MapNode.
5. `requests/socket.cpp` + `extern_socket.cpp` + `netserver` — трансляция sockopt/sockaddr.
6. mlibc (внешний) — слой linux-sysdeps: таблица «Linux syscall nr → bragi-сообщение»; главный рычаг, ядро не меняется.
7. `generic/user-clock.cpp` — база для vDSO-страницы (user-visible clock уже существует).
8. `kernel/eir/boot/linux/` — готовый Linux boot protocol; Nomilia может грузиться как Linux-ядро с первого дня.
