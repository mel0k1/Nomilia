<div align="center">

```
███╗   ██╗ ██████╗ ███╗   ███╗██╗██╗     ██╗██╗ █████╗
████╗  ██║██╔═══██╗████╗ ████║██║██║     ██║██║██╔══██╗
██╔██╗ ██║██║   ██║██╔████╔██║██║██║     ██║██║███████║
██║╚██╗██║██║   ██║██║╚██╔╝██║██║██║     ██║██║██╔══██║
██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║███████╗██║██║██║  ██║
╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝╚══════╝╚═╝╚═╝╚═╝  ╚═╝
```

**Операционная система на базе Managarm с прицелом на улучшенную совместимость с Linux**

![License](https://img.shields.io/badge/license-MIT-blue)
![Language](https://img.shields.io/badge/lang-C%2B%2B20%20%7C%20Rust-orange)
![Arch](https://img.shields.io/badge/arch-x86__64%20%7C%20aarch64%20%7C%20riscv64-informational)
![Base](https://img.shields.io/badge/based%20on-Managarm-8A2BE2)
![Status](https://img.shields.io/badge/status-early%20development-red)
[![CI](https://github.com/mel0k1/Nomilia/actions/workflows/ci.yml/badge.svg)](https://github.com/mel0k1/Nomilia/actions/workflows/ci.yml)

</div>

---

## О проекте

**Nomilia** — операционная система, строящаяся на технологическом фундаменте проекта [Managarm](https://github.com/managarm/managarm): асинхронное ядро `thor`, capability-модель `Hel`, userspace-драйверы, собственная POSIX-подсистема и libc `mlibc`. Мы не просто форкаем код — мы берём сильную архитектурную базу и развиваем то направление, которое в исходном проекте не является приоритетом: **запуск немодифицированных Linux-бинарников**.

Идея проста: у Managarm уже есть epoll, inotify, eventfd, timerfd, signalfd, pidfd, netlink и Linux-подобный sysfs — то есть значительная часть Linux-специфики уже покрыта. Nomilia доводит эту линию до конца: полноценный Linux ABI-слой, vDSO, расширенный futex, procfs/sysfs в Linux-формате — чтобы программы, собранные под Linux, работали без перекомпиляции.

## Ключевые цели

1. **Linux-совместимость** — главный фокус. Цель: статические musl-бинарники → динамические glibc-приложения → распространённые программы (busybox, bash, python, порты из репозиториев Managarm).
2. **Сохранение сильной архитектуры** — асинхронное ядро, userspace-драйверы, capability-безопасность не приносятся в жертву совместимости.
3. **Упрощение входа** — понятная документация, прозрачная сборка, честная дорожная карта.
4. **Три архитектуры** — x86_64, aarch64, riscv64 развиваются параллельно, как в upstream.

## Архитектура (кратко)

| Компонент | Роль |
|---|---|
| `eir` | Пре-ядерный загрузчик (Multiboot2 / Limine / UEFI / **Linux boot protocol**) |
| `thor` | Асинхронное ядро: фиберы + C++20-корутины, unfairness-планировщик, эвикция памяти и swap |
| `Hel` | Системный ABI ядра: capabilities, асинхронный ввод-вывод, ~80 вербов |
| `mbus` | Сервер имён и устройств |
| `sif` | Userspace-дисковерия: ACPI (uACPI), Device Tree, PCI |
| `posix-subsystem` | POSIX-сервер: VFS, procfs, sysfs, сокеты, epoll/inotify/... |
| `netserver` | Userspace TCP/IP-стек (IPv4, netlink) |
| `drivers/*` | Userspace-драйверы: NVMe, AHCI, xHCI, DRM-графика, NIC |
| `mlibc` | libc (внешний репозиторий Managarm) |

Подробный разбор кодовой базы — [meta/ANALYSIS.md](meta/ANALYSIS.md).

## Дорожная карта

- **Этап 0** — фундамент: репозиторий, документация, модель «upstream → Nomilia»
- **Этап 1** — работающая сборка: QEMU-образ, CI на три архитектуры
- **Этап 2** — Linux ABI v1: auxv (AT_RANDOM и др.), futex REQUEUE, расширенный procfs → **запуск статических musl-бинарников**
- **Этап 3** — Linux ABI v2: vDSO, динамический glibc, Linux socket ABI → **динамические Linux-программы**
- **Этап 4** — экосистема: пакетная база, GPU-ускорение, Wi-Fi
- **Этап 5** — дифференциация: namespaces/cgroups, io_uring-подобный нативный API

Детали: [meta/ROADMAP.md](meta/ROADMAP.md), идеи и обоснования: [meta/IDEAS.md](meta/IDEAS.md).

## Документация

| Документ | Содержание |
|---|---|
| [meta/ANALYSIS.md](meta/ANALYSIS.md) | Глубокий анализ исходной кодовой базы Managarm |
| [meta/ROADMAP.md](meta/ROADMAP.md) | Дорожная карта проекта по этапам |
| [meta/IDEAS.md](meta/IDEAS.md) | Идеи улучшений с приоритетами |
| [meta/UPSTREAM.md](meta/UPSTREAM.md) | Политика работы с upstream-снапшотом Managarm |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Стиль кода и правила участия |

## Статус

Снапшот кодовой базы Managarm (`85fd43c8d`) импортирован как основа (см. [meta/UPSTREAM.md](meta/UPSTREAM.md)). Сборка и QEMU-тесты (boot-матрица + kernel/posix-тесты) работают в CI — этап 1 закрыт. Этап 2 в ходу: auxv дополнен `AT_RANDOM`, `AT_CLKTCK`, `AT_HWCAP`, `AT_UID/EUID/GID/EGID`; в ядре появилась переочередь фьютексов (`helFutexRequeue`, Hel ABI №72). procfs дополнен Linux-файлами (`cpuinfo`, `meminfo`, `loadavg`, `version`, `[pid]/environ`, `[pid]/cmdline`); форкнут mlibc (ветка `nomilia`): `AT_CLKTCK`, sysdep-хук `FutexRequeue`, Linux-совместимый `uname` — CI собирает mlibc из форка. Весь пайплайн зелёный: 7 сценариев бута в QEMU (BIOS/UEFI × Limine/MB2/virtio) + kernel/posix/os-test/rust-тесты. Добавлен **vDSO**: каждый процесс получает маппинг `[clock-страница ядра][страница clocktracker][vdso.so]` с `AT_SYSINFO_EHDR` — Linux-совместимые `__vdso_clock_gettime`/`gettimeofday`/`time` читают время без syscall'ов (TSC через `HelClockPage` + realtime от clocktracker). Дальше по роадмапу: слой linux-sysdeps, vDSO-wiring в mlibc, динамические Linux-бинарники.

## Благодарности

Проект построен на коде и идеях [Managarm](https://github.com/managarm/managarm) — спасибо всем его контрибьюторам за одну из самых инженерно интересных хобби-ОС. Также благодарим команды проектов [mlibc](https://github.com/managarm/mlibc), [uACPI](https://github.com/UACPI-UAN/uacpi) и [bragi](https://github.com/managarm/bragi).

## Лицензия

Код распространяется по лицензии [MIT](LICENSE) — как и оригинальный Managarm.

<details>
<summary><b>English summary</b></summary>

**Nomilia** is an operating system built on top of the [Managarm](https://github.com/managarm/managarm) codebase: the async `thor` kernel, the capability-based `Hel` ABI, userspace drivers and the `mlibc` C library. The project's differentiating focus is **improved Linux compatibility** — running unmodified Linux binaries. Much of the Linux-specific surface (epoll, inotify, eventfd/timerfd/signalfd, pidfd, netlink, sysfs) already exists in Managarm; Nomilia adds the missing pieces: full Linux auxv (AT_RANDOM etc.), vDSO, FUTEX_REQUEUE/PI, Linux-shaped procfs/sysfs, Linux socket ABI, and a Linux syscall personality in the libc layer. Roadmap: static musl binaries → dynamic glibc programs → broader ecosystem. Licensed under MIT.

</details>
