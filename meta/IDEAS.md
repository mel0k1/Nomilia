# Идеи улучшений Nomilia

Приоритеты: **P0** — следующий этап, **P1** — на горизонте Linux ABI v2, **P2** — экосистема, **P3** — долгосрочно. Формат каждой идеи: суть → зачем → как → риск/цена.

---

## Направление A. Linux-совместимость (главный фокус проекта)

### A1. Полный auxv — самый дешёвый критичный фикс (P0)

**Суть.** Linux-программы и их динамические загрузчики читают параметры старта из auxiliary vector. В `exec.cpp` Managarm кладёт только 9 записей; не хватает как минимум `AT_RANDOM` (без него ld.so glibc/musl не инициализирует стек-канарейку и падает), `AT_CLKTCK` (гц таймеров, ожидается 100), `AT_HWCAP` (детекция CPU-фич), `AT_UID/EUID/GID/EGID`, `AT_PLATFORM`, `AT_EXECFN` уже есть.

**Зачем.** Это единственный блокер между текущим exec и «подсюнет ld-linux на загрузку». Всё остальное (PT_INTERP, ET_DYN) уже поддержано.

**Как.** Одна функция в `posix/subsystem/src/exec.cpp`: добавить генерацию записей. `AT_RANDOM` — 16 случайных байт из `helGetRandomBytes`. Риск минимальный: точка локализована, добавление записей в конец не ломает mlibc.

### A2. Linux-sysdeps слой в libc: personality, а не форк ABI (P0)

**Суть.** Ключевое архитектурное решение Nomilia: Linux-совместимость реализуется **в libc-слое**, а не новой таблицей syscall в ядре. Managarm не имеет «своей» фиксированной syscall-таблицы для приложений — приложения говорят bragi-протоколом через mlibc. Значит, можно собрать mlibc-вариант с «linux personality»: внутри sysdeps перехватываем Linux-номера вызовов и структуры, транслируем в те же bragi-сообщения (для статических musl-бинарников musl можно линковать с shim-библиотекой, реализующей Linux-ABI поверх Hel/bragi).

**Зачем.** Ядро и posix-subsystem почти не меняются; вся сложность ABI-структур (stat, sigaction, termios, utsname) изолирована в одном месте. Апгрейд upstream не конфликтует.

**Как.** Отдельный порт в дереве mlibc (`sysdeps/managarm/linux-personality`), таблица «Linux nr → обработчик», свои структуры `struct stat` (Linux layout), конвертация в протокольные. Риск: объём механической работы; mitigate — начать с top-60 syscall'ов busybox/musl.

### A3. futex: REQUEUE и PI-варианты (P0/P1)

**Суть.** В ядре `FutexRealm` умеет только WAIT/WAKE. Linux pthread-условные переменные и приоритетное наследование массово используют `FUTEX_REQUEUE`, `FUTEX_CMP_REQUEUE`, `FUTEX_LOCK_PI/UNLOCK_PI`, `FUTEX_WAIT_BITSET`.

**Зачем.** Без REQUEUE любой Linux-glibc pthread-код деградирует или ломается: condvar broadcase неминуемо делает requeue. Это второй блокер после auxv.

**Как.** Расширить `FutexRealm` (ядро) и добавить Hel-вербы `helFutexRequeue`/`helFutexWaitBitset`; в linux-personality — маппинг Linux-опкодов. PI отложить до этапа 3 (требует приоритетной наследственности в планировщике, где уже есть база — unfairness-метрика).

### A4. procfs в Linux-формате (P0)

**Суть.** procfs.cpp уже генерирует self/fd/maps/stat/uptime. Linux-приложения ожидают больше: `/proc/cpuinfo` (glibc и JVM парсят его при старте), `/proc/meminfo`, `/proc/self/status`, `/proc/self/environ`, `/proc/cmdline`, `/proc/version` с Linux-подобной строкой, `/proc/sys/kernel/*`.

**Как.** По готовым образцам `UptimeNode`/`MapNode` — чисто аддитивные узлы. cpuinfo — сериализация из `x86/cpu.cpp`-данных через kerncfg-протокол. Низкий риск, высокая совместимостная отдача.

### A5. vDSO (P1)

**Суть.** Страница в userspace с быстрыми `clock_gettime`/`gettimeofday`/`time`/`getcpu`, экспортируемая через `AT_SYSINFO_EHDR`. В ядре уже есть прообраз — `user-clock.cpp` (user-visible clock page), плюс clocktracker-сервер.

**Зачем.** Glibc-программы без vDSO платят сисколлом на каждый вызов времени; бенчмарки и логи замедляются на порядки. Также Linux-бинарники ожидают `AT_SYSINFO_EHDR`.

**Как.** Стадия-1: развить user-clock до полноценной страницы с данными (сек/нс, мультиклоковость через clocktracker). Стадия-2: ELF-vDSO с symbol table, как у Linux. Риск: синхронизация seqlock'а часов; у thor уже есть соответствующие примитивы.

### A6. Linux socket ABI и IPv6 (P1)

**Суть.** Сокеты живут в двух точках: un-socket.cpp (AF_UNIX) и passthrough в netserver (AF_INET). Linux-программы ждут: Linux-коды sockopt (SOL_SOCKET/SO_* значения в Linux отличаются от многих BSD-наследий), sockaddr-форматы, `SOCK_CLOEXEC`-флаги, ioctls (SIOCGIFCONF), **IPv6** (не подтверждён в диспетчере).

**Как.** Трансляционные таблицы в `requests/socket.cpp` + расширение netserver (tcp4.cpp уже структурирован — добавить tcp6/ip6). Риск средний: сетевой стек userspace, отладка комфортная.

### A7. inotify в Linux-семантике (P1)

Файл уже есть (305 строк), но Linux-программы (udev, файловые менеджеры, systemd) зависят от тонкостей: `IN_EXCL_UNLINK`, `IN_MASK_ADD`, коалесинг событий, watch-descriptor нумерация. Задача: прогнать тест-набор inotify-tools и добить расхождения.

### A8. io_uring — оценочный этап (P2)

**Суть.** Флагманский Linux async API. Полная реализация тяжела, но у Nomilia есть козырь: ядро асинхронно по природе (Hel-вербы асинхронны из коробки). Даже частичный io_uring (SQPOLL off, базовые op-коды: readv/writev/openat/statx/accept) вытянет большие классы ПО (node.js, nginx-подобное).

**Как.** Сначала количественная оценка: сколько Linux-ПО реально требует io_uring при сборке. Реализация поверх HelQueue (очереди уже lock-free и с дескрипторами в кольце — семантически близко к SQ/CQ).

### A9. Namespaces и cgroups → Linux-контейнеры (P2/P3)

cgroupfs уже минимально есть, namespaces отсутствуют. Стратегически: capability-модель Hel — хорошая основа для изоляции; PID/NET/MOUNT namespace поверх posix-subsystem реализуемы в userspace-сервере без правки ядра (уникальное преимущество архитектуры). Это путь к запуску Linux-контейнерных ворклоадов без виртуализации.

### A10. Реверс загрузки: Nomilia как Linux-ядро (P1, почти бесплатно)

`kernel/eir/boot/linux/` уже умеет грузиться по Linux boot protocol. Систематизировать: kexec-загрузка Nomilia из работающего Linux, прямая загрузка QEMU (`-kernel`), поддержка EFI-stub-подобного сценария. Дешёвая фича с большим UX-эффектом (безгипервизорные тестовые стенды, hardware CI).

---

## Направление B. Ядро

### B1. Секвенс-пойнт vDSO-часов и tickless-режим (P2)
Развитие идей A5: полный tickless idle с dyntick-базой, reducing power. База: idle-intel.cpp с mwait-состояниями.

### B2. NUMA-осведомлённость балансировщика (P3)
LoadBalancer уже оперирует деревом узлов (LbNode) — добавить метрики по NUMA-доменам и policy placement для больших машин.

### B3. Развитие swap: страничный демон в userspace (P2)
SwapSpace с бюджетом уже в ядре; вынести writeback-политики в userspace-демон через ManagedMemory-нотификации — гибкие стратегии (zram, NVMe-swap priority).

### B4. Виртуализация как фича продукта (P2)
VMX/SVM/EPT/NPT/VT-d и RISC-V H-ext уже в ядре. Довести до userspace-API уровня «virt-run»: устройства virtio для гостей (транспорт core/virtio уже есть) → запуск Linux-гостей с почти нативной скоростью. Синергия с A9: совместимость через контейнеры ИЛИ виртуалки — обе дорожки.

---

## Направление C. Драйверы и графика

### C1. virtio-gpu + mesa (P2)
Самый быстрый путь к GPU-ускорению в QEMU/CI; DRM-фреймворк core/drm готов. Затем virgl/venus для vulkan-опенджл хоста.

### C2. Стабилизация intel-lil (P3)
Native Intel-драйвер амбициозен; альтернатива — портирование режима совместимости с linux i915 через userspace-shim. Оценить на этапе 4.

### C3. Wi-Fi стек (P2)
userspace-модель хорошо подходит: cfg80211-подобный слой + портированные firmware-загрузчики (iwlwifi). Начать с USB-донглов (rtlx) — их проще тестировать.

### C4. NVMe-мультиконтроллерность и TRIM (P2)
NVMe-драйвер есть; добить: namespaces, TRIM/deallocate, для swap-подсистемы B3.

---

## Направление D. Инфраструктура и экосистема

### D1. Упрощение сборки: Nomilia-специи для xbstrap (P1)
Сохранить проверенный xbstrap-пайплайн, но предоставить: готовый devcontainer/Dockerfile, prebuilt-артефакты тулчейна в GitHub Releases, `just`/`make` фасад над xbstrap-командами. Цель — «clone → qemu» за 30 минут.

### D2. CI-расширение (P1)
Матрица arch × конфигов (kasan/ubsan), nightly-QEMU-прогоны posix-tests + kernel-tests, комментирование PR с логами загрузки. Добавить linux-abi-тесты (этапы 2–3) как отдельный джоб.

### D3. Документация: заполнить sys-arch (P1)
У upstream docs/src/sys-arch — заглушки. У Nomilia уже есть ANALYSIS.md — перенести его разделы в docs-book (mdbook, book.toml уже у upstream) и развивать как живую архитектурную книгу.

### D4. Пакетный менеджер (P3)
Бинарные пакеты поверх xbps (уже в bootstrap) или собственный минимальный формат. Не спешить: сначала порты из этапа 4.

### D5. Диффы против upstream: дисциплина (P0, процесс)
Все изменения Nomilia — аддитивные файлы/флаги там, где возможно (linux-personality — отдельный каталог, новые bragi-сообщения с новыми номерами, новые узлы procfs). Это делает ребейз на upstream-коммиты дешёвым, а upstream можно безопасно подтягивать раз в месяц.

---

## Таблица quick wins (сортировка по цене/эффекту)

| # | Идея | Цена | Эффект | Приоритет |
|---|---|---|---|---|
| 1 | A1 auxv (AT_RANDOM...) | часы | Linux-бинарники оживают | P0 |
| 2 | A4 procfs-файлы | часы-дни | совместимость glibc/утилит | P0 |
| 3 | A3 futex REQUEUE | дни | pthread Linux-программ | P0 |
| 4 | A10 Linux boot protocol | дни | kexec/QEMU -kernel | P1 |
| 5 | A2 linux-personality libc | недели | весь Linux-софт | P0 |
| 6 | A5 vDSO | недели | скорость + glibc | P1 |
| 7 | A6 socket ABI/IPv6 | недели | сетевой софт | P1 |
| 8 | C1 virtio-gpu+mesa | недели | графика в CI | P2 |

**Стратегическая ставка:** Nomilia выигрывает не там, где переписывает Managarm, а там, где достраивает мост к Linux-экосистеме поверх лучшей в классе асинхронной архитектуры. Каждая идея выше выбрана так, чтобы сохранять малый дифф против upstream (D5) — это позволяет бесконечно долго питаться улучшениями исходного проекта, не форкаясь навсегда.
