# Дорожная карта Nomilia

Каждый этап имеет измеримый критерий готовности (Definition of Done). Этапы не жёстко линейны: внутри этапа задачи можно распараллеливать, но зависимость «Linux ABI v2 → после v1» принципиальна.

## Этап 0 — Фундамент (текущий)

Модель разработки и база знаний.

- [x] Изучение кодовой базы Managarm, фиксация точек расширения (`docs/ANALYSIS.md`)
- [x] Репозиторий, документация, лицензия (MIT, с атрибуцией Managarm)
- [ ] Определить модель отслеживания upstream: ветка `upstream-snapshot` + периодические ребейзы `main`
- [ ] Выбрать стратегии по инфраструктуре: сохранить xbstrap-пайплайн или собрать свой bootstrap-слой

**DoD**: новый разработчик за один вечер понимает, что такое Nomilia, чем она отличается от Managarm и где начинается работа.

## Этап 1 — Работающая сборка

- [ ] Форк-цепочка сборки: xbstrap-сайт Nomilia (по образцу `ci/bootstrap-site-*.yml`)
- [ ] CI: сборка ядра и userspace для x86_64 (затем aarch64, riscv64)
- [ ] QEMU-образ с загрузкой через `eir` (Multiboot2 / direct kernel boot)
- [ ] Прогон kernel-tests и posix-tests в CI (по образцу `utils/ci-boot`)
- [ ] Бейджи сборки в README

**DoD**: `git clone` + одна команда → загружающаяся в QEMU система с башней серверов sif → posix-subsystem.

## Этап 2 — Linux ABI v1: статические бинарники

Первая настоящая фича Nomilia. Цель — **немодифицированный статический musl-бинарник (busybox) запускается и работает**.

- [x] `exec.cpp`: `AT_RANDOM` в auxv — 16 случайных байт через `helGetRandomBytes`
- [ ] `exec.cpp`: `AT_CLKTCK`, `AT_HWCAP`, `AT_UID/EUID/GID/EGID`, `AT_PLATFORM`
- [ ] Ядро: `FUTEX_REQUEUE` (+ оценка потребности в PI-вариантах) в `FutexRealm`
- [ ] procfs: `cpuinfo`, `meminfo`, `status`, `environ`, `cmdline`, `self/maps` в Linux-формате
- [ ] mlibc: слой `linux-sysdeps` — таблица «Linux nr → bragi» для статической musl-персональности
- [ ] uname: Linux-совместимое `utsname` (имя ядра, версия в формате Linux)
- [ ] Тест-матрица: busybox (sh, ls, ps, top), статические утилиты

**DoD**: `qemu: nomilia /bin/busybox sh` — интерактивная сессия без падений.

## Этап 3 — Linux ABI v2: динамические программы

- [ ] vDSO: страница с clock_gettime/gettimeofday/time/cpu на базе `user-clock.cpp`; `AT_SYSINFO_EHDR`
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
