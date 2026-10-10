#!/usr/bin/env bash
# Собирает Linux-payloads для тестов совместимости Nomilia:
#   musl (из исходников) -> busybox static + busybox dynamic + hello-dynamic.
# Вызывается из .github/workflows/payloads.yml; можно запускать и локально.
# Результат: $OUT_DIR/sysroot/bin, $OUT_DIR/sysroot/lib, $OUT_DIR/manifest.txt.
# Стадии: musl busybox-static busybox-dynamic hello sysroot smoke manifest
# (локально можно перезапускать частично: STAGES="busybox-dynamic smoke").

set -euo pipefail

MUSL_VERSION="${MUSL_VERSION:-1.2.5}"
BUSYBOX_VERSION="${BUSYBOX_VERSION:-1.36.1}"
ARCH="$(uname -m)"
LDSO_NAME="ld-musl-${ARCH}.so.1"

SRC_DIR="${SRC_DIR:-$PWD/_src}"
TOOLCHAIN_DIR="${TOOLCHAIN_DIR:-$PWD/toolchain}"
OUT_DIR="${OUT_DIR:-$PWD/payload}"
JOBS="${JOBS:-$(nproc)}"
STAGES="${STAGES:-musl busybox-static busybox-dynamic hello sysroot smoke manifest}"

MUSL_PREFIX="$TOOLCHAIN_DIR/musl"
MUSL_GCC="$MUSL_PREFIX/bin/musl-gcc"
SYSROOT="$OUT_DIR/sysroot"
STAMPS="$OUT_DIR/.stamps"
mkdir -p "$STAMPS"
SCRIPT_HASH="$(sha256sum "$0" | cut -d' ' -f1)"

# штамп привязан к хэшу скрипта: правки инвалидируют сделанные стадии
stage_done() { [ -f "$STAMPS/$1" ] && [ "$(cat "$STAMPS/$1" 2>/dev/null)" = "$SCRIPT_HASH" ]; }
stage_start() { rm -f "$STAMPS/$1"; }

fetch() { # fetch <url> <file>
    curl -fsSL --retry 3 --connect-timeout 20 -o "$SRC_DIR/$2" "$1"
}

stage_musl() {
    stage_start musl
    rm -rf "$SRC_DIR/musl-$MUSL_VERSION" "$MUSL_PREFIX"
    mkdir -p "$SRC_DIR" "$MUSL_PREFIX"
    fetch "https://musl.libc.org/releases/musl-$MUSL_VERSION.tar.gz" "musl.tar.gz"
    tar -C "$SRC_DIR" -xzf "$SRC_DIR/musl.tar.gz"
    (
        cd "$SRC_DIR/musl-$MUSL_VERSION"
        ./configure --prefix="$MUSL_PREFIX"
        make -j"$JOBS" >/dev/null
        make install
    )
    # musl-gcc собирает с -nostdinc, поэтому UAPI-заголовки ядра (не зависят от libc)
    # кладём прямо в префикс musl. linux-libc-dev раскладывает UAPI не только в linux/,
    # но и в mtd/, scsi/ и пр. — копируем каталоги-владения, разыменовывая симлинки.
    inc="$MUSL_PREFIX/include"
    uapi_dirs="$(dpkg-query -L linux-libc-dev 2>/dev/null | sed -n 's|^/usr/include/\([^/]*\)/.*|\1|p' | sort -u)"
    [ -n "$uapi_dirs" ] || uapi_dirs="linux asm-generic drm misc mtd rdma regulator scsi sound video xen"
    for d in $uapi_dirs; do
        case "$d" in *-linux-*) continue;; esac
        [ -d "/usr/include/$d" ] && cp -rL "/usr/include/$d" "$inc/$d"
    done
    multiarch="$(gcc -print-multiarch 2>/dev/null || true)"
    if [ -d "/usr/include/$multiarch/asm" ]; then
        cp -rL "/usr/include/$multiarch/asm" "$inc/asm"
    elif [ -d /usr/include/asm ]; then
        cp -rL /usr/include/asm "$inc/asm"
    else
        echo "warning: no kernel asm headers found" >&2
    fi
    "$MUSL_GCC" --version >/dev/null  # sanity: wrapper рабочий
    echo "$SCRIPT_HASH" > "$STAMPS/musl"
}

build_busybox() { # build_busybox <stage> <kind> <out-name>
    local st="$1" kind="$2" out="$3"
    stage_start "$st"
    rm -rf "$SRC_DIR/busybox-$BUSYBOX_VERSION"
    [ -f "$SRC_DIR/busybox.tar.bz2" ] || fetch "https://busybox.net/downloads/busybox-$BUSYBOX_VERSION.tar.bz2" "busybox.tar.bz2"
    tar -C "$SRC_DIR" -xjf "$SRC_DIR/busybox.tar.bz2"
    (
        cd "$SRC_DIR/busybox-$BUSYBOX_VERSION"
        make -s defconfig
        # defconfig не включает статическую сборку — задаём вариант явно.
        if [ "$kind" = static ]; then
            sed -i 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
        else
            sed -i 's/^CONFIG_STATIC=y/# CONFIG_STATIC is not set/' .config
        fi
        # CONFIG_TC не собирается с UAPI ядра >= 6.8 (CBQ удалён из заголовков).
        sed -i 's/^CONFIG_TC=y/# CONFIG_TC is not set/' .config
        make -j"$JOBS" CC="$MUSL_GCC" >/dev/null
        cp busybox "$SYSROOT/bin/$out"
    )
    echo "$SCRIPT_HASH" > "$STAMPS/$st"
}

stage_busybox_static() { build_busybox busybox-static static busybox; }

stage_busybox_dynamic() { build_busybox busybox-dynamic dynamic busybox-dynamic; }

stage_hello() {
    stage_start hello
    # exit 0 только если сообщение реально ушло в stdout: ловит сломанный
    # writev/stdio на целевой ОС (musl флашит stdio через writev).
    cat > "$SRC_DIR/hello.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>

int main(void) {
    if(printf("hello from a musl dynamic binary (pid %ld)\n", (long)getpid()) < 0)
        return 1;
    if(fflush(stdout) || ferror(stdout))
        return 1;
    return 0;
}
EOF
    "$MUSL_GCC" -O2 -o "$SYSROOT/bin/hello-dynamic" "$SRC_DIR/hello.c"
    "$MUSL_GCC" -static -O2 -o "$SYSROOT/bin/hello-static" "$SRC_DIR/hello.c"
    echo "$SCRIPT_HASH" > "$STAMPS/hello"
}

stage_sysroot() {
    stage_start sysroot
    # лоадер musl — это сам libc.so; в sysroot он живёт под каноническим именем ld-musl-*.
    cp "$MUSL_PREFIX/lib/libc.so" "$SYSROOT/lib/$LDSO_NAME"
    # musl-бинарники ссылаются на libc по этому SONAME; загрузчик находит libc в самом себе.
    ln -sf "$LDSO_NAME" "$SYSROOT/lib/libc.musl-${ARCH}.so.1"
    echo "$SCRIPT_HASH" > "$STAMPS/sysroot"
}

stage_smoke() {
    stage_start smoke
    out="$("$SYSROOT/bin/busybox" echo hello-static)"
    [ "$out" = "hello-static" ] || { echo "FAIL: static busybox" >&2; exit 1; }
    "$SYSROOT/bin/busybox" ls / >/dev/null
    out="$("$SYSROOT/bin/busybox" sh -c 'echo pipe-check | wc -c')"
    [ "$out" = "11" ] || { echo "FAIL: static busybox sh/pipe" >&2; exit 1; }

    ldso="$SYSROOT/lib/$LDSO_NAME"
    out="$("$ldso" --library-path "$SYSROOT/lib" "$SYSROOT/bin/hello-dynamic")"
    echo "$out" | grep -q '^hello from a musl dynamic binary (pid [0-9]*)$' \
        || { echo "FAIL: dynamic hello" >&2; exit 1; }
    out="$("$ldso" --library-path "$SYSROOT/lib" "$SYSROOT/bin/busybox-dynamic" echo hello-dynamic)"
    [ "$out" = "hello-dynamic" ] || { echo "FAIL: dynamic busybox" >&2; exit 1; }
    out="$("$ldso" --library-path "$SYSROOT/lib" "$SYSROOT/bin/busybox-dynamic" sh -c 'echo hi | wc -c')"
    [ "$out" = "3" ] || { echo "FAIL: dynamic busybox sh/pipe" >&2; exit 1; }

    # PT_INTERP у динамических бинарников должен быть дефолтным линуксовым путём musl.
    for bin in busybox-dynamic hello-dynamic; do
        interp="$(readelf -l "$SYSROOT/bin/$bin" | sed -n 's/.*Requesting program interpreter: \(.*\)]/\1/p')"
        [ "$interp" = "/lib/$LDSO_NAME" ] || { echo "FAIL: PT_INTERP of $bin = $interp" >&2; exit 1; }
    done
    echo "$SCRIPT_HASH" > "$STAMPS/smoke"
}

stage_manifest() {
    stage_start manifest
    {
        echo "Nomilia linux-compat payloads"
        echo "arch: $ARCH"
        echo "musl: $MUSL_VERSION"
        echo "busybox: $BUSYBOX_VERSION"
        echo "built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo
        (cd "$SYSROOT" && find . -type f -o -type l | sort | while read -r f; do
            printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"
        done)
    } > "$OUT_DIR/manifest.txt"
    echo "$SCRIPT_HASH" > "$STAMPS/manifest"
}

mkdir -p "$SYSROOT/bin" "$SYSROOT/lib"
for st in $STAGES; do
    if stage_done "$st"; then
        echo "--- stage $st: done (skip)"
        continue
    fi
    echo "=== stage $st ==="
    "stage_${st//-/_}"
done
[ -f "$OUT_DIR/manifest.txt" ] && cat "$OUT_DIR/manifest.txt"
echo "OK: payloads in $OUT_DIR"
