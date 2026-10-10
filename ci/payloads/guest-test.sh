#!/usr/bin/env bash
# Ин-гвест CI-скрипт (выполняется ci-boot внутри Nomilia по serial-JSON).
# stdout попадает в лог джобы; ненулевой exit валит шаг CI.

echo "linux-payloads: hello-dynamic via PT_INTERP"
/usr/payload/bin/hello-dynamic
rc1=$?
echo "linux-payloads: hello-dynamic exit $rc1"

echo "linux-payloads: busybox-dynamic via PT_INTERP"
/usr/payload/bin/busybox-dynamic echo BUSYBOX_DYNAMIC_OK
rc2=$?
echo "linux-payloads: busybox-dynamic exit $rc2"

echo "linux-payloads: busybox static session"
/usr/payload/bin/busybox sh -c 'echo STATIC_BUSYBOX_$((17+25))'
rc3=$?
echo "linux-payloads: busybox-static exit $rc3"

echo "linux-payloads: loader present"
/usr/payload/bin/busybox ls -l /lib/ld-musl-x86_64.so.1 /usr/payload/bin/
rc4=$?
echo "linux-payloads: loader check exit $rc4"

if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && [ "$rc3" -eq 0 ] && [ "$rc4" -eq 0 ]; then
        echo "linux-payloads: ALL OK"
        exit 0
fi
echo "linux-payloads: FAILED (rc1=$rc1 rc2=$rc2 rc3=$rc3 rc4=$rc4)"
exit 1
