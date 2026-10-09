#!/usr/bin/env python3
import sys, os

src, dst = sys.argv[1], sys.argv[2]
with open(src, 'rb') as f:
    data = f.read()

# nomilia-linux-<stem>.elf -> nomilia_linux_<stem>_{blob,size}
base = os.path.basename(src)
assert base.startswith('nomilia-linux-') and base.endswith('.elf'), base
prefix = 'nomilia_linux_' + base[len('nomilia-linux-'):-len('.elf')].replace('-', '_')

with open(dst, 'w') as f:
    f.write(f'// генерируется gen-hello-blob.py из {base}\n')
    f.write('#include <stdint.h>\n\n')
    f.write(f'const uint8_t {prefix}_blob[] __attribute__((aligned(16))) = {{')
    for i in range(0, len(data), 16):
        f.write('\n\t' + ', '.join(str(b) for b in data[i:i + 16]) + ',')
    f.write('\n};\n\n')
    f.write(f'const unsigned long {prefix}_size = {len(data)};\n')
