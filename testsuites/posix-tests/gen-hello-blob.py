#!/usr/bin/env python3
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, 'rb') as f:
    data = f.read()

with open(dst, 'w') as f:
    f.write('// генерируется gen-hello-blob.py из nomilia-linux-hello.elf\n')
    f.write('#include <stdint.h>\n\n')
    f.write('const uint8_t nomilia_linux_hello_blob[] __attribute__((aligned(16))) = {')
    for i in range(0, len(data), 16):
        f.write('\n\t' + ', '.join(str(b) for b in data[i:i + 16]) + ',')
    f.write('\n};\n\n')
    f.write(f'const unsigned long nomilia_linux_hello_size = {len(data)};\n')
