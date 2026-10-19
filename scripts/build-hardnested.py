#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 NFClab contributors.
"""Build offline hardnested from the checked-out PM3 reference, without its UI.

Keep upstream sources and copyright notices intact. Generated copies remove
client-only includes and replace RF acquisition with a ciphertext-only stream. All
algorithm code, SIMD dispatch and tables remain upstream's implementation.
"""
from pathlib import Path
import platform
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / 'reference/proxmark3'
BUILD = ROOT / 'build/hardnested'
HOST = ROOT / 'host/hardnested'


def adapted(source, target, *, driver=False):
    text = source.read_text()
    excluded = {'commonutil.h', 'comms.h', 'proxmark3.h', 'ui.h', 'util_posix.h',
                'util.h', 'fileutils.h', 'cmdhfmfhard.h'}
    for header in excluded:
        text = re.sub(r'^#include "' + re.escape(header) + r'"[^\n]*\n', '', text, flags=re.M)
    if driver:
        start = text.index('static int acquire_nonces(')
        end = text.index('static inline bool invariant_holds(', start)
        text = text[:start] + (HOST / 'stream.inc').read_text() + '\n' + text[end:]
    target.write_text('#include "compat.h"\n' + text)


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    deps = REF / 'client/deps/hardnested'
    driver = BUILD / 'driver.c'
    brute = BUILD / 'bruteforce.c'
    adapted(REF / 'client/src/cmdhfmfhard.c', driver, driver=True)
    adapted(deps / 'hardnested_bruteforce.c', brute)
    base = ['gcc', '-O3', '-std=gnu11', '-Wall', '-Wextra', '-pthread',
            '-Wno-sign-compare', '-Wno-implicit-fallthrough', '-Wno-type-limits',
            '-I' + str(HOST), '-I' + str(deps), '-I' + str(REF / 'common'),
            '-I' + str(REF / 'include')]
    sources = [driver, brute, HOST / 'main.c', REF / 'common/crapto1/crapto1.c',
               REF / 'common/crapto1/crypto1.c', REF / 'common/bucketsort.c']
    objects = []
    arch = platform.machine().lower()
    if arch in ('x86_64', 'amd64', 'i686'):
        switches = [('-DNOSIMD_BUILD', '-mno-mmx', '-mno-sse2', '-mno-avx', '-mno-avx2', '-mno-avx512f'),
                    ('-mmmx', '-mno-sse2', '-mno-avx', '-mno-avx2', '-mno-avx512f'),
                    ('-msse2', '-mno-avx', '-mno-avx2', '-mno-avx512f'),
                    ('-mavx', '-mno-avx2', '-mno-avx512f'),
                    ('-mavx2', '-mno-avx512f'), ('-mavx512f',)]
    elif arch in ('aarch64', 'arm64'):
        switches = [('-DNOSIMD_BUILD',), ()]
    else:
        raise SystemExit('Initial hardnested build supports x86 and ARM64 hosts')
    for index, flags in enumerate(switches):
        for name in ('hardnested_bf_core', 'hardnested_bitarray_core'):
            obj = BUILD / f'{name}-{index}.o'
            subprocess.run(base + list(flags) + ['-c', str(deps / (name + '.c')), '-o', str(obj)], check=True)
            objects.append(obj)
    subprocess.run(base + [str(p) for p in sources + objects] +
                   ['-lm', '-llz4', '-lbz2', '-o', str(ROOT / 'build/m1-hardnested')], check=True)


if __name__ == '__main__':
    main()
