#include <assert.h>
#include <stdio.h>
#include "pasta.h"

int main(void) {
    char *hash;
    hash = hash_password("hello123");
    assert (verify_password(hash, "hello123"));
    printf("\x1b[1;32mC test passed\x1b[m\n");
    free_string(hash);
    return 0;
}