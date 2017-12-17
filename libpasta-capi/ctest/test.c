#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "pasta.h"

int main(void) {
    char *hash;
    hash = hash_password("hello123");
    assert (verify_password(hash, "hello123"));
    free_string(hash);

    hash = "$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa";
    hash = migrate_hash(hash);
    printf("New hash: %s\n", hash);
    free_string(hash);

    hash = "$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa";
    char *newhash;
    bool res = verify_password_update_hash(hash, "my password", &newhash);
    assert (res);
    printf("New hash: %s\n", newhash);
    assert (strcmp(newhash, hash) != 0);
    assert (verify_password(newhash, "my password"));
    // free_string(hash) // dont need to free this since it's static
    free_string(newhash);

    assert (!verify_password_update_hash(hash, "not my password", &newhash));
    printf("New hash: %s\n", newhash);
    free_string(newhash);

    printf("\x1b[1;32mC test passed\x1b[m\n");
    return 0;
}