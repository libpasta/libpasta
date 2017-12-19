#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "pasta.h"

void test_hash_and_verify() {
    char *hash;
    hash = hash_password("hello123");
    assert (verify_password(hash, "hello123"));
    assert (!verify_password(hash, "hello1234"));
    free_string(hash);
}

void test_migrate() {
    char *hash = "$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa";
    hash = migrate_hash(hash);
    // printf("New hash: %s\n", hash);
    free_string(hash);

    hash = "$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa";
    char *newhash;
    bool res = verify_password_update_hash_in_place(hash, "my password", &newhash);
    assert (res);
    // printf("New hash: %s\n", newhash);
    assert (strcmp(newhash, hash) != 0);
    assert (verify_password(newhash, "my password"));
    // free_string(hash) // dont need to free this since it's static
    free_string(newhash);

    assert (!verify_password_update_hash_in_place(hash, "not my password", &newhash));
    // printf("New hash: %s\n", newhash);
    free_string(newhash);
}

void test_config() {
    Primitive *prim = default_bcrypt();
    Config *config = config_with_primitive(prim);
    char *hash = config_hash_password(config, "hello123");
    assert (config_verify_password(config, hash, "hello123"));
    assert (!config_verify_password(config, hash, "hunter2"));
}

void test_edge_cases() {
    hash_password("");
    hash_password("\x00");
}
int main(void) {
    test_hash_and_verify();
    test_migrate();
    test_config();
    test_edge_cases();
    printf("\x1b[1;32mC test passed\x1b[m\n");
    return 0;
}
