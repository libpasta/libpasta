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
    char *old_hash = (char *)"$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa";
    char *hash;
    HashUpdateFfi *res = migrate_hash(old_hash);
    switch(res->tag) {
        case HashUpdateFfi::Tag::Updated: hash = res->updated._0; break;
        case HashUpdateFfi::Tag::Ok: assert (false && "Expected a password migration");
        case HashUpdateFfi::Tag::Failed: assert (false && "Problem migrating password");
    }
    assert (strcmp(old_hash, hash) != 0);
    printf("New hash: %s\n", hash);
    free_string(hash);

    hash = (char *)"$2a$10$vI8aWBnW3fID.ZQ4/zo1G.q1lRps.9cGLcZEiGDMVr5yUP1KUOYTa";
    char *newhash;
    res = verify_password_update_hash(hash, "my password");
    switch(res->tag) {
        case HashUpdateFfi::Tag::Updated: newhash = res->updated._0;
        case HashUpdateFfi::Tag::Ok: printf("Password verified\n"); break;
        case HashUpdateFfi::Tag::Failed: assert (false && "Password failed");
    }
    printf("New hash: %s\n", newhash);
    assert (strcmp(newhash, hash) != 0);
    assert (verify_password(newhash, "my password"));
    // free_string(hash) // dont need to free this since it's static
    free_string(newhash);

    assert (verify_password_update_hash(hash, "not my password")->tag == HashUpdateFfi::Tag::Failed);
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
