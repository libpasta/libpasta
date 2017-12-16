#include <stdbool.h>

extern char * hash_password(const char *password);
extern bool verify_password(const char *hash, const char *password);
extern void free_string(char *);
extern char * read_password(const char *prompt);

extern bool verify_password_update_hash(char *hash, const char *password, char **newhash);

extern char * migrate_hash(char *hash);
