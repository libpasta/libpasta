#include <stdbool.h>

extern char * hash_password(const char *password);
extern bool verify_password(const char* hash, const char *password);
extern void free_string(const char *);
extern char * read_password(const char *prompt);