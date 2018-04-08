#include <cstdint>
#include <cstdlib>

// Holds possible configuration options
// See the [module level documentation](index.html) for more information.
struct Config;

// Password hashing primitives
//
// Each variant is backed up by different implementation.
// Internally, primitives can either be static values, for example,
// the `lazy_static` generated value `DEFAULT_PRIM`, or dynamically allocated
// variables, which are `Arc<Box<...>>`.
//
// Most operations are expected to be performed using the static functions,
// since most use the default algorithms. However, the flexibilty to support
// arbitrary parameter sets is essential.
struct Primitive;

struct HashUpdateFfi {
  enum class Tag {
    Updated,
    Ok,
    Failed,
  };

  struct Updated_Body {
    char *_0;
  };

  Tag tag;
  union {
    Updated_Body updated;
  };
};

extern "C" {

void config_free(Config *config);

char *config_hash_password(const Config *config, const char *password);

HashUpdateFfi *config_migrate_hash(const Config *config, const char *hash);

Config *config_new();

bool config_verify_password(const Config *config, const char *hash, const char *password);

HashUpdateFfi *config_verify_password_update_hash(const Config *config,
                                                  const char *hash,
                                                  const char *password);

Config *config_with_primitive(const Primitive *prim);

Primitive *default_argon2i();

Primitive *default_bcrypt();

Primitive *default_pbkdf2i();

Primitive *default_scrypt();

void free_Primitive(Primitive *prim);

void free_string(char *s);

char *hash_password(const char *password);

HashUpdateFfi *migrate_hash(const char *hash);

Primitive *new_argon2i(unsigned int passes, unsigned int lanes, unsigned int kib);

Primitive *new_bcrypt(unsigned int cost);

Primitive *new_scrypt(unsigned char log_n, unsigned int r, unsigned int p);

char *read_password(const char *prompt);

bool verify_password(const char *hash, const char *password);

HashUpdateFfi *verify_password_update_hash(const char *hash, const char *password);

} // extern "C"
