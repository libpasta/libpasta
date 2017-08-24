libpasta - Password Storage Algorithms
===================================

#### _Making Password Painless_

This library aims to be a all-in-one solution for password storage. In
particular, we aim to provide:

 - Easy-to-use password storage with sane defaults.
 - Tools to provide parameter tuning for different use cases.
 - Automatic migration of password to new algorithms

# Design Theory

libpasta is designed to be as simple to use as possible. Most users would rather
not have to choose which password algorithm to use, nor understand what 
are the best parameter choices. 

Therefore, we take great care to make this all opaque to the user:

```rust
    
    let password = "hunter2".owned();
    let hash = hash_password(password);
    // store hash in database
    // ... time passes, user returns ...
    let password = "hunter2".owned();
    assert!(verify_password(password, &hash));
```

Internally, we leverage Rust's type system for security. We take ownership
of the password and wrap it in a `Cleartext` 



### The rest of this README is dedicated to documenting the code. For more about the library, and examples, please see: https://libpasta.github.io/

