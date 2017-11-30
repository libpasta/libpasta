libpasta - Password Storage Algorithms
===================================

[![Build Status][build_badge]][build_status]
[![Code Coverage][coverage_badge]][coverage_report]

#### _Making Password Painless_

This library aims to be a all-in-one solution for password storage. In
particular, we aim to provide:

 - Easy-to-use password storage with sane defaults.
 - Tools to provide parameter tuning for different use cases.
 - Automatic migration of password hashes to new algorithms.


## Introduction

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
    if verify_password(password, &hash) {
        // do something
    }
```

### The rest of this README is dedicated to developing the code. For more about the library, and examples, please see: https://libpasta.github.io/ or the [documentation](https://docs.rs/libpasta/).

## Roadmap

libpasta is still currently in development. The current version is `0.0.1`
representing a pre-release. After gathering some initial feedback we will
move to `0.1.0` release, at which point libpasta will be ready to use in 
test environments. We are targetting a stable `1.0.0` release once the API
is stable, and testing reveals no major issues.

## Contributing

libpasta is still in its infancy, and the best way to contribute right now is
to start testing it in new projects.

Please feel free to open new issues or pull requests for any bugs found, feature
requests, or general suggestions.

We very much welcome any contributions, and simply ask for patience and civility
when dealing with any disagreements or problems.

## License

libpasta is licensed under the MIT license: [License](license).


[build_badge]: https://travis-ci.org/libpasta/libpasta.svg?branch=master
[build_status]: https://travis-ci.org/libpasta/libpasta
[coverage_badge]: https://codecov.io/gh/libpasta/libpasta/graph/badge.svg
[coverage_report]: https://codecov.io/gh/libpasta/libpasta/
[documentation]: https://libpasta.github.io/doc/libpasta/
[license]: LICENSE.md
