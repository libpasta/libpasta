libpasta - Password Storage Algorithms
===================================

[![Development][badge-ci]][badge-ci-link]


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

## Comparison

A brief comparison between libpasta and some alternatives can be found
in [the documentation](https://libpasta.github.io/introduction/alternatives/).


## Installation

To build the `libpasta` system library, simply run `make`. This outputs
a `build/libpasta.so` file (or system-appropriate filename).

You can also try running `make install` to automatically move it to the correct
location.

The library is generated as a result of building [libpasta-capi](libpasta-capi/),
which is a C-API wrapper built around the Rust code.

### The rest of this README is dedicated to developing the code. For more about the library, and examples, please see: https://libpasta.github.io/ or the [documentation](https://docs.rs/libpasta/).

## Roadmap

libpasta is still currently in maintenance mode. The current API is at 0.1.1
and is reasonably stable. But at this time no future improvements are planned.

## Contributing

Please feel free to open new issues or pull requests for any bugs found, feature
requests, or general suggestions.

We very much welcome any contributions, and simply ask for patience and civility
when dealing with any disagreements or problems.

## License

libpasta is licensed under the MIT license: [License](license).


[badge-ci]: https://github.com/libpasta/libpasta/workflows/Rust%20CI%20checks/badge.svg
[badge-ci-link]: https://github.com/libpasta/libpasta/actions?query=workflow%3A%22Rust+CI+checks%22+branch%3Amain
[coverage_badge]: https://codecov.io/gh/libpasta/libpasta/graph/badge.svg
[coverage_report]: https://codecov.io/gh/libpasta/libpasta/
[documentation]: https://libpasta.github.io/doc/libpasta/
[license]: LICENSE.md
