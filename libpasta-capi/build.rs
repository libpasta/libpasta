extern crate cbindgen;

use std::env;

use cbindgen::{Builder, Config, Language};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let config_c = Config { language: Language::C, .. Config::default() };
    let config_cpp = Config { language: Language::Cxx, .. Config::default() };


    Builder::new()
          .with_crate(&crate_dir)
          .with_config(config_cpp)
          .with_parse_deps(true)
          .with_parse_include(&["libpasta"])
          .with_parse_exclude(&["winapi"])
          // .with_parse_expand(&["pasta"])
          .generate()
          .expect("Unable to generate bindings")
          .write_to_file("include/pasta-bindings.hpp");
    Builder::new()
          .with_crate(&crate_dir)
          .with_config(config_c)
          .with_parse_deps(true)
          .with_parse_include(&["libpasta"])
          .with_parse_exclude(&["winapi"])
          // .with_parse_expand(&["pasta"])
          .generate()
          .expect("Unable to generate bindings")
          .write_to_file("include/pasta-bindings.h");
}
