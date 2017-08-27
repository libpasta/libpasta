extern crate libpasta;

use libpasta::config;

mod common;

#[test]
pub fn test_config_file() {
    common::init_test();
    config::from_file(common::get_test_path(".libpasta.yaml"));
    println!("{}", config::to_string());
    assert!(config::to_string().contains("ln: \"11\""));
}
