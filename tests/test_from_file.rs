extern crate libpasta;

use libpasta::config;

mod common;

#[test]
pub fn test_config_file() {
    common::init_test();
    let config = config::Config::from_file(common::get_test_path(".libpasta.yaml")).unwrap();
    println!("{}", config.to_string());
    assert!(config.to_string().contains("ln: \"11\""));
}
