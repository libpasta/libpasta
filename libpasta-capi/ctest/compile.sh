#!/bin/sh

set -ex

cargo build --release --manifest-path ../Cargo.toml
gcc -DDEBUG -g -o test test.c -Wall -I../include -L../target/release -lpasta
