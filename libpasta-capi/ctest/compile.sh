#!/bin/sh

set -ex

cargo build --release --manifest-path ../Cargo.toml
g++ -DDEBUG -g -o test test.cpp -Wall -I../include -L../target/release -lpasta
