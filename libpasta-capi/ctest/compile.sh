#!/bin/sh

set -ex

cargo build --release --manifest-path ../Cargo.toml
g++ -DDEBUG -std=c++11 -g -o test test.cpp -Wall -I../include -L../target/release -lpasta
