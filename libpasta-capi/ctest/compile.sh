#!/bin/sh

set -ex

cargo build --release  --manifest-path ../Cargo.toml
${CC:="gcc"} -DDEBUG -ggdb -o test_c test.c -Wall -I../include  -L../target/release/ -lpasta
${CXX:="g++"} -DDEBUG -std=c++11 -ggdb -o test_cpp test.cpp -Wall -I../include  -L../target/release/ -lpasta
