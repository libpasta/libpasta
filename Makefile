VERSION = 0.0.5

default: libpasta.so

libpasta.so: Cargo.toml libpasta-capi/Cargo.toml
	cargo build --release --manifest-path libpasta-capi/Cargo.toml
	cp libpasta-capi/target/release/libpasta.so .

install: libpasta.so
	sudo cp libpasta.so /usr/lib/libpasta.so.$(VERSION)

uninstall:
	sudo rm /usr/lib/libpasta.so.*

.PHONY: uninstall
