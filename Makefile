VERSION = 0.0.5

all: libpasta.so libpasta.a

clean:
	rm -rf build/

force:
	cargo clean --manifest-path libpasta-capi/Cargo.toml
	make clean
	make default

libpasta: Cargo.toml libpasta-capi/Cargo.toml
	cargo build --release --manifest-path libpasta-capi/Cargo.toml

libpasta.%: libpasta
	mkdir -p build
	cp libpasta-capi/target/release/$@ build/$@

install: libpasta.so
	sudo cp build/libpasta.so /usr/lib/libpasta.so.$(VERSION)

uninstall:
	sudo rm /usr/lib/libpasta.so.*

.PHONY: clean uninstall
