VERSION = 0.0.6

all: libpasta.so libpasta.a

clean:
	rm -rf build/

force:
	cargo clean --manifest-path libpasta-capi/Cargo.toml
	make clean
	make all

libpasta: Cargo.toml libpasta-capi/Cargo.toml
	cargo build --release --manifest-path libpasta-capi/Cargo.toml

libpasta.%: libpasta
	mkdir -p build
	cp libpasta-capi/target/release/$@ build/$@

install: libpasta.so
	sudo install -D -m0755 build/libpasta.so /usr/lib/libpasta.so.${VERSION}
	sudo ln -sf /usr/lib/libpasta.so.${VERSION} /usr/lib/libpasta.so

uninstall:
	sudo rm /usr/lib/libpasta.so.$(VERSION)

test:
	cd libpasta-capi/ctest && sh compile.sh && LD_LIBRARY_PATH=../target/debug ./test

.PHONY: clean uninstall
