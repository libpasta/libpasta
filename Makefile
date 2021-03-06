VERSION = 0.1.0-rc1

all: libpasta.so libpasta.a

clean:
	cargo clean --manifest-path libpasta-capi/Cargo.toml
	rm -rf build/

force:
	cargo clean --manifest-path libpasta-capi/Cargo.toml
	make clean
	make all

libpasta: Cargo.toml libpasta-capi/Cargo.toml
	RUSTFLAGS="--print native-static-libs" cargo build --release --manifest-path libpasta-capi/Cargo.toml

libpasta.%: libpasta
	mkdir -p build
	cp libpasta-capi/target/release/$@ build/$@

install: libpasta.so
	sudo install -D -m0755 build/libpasta.so /usr/lib/libpasta.so.${VERSION}
	sudo ln -sf /usr/lib/libpasta.so.${VERSION} /usr/lib/libpasta.so

uninstall:
	sudo rm /usr/lib/libpasta.so.$(VERSION)

test:
	cd libpasta-capi/ctest && sh compile.sh && LD_LIBRARY_PATH=../target/release ./test_c && LD_LIBRARY_PATH=../target/release ./test_cpp

.PHONY: clean uninstall
