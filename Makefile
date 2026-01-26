.PHONY: clean
MUSL=musl/bin/musl-gcc
MUSL_VERSION=1.2.5
CC=${MUSL}
CFLAGS=-fno-strict-aliasing -static -Ofast -O3 -Wall -Wextra -Wno-pointer-arith -Wno-maybe-uninitialized
default: $(MUSL)
	${CC} ${CFLAGS} bgp_message.c bgp.c rib.c kernel_routing.c config.c -o ltbgp
	strip ltbgp
$(MUSL):
	curl -so musl.tar.gz https://musl.libc.org/releases/musl-${MUSL_VERSION}.tar.gz
	tar xf musl.tar.gz
	rm musl.tar.gz
	mv musl-${MUSL_VERSION} musl
	sh -c 'cd musl; ./configure --prefix="$$(pwd)"; make install -j$$(nproc)'
	cp -r /usr/include/linux musl/include
	cp -r /usr/include/asm-generic musl/include
	cp -r /usr/include/asm-generic musl/include/asm
clean:
	rm -r musl ltbgp
