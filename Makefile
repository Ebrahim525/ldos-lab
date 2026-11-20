ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# The kernel program and three userspace tools.
all: build/defense.bpf.o build/loader build/pulse build/tcpwatch

build:
	mkdir -p build

# -g supplies the BTF metadata libbpf needs when loading the BPF object.
build/defense.bpf.o: bpf/defense.bpf.c bpf/shared.h | build
	clang -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(shell gcc -dumpmachine) -c $< -o $@

build/loader: bpf/loader.c bpf/shared.h | build
	cc -O2 -Wall -Wextra $< -o $@ -lbpf -lelf -lz

build/pulse: traffic/pulse.c | build
	cc -O2 -Wall -Wextra $< -o $@

build/tcpwatch: traffic/tcpwatch.c | build
	cc -O2 -Wall -Wextra $< -o $@

clean:
	rm -rf build
