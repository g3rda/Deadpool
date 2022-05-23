CFLAGS = -Og -ggdb -Wall -static
CXXFLAGS = $(CFLAGS) -std=c++11

# All tests were taken from NIST, 2001 test vectors:
# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf


AES128_KEY             = 2b7e151628aed2a6abf7158809cf4f3c

.PHONY: clean all

all: aes128-x86-64

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

libaes.a: aes.o
	$(AR) $(ARFLAGS) $@ $^

aes_whitebox_compiler: aes-whitebox/aes_whitebox_compiler.o
	$(CXX) $(LDFLAGS) $^ -o $@ -lntl

prepare:
	./aes_whitebox_compiler aes128 $(AES128_KEY)
	mv aes_whitebox_tables.cc aes-whitebox/

aes128-x86-64: aes_whitebox_compiler prepare
	$(CXX) $(CXXFLAGS) -c aes-whitebox/aes_whitebox.cc -o aes-whitebox/aes_whitebox.o
	$(CC) $(CFLAGS) -c aes128.c -o aes128.o
	$(CC) $(LDFLAGS) -static aes-whitebox/aes_whitebox.o aes128.o -o $@ 

aes128-aarch64: aes_whitebox_compiler prepare
	aarch64-linux-gnu-g++ $(CXXFLAGS) -c aes-whitebox/aes_whitebox.cc -o aes-whitebox/aes_whitebox.o
	aarch64-linux-gnu-g++ $(CFLAGS) -c aes128.c -o aes128.o
	aarch64-linux-gnu-gcc $(LDFLAGS) -static aes-whitebox/aes_whitebox.o aes128.o -o $@ 

aes128-arm: aes_whitebox_compiler prepare 
	arm-linux-gnueabi-g++ $(CXXFLAGS) -c aes-whitebox/aes_whitebox.cc -o aes-whitebox/aes_whitebox.o
	arm-linux-gnueabi-g++ $(CFLAGS) -c aes128.c -o aes128.o
	arm-linux-gnueabi-gcc $(LDFLAGS) -static aes-whitebox/aes_whitebox.o aes128.o -o $@ 

aes128-powerpc: aes_whitebox_compiler prepare 
	powerpc-linux-gnu-g++ $(CXXFLAGS) -c aes-whitebox/aes_whitebox.cc -o aes-whitebox/aes_whitebox.o
	powerpc-linux-gnu-g++ $(CFLAGS) -c aes128.c -o aes128.o
	powerpc-linux-gnu-gcc $(LDFLAGS) -static aes-whitebox/aes_whitebox.o aes128.o -o $@ 

aes128-mips: aes_whitebox_compiler prepare 
	mips-linux-gnu-g++ $(CXXFLAGS) -c aes-whitebox/aes_whitebox.cc -o aes-whitebox/aes_whitebox.o
	mips-linux-gnu-g++ $(CFLAGS) -c aes128.c -o aes128.o
	mips-linux-gnu-gcc $(LDFLAGS) -static aes-whitebox/aes_whitebox.o aes128.o -o $@ 

clean:
	rm -f *.o *.a aes-whitebox/*.o aes-whitebox/*.a aes-whitebox/aes_whitebox_tables.cc aes_whitebox_compiler aes128-x86-64 aes128-aarch64 aes128-arm aes128-powerpc aes128-mips
