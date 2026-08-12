# HardID fuzz targets (GCC ASan/UBSan, no libFuzzer needed)
CC ?= gcc
SAN = -fsanitize=address,undefined -g -O1
CORE = ../core

all: fuzz_parsers

fuzz_parsers: fuzz_parsers.c $(CORE)/psbt.c $(CORE)/clearsign.c $(CORE)/keccak.c $(CORE)/eip712.c $(CORE)/hkdf.c $(CORE)/base58.c $(CORE)/cbor.c
	$(CC) $(SAN) -o $@ $^

run: fuzz_parsers
	./fuzz_parsers 100000

clean:
	rm -f fuzz_parsers

.PHONY: all run clean
