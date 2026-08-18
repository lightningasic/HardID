# HardID fuzz targets (GCC ASan/UBSan, no libFuzzer needed)
CC ?= gcc
SAN = -fsanitize=address,undefined -g -O1
CORE = ../core

# Full-surface harness: every untrusted-input parser in core/.
FULL_SRC = fuzz_full.c \
	$(CORE)/psbt.c $(CORE)/clearsign.c $(CORE)/keccak.c $(CORE)/eip712.c \
	$(CORE)/hkdf.c $(CORE)/base58.c $(CORE)/cbor.c $(CORE)/bip39.c \
	$(CORE)/bip32.c $(CORE)/sha512.c $(CORE)/linkproto.c $(CORE)/ctap2.c \
	$(CORE)/fido_ctaphid.c $(CORE)/fido_core.c $(CORE)/tx_asm.c \
	$(CORE)/secp256r1.c $(CORE)/secp256k1.c $(CORE)/rfc6979.c \
	$(CORE)/se_mock.c $(CORE)/app_registry.c $(CORE)/app_catalog.c \
	$(CORE)/signsvc.c $(CORE)/ecdsa.c

all: fuzz_parsers fuzz_full

fuzz_parsers: fuzz_parsers.c $(CORE)/psbt.c $(CORE)/clearsign.c $(CORE)/keccak.c $(CORE)/eip712.c $(CORE)/hkdf.c $(CORE)/base58.c $(CORE)/cbor.c
	$(CC) $(SAN) -o $@ $^

fuzz_full: $(FULL_SRC)
	$(CC) $(SAN) -o $@ $(FULL_SRC)

run: fuzz_parsers fuzz_full
	./fuzz_parsers 100000
	./fuzz_full 200000

clean:
	rm -f fuzz_parsers fuzz_full

.PHONY: all run clean
