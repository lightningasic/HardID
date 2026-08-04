# HardID component: all clean-room core + HAL sources.
# Sources live outside this component dir (../../core, ../../hal); we pull
# them in via SRCS with relative paths so there is a single source of truth.

set(HARDID_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

idf_component_register(
    SRCS
        "${HARDID_ROOT}/core/rng.c"
        "${HARDID_ROOT}/core/hkdf.c"
        "${HARDID_ROOT}/core/sha512.c"
        "${HARDID_ROOT}/core/keccak.c"
        "${HARDID_ROOT}/core/seed.c"
        "${HARDID_ROOT}/core/bip39.c"
        "${HARDID_ROOT}/core/bip32.c"
        "${HARDID_ROOT}/core/base58.c"
        "${HARDID_ROOT}/core/secp256k1.c"
        "${HARDID_ROOT}/core/rfc6979.c"
        "${HARDID_ROOT}/core/ecdsa.c"
        "${HARDID_ROOT}/core/clearsign.c"
        "${HARDID_ROOT}/core/eip712.c"
        "${HARDID_ROOT}/core/psbt.c"
        "${HARDID_ROOT}/core/pin.c"
        "${HARDID_ROOT}/core/policy.c"
        "${HARDID_ROOT}/core/multisig.c"
        "${HARDID_ROOT}/core/boot.c"
        "${HARDID_ROOT}/hal/se_transport.c"
        "${HARDID_ROOT}/hal/se_acl16.c"
        "${HARDID_ROOT}/hal/se_composite.c"
        "${HARDID_ROOT}/hal/se_transport_esp32.c"
        "${HARDID_ROOT}/hal/se_transport_esp32_i2c.c"
        "${HARDID_ROOT}/hal/se_board.c"
    INCLUDE_DIRS
        "${HARDID_ROOT}/core"
        "${HARDID_ROOT}/hal"
)

# ESP32-P4 build: use the ESP-IDF transport implementation.
target_compile_definitions(${COMPONENT_LIB} PUBLIC ESP_PLATFORM=1)
