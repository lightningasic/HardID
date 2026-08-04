# OpenShield component: all clean-room core + HAL sources.
# Sources live outside this component dir (../../core, ../../hal); we pull
# them in via SRCS with relative paths so there is a single source of truth.

set(OPENSHIELD_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

idf_component_register(
    SRCS
        "${OPENSHIELD_ROOT}/core/rng.c"
        "${OPENSHIELD_ROOT}/core/hkdf.c"
        "${OPENSHIELD_ROOT}/core/sha512.c"
        "${OPENSHIELD_ROOT}/core/keccak.c"
        "${OPENSHIELD_ROOT}/core/seed.c"
        "${OPENSHIELD_ROOT}/core/bip39.c"
        "${OPENSHIELD_ROOT}/core/bip32.c"
        "${OPENSHIELD_ROOT}/core/base58.c"
        "${OPENSHIELD_ROOT}/core/secp256k1.c"
        "${OPENSHIELD_ROOT}/core/rfc6979.c"
        "${OPENSHIELD_ROOT}/core/ecdsa.c"
        "${OPENSHIELD_ROOT}/core/clearsign.c"
        "${OPENSHIELD_ROOT}/core/eip712.c"
        "${OPENSHIELD_ROOT}/core/psbt.c"
        "${OPENSHIELD_ROOT}/core/pin.c"
        "${OPENSHIELD_ROOT}/core/policy.c"
        "${OPENSHIELD_ROOT}/core/multisig.c"
        "${OPENSHIELD_ROOT}/core/boot.c"
        "${OPENSHIELD_ROOT}/hal/se_transport.c"
        "${OPENSHIELD_ROOT}/hal/se_acl16.c"
        "${OPENSHIELD_ROOT}/hal/se_composite.c"
        "${OPENSHIELD_ROOT}/hal/se_transport_esp32.c"
        "${OPENSHIELD_ROOT}/hal/se_transport_esp32_i2c.c"
        "${OPENSHIELD_ROOT}/hal/se_board.c"
    INCLUDE_DIRS
        "${OPENSHIELD_ROOT}/core"
        "${OPENSHIELD_ROOT}/hal"
)

# ESP32-P4 build: use the ESP-IDF transport implementation.
target_compile_definitions(${COMPONENT_LIB} PUBLIC ESP_PLATFORM=1)
