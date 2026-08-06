# HardID component — ESP32-S3 bring-up build.
# Same clean-room core as the P4 build (single source of truth: ../../core),
# but the SE backend is core/se_mock.c instead of the dual-ACL16 SPI transport
# (hal/se_composite.c + se_acl16.c + se_transport_esp32*.c). No ACL16 hardware
# on this first S3 port.

set(HARDID_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")

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
        "${HARDID_ROOT}/core/rfc6979.c"
        "${HARDID_ROOT}/core/ecdsa.c"
        "${HARDID_ROOT}/core/clearsign.c"
        "${HARDID_ROOT}/core/eip712.c"
        "${HARDID_ROOT}/core/psbt.c"
        "${HARDID_ROOT}/core/pin.c"
        "${HARDID_ROOT}/core/policy.c"
        "${HARDID_ROOT}/core/multisig.c"
        "${HARDID_ROOT}/core/boot.c"
        "${HARDID_ROOT}/core/se_mock.c"
        "secp256k1_s3.c"
        "font7.c"
        "display.c"
        "touch.c"
        "inter.c"
        "keypad.c"
        "screen.c"
        "ui.c"
        "board_s3.c"
    INCLUDE_DIRS
        "${HARDID_ROOT}/core"
        "${CMAKE_CURRENT_SOURCE_DIR}"
    REQUIRES
        mbedtls esp_lcd esp_driver_spi esp_driver_gpio esp_driver_i2c
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC ESP_PLATFORM=1)
