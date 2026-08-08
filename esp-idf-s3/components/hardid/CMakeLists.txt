# HardID component — ESP32-S3 bring-up build.
# Same clean-room core as the P4 build (single source of truth: ../../core),
# but the SE backend is core/se_mock.c instead of the dual-ACL16 SPI transport
# (hal/se_composite.c + se_acl16.c + se_transport_esp32*.c). No ACL16 hardware
# on this first S3 port.

set(HARDID_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")

if(CONFIG_HARDID_SE_ACL16)
    set(HARDID_SE_SRCS
        "${HARDID_ROOT}/hal/se_acl16.c"
        "${HARDID_ROOT}/hal/se_composite.c"
        "${HARDID_ROOT}/hal/se_transport.c"
        "${HARDID_ROOT}/hal/se_transport_esp32.c"
        "${HARDID_ROOT}/hal/se_transport_esp32_i2c.c"
    )
else()
    set(HARDID_SE_SRCS "${HARDID_ROOT}/core/se_mock.c")
endif()

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
        "${HARDID_ROOT}/core/app_registry.c"
        "${HARDID_ROOT}/core/signsvc.c"
        "${HARDID_ROOT}/core/boot.c"
        "${HARDID_ROOT}/core/linkproto.c"
        "${HARDID_ROOT}/core/linksvc.c"
        ${HARDID_SE_SRCS}
        "secp256k1_s3.c"
        "font7.c"
        "font8x16.c"
        "display.c"
        "touch.c"
        "inter.c"
        "keypad.c"
        "screen.c"
        "link_esp.c"
        "ui.c"
        "board_s3.c"
    INCLUDE_DIRS
        "${HARDID_ROOT}/core"
        "${CMAKE_CURRENT_SOURCE_DIR}"
    REQUIRES
        mbedtls esp_lcd esp_driver_spi esp_driver_gpio esp_driver_i2c
        esp_driver_usb_serial_jtag spi_flash
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC ESP_PLATFORM=1)
