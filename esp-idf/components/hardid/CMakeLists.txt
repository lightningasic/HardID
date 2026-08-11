# HardID component — ESP32-P4 build.
# Single source of truth for core + HAL (../../core, ../../hal); the UI
# layer (fonts/display/touch/inter/keypad/screen/link_esp/ui) lives here
# alongside the board adapter. Ported from the ESP32-S3 bring-up build.
#
# secp256k1: ESP32-P4 uses the ilp32f ABI (32-bit RISC-V), so the compiler
# does NOT support __int128 — use the mbedTLS fallback (secp256k1_p4.c),
# same as the Xtensa S3 build (secp256k1_s3.c).

set(HARDID_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")

if(CONFIG_HARDID_SE_ACL16)
    set(HARDID_SE_SRCS
        "${HARDID_ROOT}/hal/se_acl16.c"
        "${HARDID_ROOT}/hal/se_composite.c"
        "${HARDID_ROOT}/hal/se_transport.c"
        "${HARDID_ROOT}/hal/se_transport_esp32.c"
        "${HARDID_ROOT}/hal/se_transport_esp32_i2c.c"
        "${HARDID_ROOT}/hal/se_board.c"
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
        "${HARDID_ROOT}/core/phys_entropy.c"
        "${HARDID_ROOT}/core/bip39.c"
        "${HARDID_ROOT}/core/bip32.c"
        "${HARDID_ROOT}/core/base58.c"
        "secp256k1_p4.c"
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
        "font7.c"
        "font8x16.c"
        "display.c"
        "touch.c"
        "inter.c"
        "keypad.c"
        "screen.c"
        "link_esp.c"
        "ui.c"
        "board_p4.c"
        "entropy_p4.c"
    INCLUDE_DIRS
        "${HARDID_ROOT}/core"
        "${HARDID_ROOT}/hal"
        "${CMAKE_CURRENT_SOURCE_DIR}"
    REQUIRES
        mbedtls esp_lcd esp_driver_spi esp_driver_gpio esp_driver_i2c
        esp_driver_usb_serial_jtag spi_flash bootloader_support esp_app_format
        esp_driver_tsens esp_timer nvs_flash
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC ESP_PLATFORM=1)
