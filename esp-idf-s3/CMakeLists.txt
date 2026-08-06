# HardID Hardware Wallet — ESP-IDF project (ESP32-S3)
# Target board: Waveshare ESP32-S3-Touch-LCD-2 (ESP32-S3R8: 16MB flash, 8MB Octal PSRAM)
# Minimum ESP-IDF version: v5.2 (ESP32-S3 support, stable SPI driver API)
cmake_minimum_required(VERSION 3.16)

# Target chip
set(IDF_TARGET esp32s3)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(hardid)