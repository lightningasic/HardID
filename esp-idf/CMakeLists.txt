# OpenShield Hardware Wallet — ESP-IDF project (ESP32-P4)
# Minimum ESP-IDF version: v5.2 (ESP32-P4 support)
cmake_minimum_required(VERSION 3.16)

# Target chip
set(IDF_TARGET esp32p4)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(openshield)
