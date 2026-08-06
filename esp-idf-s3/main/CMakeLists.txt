idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES hardid driver esp_driver_spi esp_driver_gpio)