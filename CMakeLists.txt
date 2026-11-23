cmake_minimum_required(VERSION 3.12)

# Pull in SDK (must be before project)
include(pico_sdk_import.cmake)

project($ENV{NAME} C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Initialize the SDK
pico_sdk_init()



add_executable($ENV{NAME}
        main.cpp
	lcd.c
        enc28j60io.c
        enc28j60.c
        ip.cpp
        )

# Pull in our (to be renamed) simple get you started dependencies
target_link_libraries($ENV{NAME} pico_stdlib hardware_i2c hardware_spi pico_rand)
# Packet processing can hold a transmit and a receive frame on the stack.
target_compile_definitions($ENV{NAME} PRIVATE PICO_STACK_SIZE=0x1000)

# create map/bin/hex file etc.
pico_add_extra_outputs($ENV{NAME})

