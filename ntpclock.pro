
TEMPLATE = app
TARGET = ntpclock
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/common/pico_base/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/common/pico_binary_info/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/common/pico_stdlib/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/common/pico_time/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/common/pico_util/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/rp2_common/hardware_base/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/rp2_common/hardware_gpio/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/rp2_common/hardware_i2c/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/rp2_common/hardware_spi/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/rp2_common/hardware_uart/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/rp2_common/hardware_rtc/include
INCLUDEPATH += $(HOME)/pico/pico-sdk/src/rp2_common/pico_stdio/include

HEADERS += build/generated/pico_base/pico/config_autogen.h \
           build/generated/pico_base/pico/version.h \
           enc28j60.h \
           enc28j60io.h \
           ip.h \
           lcd.h

SOURCES += main.c \
           build/CMakeFiles/3.16.3/CompilerIdC/CMakeCCompilerId.c \
           build/CMakeFiles/3.16.3/CompilerIdCXX/CMakeCXXCompilerId.cpp \
           build/elf2uf2/CMakeFiles/3.16.3/CompilerIdC/CMakeCCompilerId.c \
           build/elf2uf2/CMakeFiles/3.16.3/CompilerIdCXX/CMakeCXXCompilerId.cpp \
           enc28j60.c \
           enc28j60io.c \
           ip.c \
           lcd.c
