
NAME=ntpclock
PICO_SDK_PATH=~/pico/pico-sdk
PICO ?= $(shell ../findpico.sh)

.PHONY: all run clean mnt usb

all:
	mkdir -p build
	cd build && NAME=$(NAME) PICO_SDK_PATH=$(PICO_SDK_PATH) cmake ..
	$(MAKE) -C build -j8

run: all
	sudo cp build/$(NAME).uf2 /mnt/pico
	sudo sync

clean:
	rm -fr build

mnt:
	-mkdir -p /mnt/pico
	-sudo ln -s /dev/disk/by-path/$(PICO) /dev/pico
	sudo mount /dev/pico /mnt/pico
	ls /mnt/pico

usb:
	ls -l /dev/disk/by-path/ | grep -e "pci-.*-usb-.*-scsi-.*-part1"
