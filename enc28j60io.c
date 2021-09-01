/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#include "enc28j60io.h"
#include "pico/stdlib.h"
#include "hardware/spi.h"

#define PIN_SCK  2
#define PIN_MOSI 3
#define PIN_MISO 4
#define PIN_CS   5

#define SPI_PORT spi0

uint32_t milliseconds()
{
	return to_ms_since_boot(get_absolute_time());
}

void enc28j60_init_io()
{
	spi_init(SPI_PORT, 30 * 1000 * 1000);
	spi_set_format(SPI_PORT, 8, SPI_CPOL_0, SPI_CPHA_1, SPI_MSB_FIRST);
	gpio_set_function(PIN_MISO, GPIO_FUNC_SPI);
	gpio_set_function(PIN_SCK, GPIO_FUNC_SPI);
	gpio_set_function(PIN_MOSI, GPIO_FUNC_SPI);
	gpio_init(PIN_CS);
	gpio_set_dir(PIN_CS, GPIO_OUT);
	gpio_put(PIN_CS, 1);
}

void enc28j60_cs(bool f)
{
	gpio_put(PIN_CS, f);  // Active low
	sleep_us(1);
}

int enc28j60_io(uint8_t c)
{
	spi_write_read_blocking(SPI_PORT, &c, &c, 1);
	return c;
}


