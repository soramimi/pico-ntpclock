/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#include "pico/stdlib.h"
#include "enc28j60.h"
#include "enc28j60io.h"
#include "ip.h"

#define RXND_INIT (TXST_INIT - 1)
#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_FCS_SIZE 4
#define CONTROLLER_TIMEOUT_US 5000

enum {
	ECON1_TXRST = 0x80,
	ECON1_TXRTS = 0x08,
	ECON1_RXEN = 0x04,
	ECON2_PKTDEC = 0x40,
	EIR_TXIF = 0x08,
	EIR_TXERIF = 0x02,
	ESTAT_TXABRT = 0x02,
	ESTAT_CLKRDY = 0x01,
	MISTAT_BUSY = 0x01,
	PHSTAT2_LSTAT = 0x0400,
	RX_STATUS_OK = 0x80,
};

static uint16_t next_packet;

static uint8_t read_control(int reg, bool mac_or_mii)
{
	enc28j60_cs(0);
	enc28j60_io(reg);
	if (mac_or_mii) {
		enc28j60_io(0);
	}
	uint8_t data = enc28j60_io(0);
	enc28j60_cs(1);
	return data;
}

static void write_control(int reg, int val)
{
	enc28j60_cs(0);
	enc28j60_io(0x40 | reg);
	enc28j60_io(val);
	enc28j60_cs(1);
}

static void write_control16(int low_reg, uint16_t value)
{
	write_control(low_reg, value & 0xff);
	write_control(low_reg + 1, value >> 8);
}

static void bit_set(int reg, int val)
{
	enc28j60_cs(0);
	enc28j60_io(0x80 | reg);
	enc28j60_io(val);
	enc28j60_cs(1);
}

static void bit_clear(int reg, int val)
{
	enc28j60_cs(0);
	enc28j60_io(0xa0 | reg);
	enc28j60_io(val);
	enc28j60_cs(1);
}

static void select_bank(int bank)
{
	bit_clear(ECON1, 0x03);
	bit_set(ECON1, bank & 0x03);
}

static void reset(void)
{
	enc28j60_cs(0);
	enc28j60_io(0xff);
	enc28j60_cs(1);
}

static bool wait_for_phy(void)
{
	select_bank(3);
	uint64_t deadline = time_us_64() + CONTROLLER_TIMEOUT_US;
	do {
		if (!(read_control(MISTAT, true) & MISTAT_BUSY)) {
			return true;
		}
	} while (time_us_64() < deadline);
	return false;
}

static bool write_phy(int reg, uint16_t value)
{
	select_bank(2);
	write_control(MIREGADR, reg);
	write_control16(MIWRL, value);
	return wait_for_phy();
}

static bool read_phy(int reg, uint16_t *value)
{
	select_bank(2);
	write_control(MIREGADR, reg);
	write_control(MICMD, 1);
	sleep_us(11);
	bool ready = wait_for_phy();
	select_bank(2);
	write_control(MICMD, 0);
	if (!ready) {
		return false;
	}
	uint16_t low = read_control(MIRDL, true);
	*value = low | ((uint16_t)read_control(MIRDH, true) << 8);
	return true;
}

static bool controller_ready(void)
{
	// ESTAT bit 3 is unimplemented and reads as zero on the controller.
	return (read_control(ESTAT, false) & (0x08 | ESTAT_CLKRDY)) == ESTAT_CLKRDY;
}

static void release_rx_packet(uint16_t next)
{
	// Errata item 14 requires ERXRDPT to contain an odd address.
	write_control16(ERXRDPTL, next == RXST_INIT ? RXND_INIT : next - 1);
	next_packet = next;
	bit_set(ECON2, ECON2_PKTDEC);
}

static uint16_t read_buffer16(void)
{
	uint16_t low = enc28j60_io(0);
	return low | ((uint16_t)enc28j60_io(0) << 8);
}

bool eth_init(uint8_t const *macaddr)
{
	enc28j60_init_io();
	reset();
	sleep_ms(1);
	uint64_t deadline = time_us_64() + CONTROLLER_TIMEOUT_US;
	while (!controller_ready()) {
		if (time_us_64() >= deadline) {
			return false;
		}
	}

	select_bank(0);
	next_packet = RXST_INIT;
	write_control16(ETXSTL, TXST_INIT);
	write_control16(ETXNDL, TXST_INIT);
	write_control16(ERXSTL, RXST_INIT);
	write_control16(ERXNDL, RXND_INIT);
	write_control16(ERXRDPTL, RXND_INIT);

	select_bank(2);
	write_control(MACON1, 0x0d);
	write_control(MACON3, 0x33);
	write_control(MACON4, 0x00);
	write_control16(MAMXFLL, MAX_FRAME_SIZE);
	write_control(MABBIPG, 0x15);
	write_control(MAIPGL, 0x12);
	write_control(MAIPGH, 0x0c);

	select_bank(3);
	write_control(MAADR1, macaddr[0]);
	write_control(MAADR2, macaddr[1]);
	write_control(MAADR3, macaddr[2]);
	write_control(MAADR4, macaddr[3]);
	write_control(MAADR5, macaddr[4]);
	write_control(MAADR6, macaddr[5]);

	if (!write_phy(PHCON1, 0x0100) || !write_phy(PHLCON, 0x0742)) {
		return false;
	}
	bit_set(ECON1, ECON1_RXEN);
	return true;
}

int eth_link_status(void)
{
	uint16_t status;
	if (!controller_ready() || !read_phy(PHSTAT2, &status)) {
		return -1;
	}
	return (status & PHSTAT2_LSTAT) != 0;
}

int eth_recv_packet(void *ptr, int maxlen)
{
	select_bank(1);
	if (read_control(EPKTCNT, false) == 0) {
		return 0;
	}
	select_bank(0);
	write_control16(ERDPTL, next_packet);
	enc28j60_cs(0);
	enc28j60_io(0x3a);
	uint16_t next = read_buffer16();
	uint16_t length_with_fcs = read_buffer16();
	uint16_t status = read_buffer16();
	if (next > RXND_INIT || (next & 1) || next == next_packet) {
		enc28j60_cs(1);
		return -1;
	}
	int length = (int)length_with_fcs - ETHERNET_FCS_SIZE;
	if (!(status & RX_STATUS_OK) || length_with_fcs > MAX_FRAME_SIZE ||
			length < ETHERNET_HEADER_SIZE || length > maxlen) {
		enc28j60_cs(1);
		release_rx_packet(next);
		return 0;
	}
	uint8_t *data = ptr;
	for (int i = 0; i < length; ++i) {
		data[i] = enc28j60_io(0);
	}
	enc28j60_cs(1);
	release_rx_packet(next);
	return length;
}

static void reset_transmitter(void)
{
	bit_clear(ECON1, ECON1_TXRTS);
	bit_set(ECON1, ECON1_TXRST);
	bit_clear(ECON1, ECON1_TXRST);
	bit_clear(EIR, EIR_TXIF | EIR_TXERIF);
}

bool eth_send_packet(void const *ptr, unsigned int len)
{
	if (len < ETHERNET_HEADER_SIZE || len > MAX_FRAME_SIZE - ETHERNET_FCS_SIZE) {
		return false;
	}

	select_bank(0);
	if ((read_control(ECON1, false) & ECON1_TXRTS) ||
			(read_control(EIR, false) & EIR_TXERIF)) {
		reset_transmitter();
	}
	write_control16(EWRPTL, TXST_INIT);
	write_control16(ETXNDL, TXST_INIT + len);

	uint8_t const *data = ptr;
	enc28j60_cs(0);
	enc28j60_io(0x7a);
	enc28j60_io(0);
	for (unsigned i = 0; i < len; ++i) {
		enc28j60_io(data[i]);
	}
	enc28j60_cs(1);
	bit_clear(ESTAT, ESTAT_TXABRT);
	bit_clear(EIR, EIR_TXIF | EIR_TXERIF);
	bit_set(ECON1, ECON1_TXRTS);

	uint64_t deadline = time_us_64() + CONTROLLER_TIMEOUT_US;
	do {
		uint8_t flags = read_control(EIR, false);
		if (flags & EIR_TXERIF) {
			break;
		}
		if (flags & EIR_TXIF) {
			if (!(read_control(ESTAT, false) & ESTAT_TXABRT)) {
				return true;
			}
			break;
		}
	} while (time_us_64() < deadline);

	reset_transmitter();
	return false;
}
