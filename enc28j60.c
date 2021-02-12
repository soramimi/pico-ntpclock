/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#include "enc28j60.h"
#include "ip.h"
#include "pico/stdlib.h"

uint16_t _enc28j60_next_packet_ptr;

int enc28j60_read_control_e(int reg)
{
	int t;
	enc28j60_cs(0);
	enc28j60_io(reg);
	t = enc28j60_io(0);
	enc28j60_cs(1);
	return t;
}

int enc28j60_read_control_m(int reg)
{
	int t;
	enc28j60_cs(0);
	enc28j60_io(reg);
	enc28j60_io(reg); // 1 more
	t = enc28j60_io(0);
	enc28j60_cs(1);
	return t;
}

int enc28j60_read_buffer()
{
	int t;
	enc28j60_cs(0);
	enc28j60_io(0x3a);
	t = enc28j60_io(0);
	enc28j60_cs(1);
}

void enc28j60_write_control(int reg, int val)
{
	enc28j60_cs(0);
	enc28j60_io(0x40 | reg);
	enc28j60_io(val);
	enc28j60_cs(1);
}

int enc28j60_write_buffer(int val)
{
	enc28j60_cs(0);
	enc28j60_io(0x7a);
	enc28j60_io(val);
	enc28j60_cs(1);
}

int enc28j60_bit_set(int reg, int val)
{
	enc28j60_cs(0);
	enc28j60_io(0x80 | reg);
	enc28j60_io(val);
	enc28j60_cs(1);
}

int enc28j60_bit_clr(int reg, int val)
{
	enc28j60_cs(0);
	enc28j60_io(0xa0 | reg);
	enc28j60_io(val);
	enc28j60_cs(1);
}

int enc28j60_reset()
{
	enc28j60_cs(0);
	enc28j60_io(0xff);
	enc28j60_cs(1);
}

void enc28j60_select_bank(int n)
{
	enc28j60_bit_clr(ECON1, 0x03);
	enc28j60_bit_set(ECON1, n & 0x03);
}

void enc28j60_write_phy(int reg, int val)
{
	enc28j60_select_bank(2);
	enc28j60_write_control(MIREGADR, reg);
	enc28j60_write_control(MIWRL, val & 0xff);
	enc28j60_write_control(MIWRH, val >> 8);
	while (enc28j60_read_control_m(MISTAT) & 0x01);
}

void enc28j60_send_packet(uint8_t const *ptr, int len)
{
	int i;

	if (len < 0 || len > MAX_FRAME_SIZE) {
		return;
	}

	enc28j60_select_bank(0);

	while (enc28j60_read_control_e(ECON1) & 0x08); // while ECON1.TXRTS == 1

	enc28j60_write_control(ETXSTL, TXST_INIT & 0xff);
	enc28j60_write_control(ETXSTH, TXST_INIT >> 8);

	enc28j60_write_control(EWRPTL, TXST_INIT & 0xff);
	enc28j60_write_control(EWRPTH, TXST_INIT >> 8);

	enc28j60_write_control(ETXNDL, (TXST_INIT + len) & 0xff);
	enc28j60_write_control(ETXNDH, (TXST_INIT + len) >> 8);

	enc28j60_cs(0);
	enc28j60_io(0x7a);
	enc28j60_io(0x00);
	for (i = 0; i < len; i++) {
		enc28j60_io(ptr[i]);
	}
	enc28j60_cs(1);

	enc28j60_bit_clr(EIR, 0x08);
	enc28j60_bit_set(EIE, 0x08);
	enc28j60_bit_set(ECON1, 0x08);
}

int enc28j60_peek_packet()
{
	uint16_t next;
	uint16_t len;
	uint16_t stat;

	enc28j60_select_bank(1);
	if (enc28j60_read_control_e(EPKTCNT) == 0) {
		return 0;
	}

	enc28j60_select_bank(0);
	enc28j60_write_control(ERDPTL, _enc28j60_next_packet_ptr & 0xff);
	enc28j60_write_control(ERDPTH, _enc28j60_next_packet_ptr >> 8);

	enc28j60_cs(0);
	enc28j60_io(0x3a);
	next = enc28j60_io(0);
	next |= enc28j60_io(0) << 8;
	len = enc28j60_io(0);
	len |= enc28j60_io(0) << 8;
	stat = enc28j60_io(0);
	stat |= enc28j60_io(0) << 8;
	enc28j60_cs(1);

	if (len < 6 + 6 + 2 + 4) {
		len = -1;
	} else {
		len -= 4;
	}

	return len;
}

void enc28j60_recv_packet(uint8_t *ptr, int maxlen)
{
	int i;
	uint16_t next;
	uint16_t len;
	uint16_t stat;

	enc28j60_select_bank(0);
	enc28j60_write_control(ERDPTL, _enc28j60_next_packet_ptr & 0xff);
	enc28j60_write_control(ERDPTH, _enc28j60_next_packet_ptr >> 8);

	enc28j60_cs(0);
	enc28j60_io(0x3a);
	next = enc28j60_io(0);
	next |= enc28j60_io(0) << 8;
	len = enc28j60_io(0);
	len |= enc28j60_io(0) << 8;
	stat = enc28j60_io(0);
	stat |= enc28j60_io(0) << 8;
	if (len < 4) {
		len = 0;
	} else {
		len -= 4;
		for (i = 0; i < len; i++) {
			uint8_t c = enc28j60_io(0);
			if (i < maxlen) {
				ptr[i] = c;
			}
		}
	}
	enc28j60_cs(1);

	enc28j60_write_control(ERXRDPTL, next & 0xff);
	enc28j60_write_control(ERXRDPTH, next >> 8);
	_enc28j60_next_packet_ptr = next;

	enc28j60_bit_set(ECON2, 0x40); // set PKTDEC
}

void enc28j60_drop_packet()
{
	uint16_t next;

	enc28j60_select_bank(0);
	enc28j60_write_control(ERDPTL, _enc28j60_next_packet_ptr & 0xff);
	enc28j60_write_control(ERDPTH, _enc28j60_next_packet_ptr >> 8);

	enc28j60_cs(0);
	enc28j60_io(0x3a);
	next = enc28j60_io(0);
	next |= enc28j60_io(0) << 8;
	enc28j60_cs(1);

	enc28j60_write_control(ERXRDPTL, next & 0xff);
	enc28j60_write_control(ERXRDPTH, next >> 8);
	_enc28j60_next_packet_ptr = next;

	enc28j60_bit_set(ECON2, 0x40); // set PKTDEC
}

void enc28j60_init(uint8_t const *macaddr)
{
	int max_frame_size = MAX_FRAME_SIZE;

	enc28j60_init_io();
	enc28j60_reset();
	sleep_ms(1);

	while (!(enc28j60_read_control_e(ESTAT) & 0x01)); // while ESTAT.CLKRDY == 0

	_enc28j60_next_packet_ptr = RXST_INIT;

	// initialize buffer
	enc28j60_write_control(ETXSTL, TXST_INIT & 0xff);
	enc28j60_write_control(ETXSTH, TXST_INIT >> 8);
	enc28j60_write_control(ETXNDL, TXST_INIT & 0xff);
	enc28j60_write_control(ETXNDH, TXST_INIT >> 8);
	enc28j60_write_control(ERXSTL, RXST_INIT & 0xff);
	enc28j60_write_control(ERXSTH, RXST_INIT > 8);
	enc28j60_write_control(ERXNDL, (TXST_INIT - 1) & 0xff);
	enc28j60_write_control(ERXNDH, (TXST_INIT - 1) >> 8);

	enc28j60_write_control(ERXRDPTL, RXST_INIT & 0xff);
	enc28j60_write_control(ERXRDPTH, RXST_INIT >> 8);

	// initialize MAC
	enc28j60_select_bank(2);
	enc28j60_write_control(MACON1, 0x0d);
	enc28j60_write_control(MACON3, 0x33);
	enc28j60_write_control(MACON4, 0x00);
	enc28j60_write_control(MAMXFLL, max_frame_size & 0xff);
	enc28j60_write_control(MAMXFLH, max_frame_size >> 8);
	enc28j60_write_control(MABBIPG, 0x15);
	enc28j60_write_control(MAIPGL, 0x12);
	enc28j60_write_control(MAIPGH, 0x0c);

	// initialize address
	enc28j60_select_bank(3);
	enc28j60_write_control(MAADR1, macaddr[0]);
	enc28j60_write_control(MAADR2, macaddr[1]);
	enc28j60_write_control(MAADR3, macaddr[2]);
	enc28j60_write_control(MAADR4, macaddr[3]);
	enc28j60_write_control(MAADR5, macaddr[4]);
	enc28j60_write_control(MAADR6, macaddr[5]);

	// initialize PHY
	enc28j60_write_phy(PHCON1, 0x0100); // PDPXMD
	enc28j60_write_phy(PHLCON, 0x0742);

	//
	enc28j60_bit_set(ECON1, 0x04); // set RXEN
}

void eth_init(uint8_t const *macaddr)
{
	enc28j60_init(macaddr);
}

unsigned int eth_recv_packet(void *ptr, int maxlen)
{
	int len = enc28j60_peek_packet();
	if (len == 0) {
		return 0;
	}
	if (len < 0) {
		enc28j60_drop_packet();
		return 0;
	}
	enc28j60_recv_packet((uint8_t *)ptr, maxlen);
	return len;
}

void eth_send_packet(void const *ptr, unsigned int len)
{
	enc28j60_send_packet((uint8_t const *)ptr, len);
}

