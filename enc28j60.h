/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#ifndef ENC28J60_H
#define ENC28J60_H

#include <stdint.h>

void enc28j60_init(uint8_t const *macaddr);
int enc28j60_peek_packet();
void enc28j60_drop_packet();
void enc28j60_recv_packet(uint8_t *ptr, int maxlen);
void enc28j60_send_packet(uint8_t const *ptr, int len);

#define MAX_FRAME_SIZE 1518

#define RXST_INIT 0x0000
#define TXST_INIT 0x1A00

// bank 0
#define ERDPTL 0x00
#define ERDPTH 0x01
#define EWRPTL 0x02
#define EWRPTH 0x03
#define ETXSTL 0x04
#define ETXSTH 0x05
#define ETXNDL 0x06
#define ETXNDH 0x07
#define ERXSTL 0x08
#define ERXSTH 0x09
#define ERXNDL 0x0a
#define ERXNDH 0x0b
#define ERXRDPTL 0x0c
#define ERXRDPTH 0x0d
#define ERXWRPTL 0x0e
#define ERXWRPTH 0x0f
#define EDMASTL 0x10
#define EDMASTH 0x11
#define EDMANDL 0x12
#define EDMANDH 0x13
#define EDMADSTL 0x14
#define EDMADSTH 0x15
#define EDMACSL 0x16
#define EDMACSH 0x17
//#define - 0x18
//#define - 0x19

// bank 1
#define EHT0 0x00
#define EHT1 0x01
#define EHT2 0x02
#define EHT3 0x03
#define EHT4 0x04
#define EHT5 0x05
#define EHT6 0x06
#define EHT7 0x07
#define EPMM0 0x08
#define EPMM1 0x09
#define EPMM2 0x0a
#define EPMM3 0x0b
#define EPMM4 0x0c
#define EPMM5 0x0d
#define EPMM6 0x0e
#define EPMM7 0x0f
#define EPMCSL 0x10
#define EPMCSH 0x11
//#define - 0x12
//#define - 0x13
#define EPMOL 0x14
#define EPMOH 0x15
//#define Reserved 0x16
//#define Reserved 0x17
#define ERXFCON 0x18
#define EPKTCNT 0x19

// bank 2
#define MACON1 0x00
//#define Reserved 0x01
#define MACON3 0x02
#define MACON4 0x03
#define MABBIPG 0x04
//#define - 0x05
#define MAIPGL 0x06
#define MAIPGH 0x07
#define MACLCON1 0x08
#define MACLCON2 0x09
#define MAMXFLL 0x0a
#define MAMXFLH 0x0b
//#define Reserved 0x0c
//#define Reserved 0x0d
//#define Reserved 0x0e
//#define - 0x0f
//#define Reserved 0x10
//#define Reserved 0x11
#define MICMD 0x12
//#define - 0x13
#define MIREGADR 0x14
//#define Reserved 0x15
#define MIWRL 0x16
#define MIWRH 0x17
#define MIRDL 0x18
#define MIRDH 0x19

// bank 3
#define MAADR5 0x00
#define MAADR6 0x01
#define MAADR3 0x02
#define MAADR4 0x03
#define MAADR1 0x04
#define MAADR2 0x05
#define EBSTSD 0x06
#define EBSTCON 0x07
#define EBSTCSL 0x08
#define EBSTCSH 0x09
#define MISTAT 0x0a
//#define - 0x0b
//#define - 0x0c
//#define - 0x0d
//#define - 0x0e
//#define - 0x0f
//#define - 0x10
//#define - 0x11
#define EREVID 0x12
//#define - 0x13
//#define - 0x14
#define ECOCON 0x15
//#define Reserved 0x16
#define EFLOCON 0x17
#define EPAUSL 0x18
#define EPAUSH 0x19

// common
//#define Reserved 0x1a
#define EIE 0x1b
#define EIR 0x1c
#define ESTAT 0x1d
#define ECON2 0x1e
#define ECON1 0x1f

// phy
#define PHCON1 0x00
#define PHSTAT1 0x01
#define PHID1 0x02
#define PHID2 0x03
#define PHCON2 0x10
#define PHSTAT2 0x11
#define PHIE 0x12
#define PHIR 0x13
#define PHLCON 0x14

#endif

