/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <stdbool.h>

// provided by host program
uint32_t milliseconds();
void eth_init(uint8_t const *macaddr);
unsigned int eth_recv_packet(void *ptr, int maxlen);
void eth_send_packet(void const *ptr, unsigned int len);

//

struct packet_header_t {
	uint8_t src_addr[4];
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint8_t data[0];
};

void ip_config(uint8_t const *ipv4, uint8_t const *mask, uint8_t const *gateway, uint8_t const *dns);
void ip_stack_init(uint8_t const *macaddr);
bool ip_config_with_dhcp();
void ip_stack_process();
bool gethostbyname(char const *name, uint8_t *ipv4);
bool send_udp_packet(uint8_t const *dstipv4, uint16_t dstport, uint16_t srcport, uint8_t const *ptr, uint16_t len);
struct packet_header_t *take_udp_packet(); // after using the buffer should be free(p);

#endif


