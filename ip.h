/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#ifndef IP_H
#define IP_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// provided by host program
uint32_t milliseconds();
bool eth_init(uint8_t const *macaddr);
int eth_link_status(void); // 1 up, 0 down, -1 controller error
int eth_recv_packet(void *ptr, int maxlen); // bytes received, 0 empty, -1 controller error
bool eth_send_packet(void const *ptr, unsigned int len);
// Write the HTTP response for a request line and return its byte length, or 0 on failure.
unsigned int handle_http_request(char const *request_line, char *response, unsigned int capacity);

//

#define NTP_PACKET_SIZE 48

void ip_config(uint8_t const *ipv4, uint8_t const *mask, uint8_t const *gateway, uint8_t const *dns);
void ip_stack_init(uint8_t const *macaddr);
void ip_get_address(uint8_t *ipv4);
bool ip_link_up(void);
uint32_t ip_network_generation(void);
void ip_stack_process();
// Returns true when an address is available. Call again while a DNS query is in progress.
bool ip_resolve_name(char const *name, uint8_t *ipv4);
bool send_udp_packet(uint8_t const *dstipv4, uint16_t dstport, uint16_t srcport, uint8_t const *ptr, uint16_t len);
void ip_expect_ntp_reply(uint8_t const *server, uint16_t port, uint8_t const *timestamp);
void ip_cancel_ntp_reply(void);
bool ip_take_ntp_reply(uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif
