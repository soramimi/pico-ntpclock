/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#include "ip.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_FRAME_SIZE 1518

uint16_t ntohs(uint16_t v)
{
	return ((v << 8) & 0xff00) | ((v >> 8) & 0x00ff);
}

uint16_t htons(uint16_t v)
{
	return ((v << 8) & 0xff00) | ((v >> 8) & 0x00ff);
}

uint32_t ntohl(uint32_t v)
{
	return ((v << 24) & 0xff000000) | ((v << 8) & 0x00ff00) | ((v >> 8) & 0x0000ff00) | ((v >> 24) & 0x000000ff);
}

uint32_t htonl(uint32_t v)
{
	return ((v << 24) & 0xff000000) | ((v << 8) & 0x00ff00) | ((v >> 8) & 0x0000ff00) | ((v >> 24) & 0x000000ff);
}

//

#define DHCP_MAGIC_COOKIE 0x63825363

struct ethernet_frame_t {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
};

struct ip_frame_t {
	uint8_t version_and_length;
	uint8_t service;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags_and_fragment_offset;
	uint8_t time_to_live;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src;
	uint32_t dst;
} __attribute__ ((packed));

struct udp_frame_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
} __attribute__ ((packed));

struct dhcp_frame_t {
	uint8_t msg_type;
	uint8_t hw_type;
	uint8_t hw_addr_len;
	uint8_t hops;
	uint32_t transaction_id;
	uint16_t seconds_slapsed;
	uint16_t bootp_flags;
	uint32_t client_ip_addr;
	uint32_t user_ip_addr;
	uint32_t server_ip_addr;
	uint32_t gateway_ip_addr;
	uint8_t client_mac_addr[6];
	uint8_t client_hw_addr_padding[10];
	uint8_t server_host_name[64];
	uint8_t boot_file_name[128];
	uint32_t magic_cookie;
} __attribute__ ((packed));

struct arp_frame_t {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware;
	uint8_t protocol;
	uint16_t opode;
	uint8_t sender_mac_addr[6];
	uint32_t sender_ip_addr;
	uint8_t target_mac_addr[6];
	uint32_t target_ip_addr;
} __attribute__ ((packed));

struct icmp_frame_t {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t sequence_number;
} __attribute__ ((packed));

struct dns_frame_t {
	uint16_t transaction_id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answer_rrs;
	uint16_t authority_rrs;
	uint16_t additional_rrs;
} __attribute__ ((packed));

enum {
	STATE_IDLE,
	STATE_SENT_DHCP_DISCOVER,
	STATE_DHCP_NACK,
};

#define ARP_CACHE_SIZE 10
#define DNS_CACHE_SIZE 10
#define UDP_PACKET_BUFFER_SIZE 8

struct arp_cache_item_t {
	bool valid;
	uint8_t ipv4[4];
	uint8_t mac[6];
};

struct dns_cache_item_t {
	uint16_t transaction_id;
	bool valid_address;
	uint8_t ipv4[4];
	char name[1];
};

struct ip_stack_globals_t {
	uint16_t packet_id;
	uint8_t mac_addr[6];
	uint8_t ipv4_addr[4];
	uint8_t subnet_mask[4];
	uint8_t gateway_addr[4];
	uint8_t dns_addr[4];
	uint16_t ip_identifier;
	uint16_t dns_transaction_id;
	struct arp_cache_item_t arp_cache[ARP_CACHE_SIZE];
	struct dns_cache_item_t *dns_cache[DNS_CACHE_SIZE];
	struct packet_header_t *udp_packets[UDP_PACKET_BUFFER_SIZE];
	uint16_t udp_packet_count;
	int dhcp_ack_waiting;
	int state;
} ip_stack_globals;


void ip_stack_init(uint8_t const *macaddr)
{
	int i;
	memset(&ip_stack_globals, 0, sizeof(ip_stack_globals));
	memcpy(ip_stack_globals.mac_addr, macaddr, 6);
	ip_stack_globals.packet_id = 0;
	ip_stack_globals.state = STATE_IDLE;
	ip_stack_globals.dhcp_ack_waiting = 0;
	ip_stack_globals.ip_identifier = 0;
	ip_stack_globals.dns_transaction_id = 0;
	for (i = 0; i < DNS_CACHE_SIZE; i++) {
		ip_stack_globals.dns_cache[i] = 0;
	}
	for (i = 0; i < UDP_PACKET_BUFFER_SIZE; i++) {
		ip_stack_globals.udp_packets[i] = 0;
	}
	ip_stack_globals.udp_packet_count = 0;
	eth_init(ip_stack_globals.mac_addr);
	sleep_ms(100);
}

//

uint32_t get_ip_address()
{
	return *(uint32_t const *)&ip_stack_globals.ipv4_addr;
}

uint32_t get_ip_subnet_mask()
{
	return *(uint32_t const *)&ip_stack_globals.subnet_mask;
}

//

void write_l(void *ptr, uint32_t val)
{
	uint8_t *p = (uint8_t *)ptr;
	p[0] = (uint8_t)(val >> 24);
	p[1] = (uint8_t)(val >> 16);
	p[2] = (uint8_t)(val >> 8);
	p[3] = (uint8_t)val;
}

uint32_t read_l(uint32_t const *ptr)
{
	uint8_t const *p = (uint8_t const *)ptr;
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}


void write_s(void *ptr, uint16_t val)
{
	uint8_t *p = (uint8_t *)ptr;
	p[0] = (uint8_t)(val >> 8);
	p[1] = (uint8_t)val;
}

uint16_t read_s(uint16_t const *ptr)
{
	uint8_t *p = (uint8_t *)ptr;
	return (p[0] << 8) | p[1];
}

uint16_t compute_sum(uint16_t sum, void const *ptr, int len)
{
	int i;
	uint32_t s = sum;
	for (i = 0; i < len; i++) {
		uint16_t c = ((uint8_t const *)ptr)[i];
		if (i & 1) {
			s += c;
		} else {
			s += c << 8;
		}
		s = (s + (s >> 16)) & 0xffff;
	}
	return (uint16_t)s;
}

void set_ip_checksum(struct ip_frame_t *ip)
{
	uint32_t sum;
	ip->checksum = 0;
	sum = compute_sum(0, ip, sizeof(struct ip_frame_t));
	sum = ~sum;
	write_s(&ip->checksum, sum);
}

void set_udp_checksum(struct udp_frame_t *udp, struct ip_frame_t const *ip)
{
	struct {
		uint32_t src;
		uint32_t dst;
		uint8_t zero;
		uint8_t protocol;
		uint16_t length;
	} header;
	uint16_t sum;
	int len = read_s(&udp->length);

	udp->checksum = 0;

	header.src = ip->src;
	header.dst = ip->dst;
	header.zero = 0;
	header.protocol = ip->protocol;
	write_s(&header.length, len);

	sum = compute_sum(0, &header, sizeof(header));
	sum = compute_sum(sum, udp, len);
	sum = ~sum;
	if (sum == 0) {
		sum = 0xffff;
	}
	write_s(&udp->checksum, sum);
}

void set_icmp_checksum(struct icmp_frame_t *icmp, struct ip_frame_t const *ip)
{
	uint32_t sum;
	uint8_t const *p = (uint8_t const *)icmp;
	uint16_t n = read_s(&ip->total_length);
	if (n >= sizeof(struct ip_frame_t) + sizeof(struct icmp_frame_t)) {
		p += n - sizeof(struct ip_frame_t);
	}
	icmp->checksum = 0;
	sum = compute_sum(0, icmp, p - (uint8_t const *)icmp);
	sum = ~sum;
	write_s(&icmp->checksum, sum);
}

void set_ip_identifier(struct ip_frame_t *ip)
{
	write_s(&ip->identification, ip_stack_globals.ip_identifier);
	ip_stack_globals.ip_identifier++;
}

struct eth_ip_udp_frame_t {
	struct ethernet_frame_t eth;
	struct ip_frame_t ip;
	struct udp_frame_t udp;
}  __attribute__ ((packed));

void prepare_ip_packet(struct ip_frame_t *ip, void *end)
{
	uint16_t len = (uint8_t const *)end - (uint8_t const*)ip;
	ip->version_and_length = 0x45; // version=4; length=20
	set_ip_identifier(ip);
	ip->time_to_live = 128;
	write_s(&ip->total_length, len);
}

void prepare_udp_packet(struct eth_ip_udp_frame_t *frame, uint8_t const *dstipv4, uint16_t dstport, uint16_t srcport, void *end)
{
	uint16_t len = (uint8_t const *)end - (uint8_t const *)&frame->udp;
	frame->ip.protocol = 17;
	memcpy(&frame->ip.dst, dstipv4, 4);
	write_s(&frame->udp.dst_port, dstport);
	write_s(&frame->udp.src_port, srcport);
	write_s(&frame->udp.length, len);
}

//

struct dhcp_header_frame_t {
	struct eth_ip_udp_frame_t header;
	struct dhcp_frame_t dhcp;
} __attribute__ ((packed));

static void prepare_dhcp(struct dhcp_frame_t *dhcp, uint8_t const *macaddr)
{
	dhcp->msg_type = 1;
	dhcp->hw_type = 1;
	dhcp->hw_addr_len = 6;
	write_l(&dhcp->transaction_id, 0x736f7261);
	write_s(&dhcp->bootp_flags, 0x8000);
	memcpy(dhcp->client_mac_addr, macaddr, 6);
}

static void send_dhcp_packet(struct dhcp_header_frame_t *frame, uint8_t *begin, uint8_t *end)
{
	uint8_t dstaddr[] = {
		0xff, 0xff, 0xff, 0xff
	};
	prepare_udp_packet(&frame->header, dstaddr, 67, 68, end);
	prepare_ip_packet(&frame->header.ip, end);
	set_udp_checksum(&frame->header.udp, &frame->header.ip);
	set_ip_checksum(&frame->header.ip);
	eth_send_packet(begin, end - begin);
}

void send_dhcp_discover()
{
	uint8_t tmp[MAX_FRAME_SIZE];
	//	uint8_t tmp[304];
	uint8_t *p;
	struct dhcp_header_frame_t *frame;

	uint8_t const *macaddr = ip_stack_globals.mac_addr;

	frame = (struct dhcp_header_frame_t *)tmp;
	p = tmp + sizeof(struct dhcp_header_frame_t);

	memset(tmp, 0, sizeof(tmp));

	memset(&frame->header.eth.dst, 0xff, 6);
	memcpy(&frame->header.eth.src, macaddr, 6);
	write_s(&frame->header.eth.type, 0x0800);

	write_s(&frame->header.ip.flags_and_fragment_offset, 0x4000);

	prepare_dhcp(&frame->dhcp, macaddr);

	write_l(&frame->dhcp.magic_cookie, DHCP_MAGIC_COOKIE);

	*p++ = 0x35; // DHCP Message Type
	*p++ = 0x01;
	*p++ = 0x01; // Discover
	*p++ = 0x3d; // Client identifier
	*p++ = 0x07;
	*p++ = 0x01;
	*p++ = macaddr[0];
	*p++ = macaddr[1];
	*p++ = macaddr[2];
	*p++ = macaddr[3];
	*p++ = macaddr[4];
	*p++ = macaddr[5];
	*p++ = 0x37; // Parameter Request List
	*p++ = 0x07;
	*p++ = 0x01;
	*p++ = 0x03;
	*p++ = 0x06;
	*p++ = 0x0f;
	*p++ = 0x0c;
	*p++ = 0x3a;
	*p++ = 0x3b;
	*p++ = 0xff; // End

	send_dhcp_packet(frame, tmp, p);
}

void send_dhcp_request(struct dhcp_frame_t const *dhcp)
{
	uint8_t tmp[MAX_FRAME_SIZE];
	//	uint8_t tmp[316];
	uint8_t *p;
	struct dhcp_header_frame_t *frame;

	uint8_t const *macaddr = ip_stack_globals.mac_addr;

	frame = (struct dhcp_header_frame_t *)tmp;
	p = tmp + sizeof(struct dhcp_header_frame_t);

	memset(tmp, 0, sizeof(tmp));

	memset(&frame->header.eth.dst, 0xff, 6);
	memcpy(&frame->header.eth.src, macaddr, 6);
	write_s(&frame->header.eth.type, 0x0800);

	write_s(&frame->header.ip.flags_and_fragment_offset, 0x4000);

	prepare_dhcp(&frame->dhcp, macaddr);

	write_l(&frame->dhcp.magic_cookie, DHCP_MAGIC_COOKIE);

	*p++ = 0x35; // DHCP Message Type
	*p++ = 0x01;
	*p++ = 0x03; // Request

	*p++ = 0x3d; // Client Identifier
	*p++ = 0x07;
	*p++ = 0x01;
	*p++ = macaddr[0];
	*p++ = macaddr[1];
	*p++ = macaddr[2];
	*p++ = macaddr[3];
	*p++ = macaddr[4];
	*p++ = macaddr[5];

	*p++ = 0x32; // Requested IP Address
	*p++ = 0x04;
	memcpy(p, &dhcp->user_ip_addr, 4);
	p += 4;

	*p++ = 0x36; // DHCP Server Identifier
	*p++ = 0x04;
	memcpy(p, &dhcp->server_ip_addr, 4);
	p += 4;

	*p++ = 0x37; // Parameter Request List
	*p++ = 0x03;
	*p++ = 0x01; // Subnet Mask
	*p++ = 0x03; // Router
	*p++ = 0x06; // Domain Name Server

#if 0
	*p++ = 0x0c; // Host Name
	*p++ = 0x08;
	*p++ = 'e';
	*p++ = 'x';
	*p++ = 'a';
	*p++ = 'm';
	*p++ = 'p';
	*p++ = 'l';
	*p++ = 'e';
	*p++ = '1';
#endif

#if 0
	*p++ = 0x51; // Client Fully Qualified Domain Name
	*p++ = 0x0b;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 'e';
	*p++ = 'x';
	*p++ = 'a';
	*p++ = 'm';
	*p++ = 'p';
	*p++ = 'l';
	*p++ = 'e';
	*p++ = '2';
#endif

#if 0
	*p++ = 0x3c; // Vendor Class Identifier
	*p++ = 0x08;
	*p++ = 'e';
	*p++ = 'x';
	*p++ = 'a';
	*p++ = 'm';
	*p++ = 'p';
	*p++ = 'l';
	*p++ = 'e';
	*p++ = '3';
#endif

	*p++ = 0xff; // End

	send_dhcp_packet(frame, tmp, p);
}

//

void send_arp_request(uint8_t const *ipv4)
{
	struct frame_t {
		struct ethernet_frame_t eth;
		struct arp_frame_t arp;
	} __attribute__ ((packed)) frame;

	memset(&frame, 0, sizeof(struct frame_t));

	memset(frame.eth.dst, 0xff, 6);
	memcpy(frame.eth.src, ip_stack_globals.mac_addr, 6);
	write_s(&frame.eth.type, 0x0806);

	write_s(&frame.arp.hardware_type, 1);
	write_s(&frame.arp.protocol_type, 0x0800);
	frame.arp.hardware = 6;
	frame.arp.protocol = 4;
	write_s(&frame.arp.opode, 1);
	memcpy(frame.arp.sender_mac_addr, ip_stack_globals.mac_addr, 6);
	memcpy(&frame.arp.sender_ip_addr, ip_stack_globals.ipv4_addr, 4);
	memcpy(&frame.arp.target_ip_addr, ipv4, 4);
	eth_send_packet(&frame, sizeof(struct frame_t));
}

void send_arp_response(struct arp_frame_t const *arp)
{
	struct frame_t {
		struct ethernet_frame_t eth;
		struct arp_frame_t arp;
	} __attribute__ ((packed)) frame;

	memset(&frame, 0, sizeof(struct frame_t));

	memcpy(frame.eth.dst, arp->sender_mac_addr, 6);
	memcpy(frame.eth.src, ip_stack_globals.mac_addr, 6);
	write_s(&frame.eth.type, 0x0806);

	write_s(&frame.arp.hardware_type, 1);
	write_s(&frame.arp.protocol_type, 0x0800);
	frame.arp.hardware = 6;
	frame.arp.protocol = 4;
	write_s(&frame.arp.opode, 2);
	memcpy(frame.arp.sender_mac_addr, ip_stack_globals.mac_addr, 6);
	memcpy(&frame.arp.sender_ip_addr, ip_stack_globals.ipv4_addr, 4);
	memcpy(frame.arp.target_mac_addr, arp->sender_mac_addr, 6);
	frame.arp.target_ip_addr = arp->sender_ip_addr;
	eth_send_packet((uint8_t const *)&frame, sizeof(struct frame_t));
}

//

void send_icmp_echo_reply(struct ethernet_frame_t const *eth, struct ip_frame_t const *ip, struct icmp_frame_t const *icmp)
{
	uint8_t tmp[MAX_FRAME_SIZE];
	struct frame_t {
		struct ethernet_frame_t eth;
		struct ip_frame_t ip;
		struct icmp_frame_t icmp;
	} __attribute__ ((packed)) *frame;

	frame = (struct frame_t *)tmp;

	memset(tmp, 0, sizeof(tmp));

	memcpy(frame->eth.dst, eth->src, 6);
	memcpy(frame->eth.src, ip_stack_globals.mac_addr, 6);
	write_s(&frame->eth.type, 0x0800);

	write_s(&frame->ip.flags_and_fragment_offset, 0);
	frame->ip.protocol = 0x01; // icmp
	frame->ip.dst = ip->src;
	memcpy(&frame->ip.src, ip_stack_globals.ipv4_addr, 4);

	uint8_t *p = (uint8_t *)&frame->icmp;
	uint16_t ip_total_length = read_s(&ip->total_length);
	if (ip_total_length >= sizeof(struct ip_frame_t) && sizeof(struct ethernet_frame_t) + ip_total_length <= MAX_FRAME_SIZE) {
		memcpy(p, icmp, ip_total_length - sizeof(struct ip_frame_t));
		p += ip_total_length;
	} else {
		p += sizeof(struct icmp_frame_t);
	}

	frame->icmp.type = 0; // reply

	prepare_ip_packet(&frame->ip, p);
	set_ip_checksum(&frame->ip);
	set_icmp_checksum(&frame->icmp, &frame->ip);
	eth_send_packet(tmp, p - tmp);
}


//

void ip_stack_term()
{
	int i;
	for (i = 0; i < DNS_CACHE_SIZE; i++) {
		struct dns_cache_item_t *p = ip_stack_globals.dns_cache[i];
		if (p) {
			free(p);
		}
	}
}

void on_icmp_packet(struct ethernet_frame_t const *eth, struct ip_frame_t const *ip, uint8_t *p, bool broadcast)
{
	struct icmp_frame_t *icmp = (struct icmp_frame_t *)p;
	if (icmp->type == 8) { // echo request
		send_icmp_echo_reply(eth, ip, icmp);
		return;
	}
}

static bool is_addr_zero(uint8_t const *addr)
{
	return !addr[0] && !addr[1] && !addr[2] && !addr[3];
}

bool is_valid_ip_address()
{
	if (is_addr_zero(ip_stack_globals.subnet_mask)) {
		return false;
	}
	if (is_addr_zero(ip_stack_globals.ipv4_addr)) {
		return false;
	}
	if (is_addr_zero(ip_stack_globals.dns_addr)) {
		return false;
	}
	return true;
}

void process_dhcp_options(struct dhcp_frame_t *dhcp, uint8_t const *begin, uint8_t const *end)
{
	uint8_t const *p = begin;
	uint8_t subnet_mask[4];
	uint8_t gateway_addr[4];
	uint8_t dns_addr[4];
	bool dhcp_ack = false;
	bool offer = false;
	memset(subnet_mask, 0, 4);
	memset(gateway_addr, 0, 4);
	memset(dns_addr, 0, 4);
	while (p + 1 < end && p[0] != 0xff && p + 2 + p[1] <= end) {
		uint8_t option = p[0];
		uint8_t len = p[1];
		p += 2;
		switch (option) {
		case 53: // dhcp message type
			if (len == 1) {
				if (p[0] == 2) { // offer
					if (is_valid_ip_address()) {
						break;
					}
					if (ip_stack_globals.state != STATE_SENT_DHCP_DISCOVER) {
						break;
					}
					if (ip_stack_globals.dhcp_ack_waiting != 0) {
						break;
					}
					offer = true;
				} else if (p[0] == 5) { // ack
					if (ip_stack_globals.state == STATE_SENT_DHCP_DISCOVER && ip_stack_globals.dhcp_ack_waiting > 0) {
						dhcp_ack = true;
					}
					ip_stack_globals.state = STATE_IDLE;
					ip_stack_globals.dhcp_ack_waiting = 0;
				} else if (p[0] == 6) { // nack
					ip_stack_globals.state = STATE_DHCP_NACK;
					ip_stack_globals.dhcp_ack_waiting = 0;
				}
			}
			break;
		case 54: // dhcp server identifier
			if (len == 4) {
				memcpy(&dhcp->server_ip_addr, p, 4);
			}
			break;
		case 1: // subnet mask
			if (len == 4) {
				memcpy(subnet_mask, p, 4);
			}
			break;
		case 3: // default gateway
			if (len == 4) {
				memcpy(gateway_addr, p, 4);
			}
			break;
		case 6: // DNS
			if (len == 4) {
				memcpy(dns_addr, p, 4);
			}
			break;
		}
		p += len;
	}
	if (offer) {
		send_dhcp_request(dhcp);
		ip_stack_globals.dhcp_ack_waiting = 1;
	}
	if (dhcp_ack) {
		memcpy(ip_stack_globals.ipv4_addr, &dhcp->user_ip_addr, 4);
		memcpy(ip_stack_globals.subnet_mask, subnet_mask, 4);
		memcpy(ip_stack_globals.gateway_addr, gateway_addr, 4);
		memcpy(ip_stack_globals.dns_addr, dns_addr, 4);
	}
}

uint8_t const *skip_dns_name_field(uint8_t const *ptr, uint8_t const *end)
{
	while (ptr < end) {
		if (*ptr == 0) {
			ptr++;
			break;
		}
		if ((*ptr & 0xc0) == 0xc0) {
			ptr += 2;
			break;
		}
		ptr += 1 + *ptr;
	}
	return ptr;
}

void process_dns_response(struct dns_frame_t const *dns, uint8_t const *end)
{
	unsigned int i;
	uint8_t const *p = (uint8_t const *)dns + sizeof(struct dns_frame_t);

	uint8_t host_addr[4];
	bool host_addr_is_valid = false;

	uint16_t questions = read_s(&dns->questions);
	uint16_t answers_rrs = read_s(&dns->answer_rrs);
	uint16_t authority_rrs = read_s(&dns->authority_rrs);
	uint16_t additional_rrs = read_s(&dns->additional_rrs);

	if (p < end) {
		for (i = 0; i < questions; i++) {
			p = skip_dns_name_field(p, end);
			p += 4;
		}
	}

	if (p < end) {
		for (i = 0; i < answers_rrs; i++) {
			uint16_t type;
			uint16_t cls;
			uint16_t datalen;
			p = skip_dns_name_field(p, end);
			if (p + 10 <= end) {
				type = read_s((uint16_t const *)p);
				p += 2;
				cls = read_s((uint16_t const *)p);
				p += 2;
				p += 4; // time to live
				datalen = read_s((uint16_t const *)p);
				p += 2;
				if (type == 1 && !host_addr_is_valid) { // A
					if (datalen == 4 && p + datalen < end) {
						memcpy(host_addr, p, 4);
						host_addr_is_valid = true;
					}
				}
				p += datalen; // primary name
			}
		}
	}

	if (p < end) {
		for (i = 0; i < authority_rrs; i++) {
			uint16_t type;
			uint16_t cls;
			uint16_t datalen;
			p = skip_dns_name_field(p, end);
			if (p + 10 <= end) {
				type = read_s((uint16_t const *)p);
				p += 2;
				cls = read_s((uint16_t const *)p);
				p += 2;
				p += 4; // time to live
				datalen = read_s((uint16_t const *)p);
				p += 2;
				p += datalen; // primary name
			}
		}
	}

	if (p < end) {
		for (i = 0; i < additional_rrs; i++) {
			uint16_t type;
			uint16_t cls;
			uint16_t datalen;
			p = skip_dns_name_field(p, end);
			if (p + 10 <= end) {
				type = read_s((uint16_t const *)p);
				p += 2;
				cls = read_s((uint16_t const *)p);
				p += 2;
				p += 4; // time to live
				datalen = read_s((uint16_t const *)p);
				p += 2;
				p += datalen; // primary name
			}
		}
	}

	if (host_addr_is_valid) {
		uint16_t tran_id = read_s(&dns->transaction_id);
		for (i = 0; i < DNS_CACHE_SIZE; i++) {
			struct dns_cache_item_t *item = ip_stack_globals.dns_cache[i];
			if (item && tran_id == item->transaction_id) {
				memcpy(item->ipv4, host_addr, 4);
				item->valid_address = true;
			}
		}
	}
}

void on_udp_packet(struct ip_frame_t const *ip, uint8_t *p, bool broadcast)
{
	struct udp_frame_t *udp = (struct udp_frame_t *)p;
	uint16_t len = read_s(&udp->length);
	uint8_t const *end = (uint8_t const *)udp;
	end += len;
	p += sizeof(struct udp_frame_t);
	if (ntohs(udp->dst_port) == 68) {
		struct dhcp_frame_t *dhcp = (struct dhcp_frame_t *)p;
		if (read_l(&dhcp->magic_cookie) == DHCP_MAGIC_COOKIE) {
			process_dhcp_options(dhcp, p + sizeof(struct dhcp_frame_t), end);
		}
	} else if (ntohs(udp->src_port) == 53) {
		struct dns_frame_t *dns = (struct dns_frame_t *)p;
		process_dns_response(dns, end);
	} else {
		if (len >= sizeof(struct udp_frame_t) && len <= MAX_FRAME_SIZE && ip_stack_globals.udp_packet_count < UDP_PACKET_BUFFER_SIZE) {
			struct packet_header_t *packet = (struct packet_header_t *)malloc(sizeof(struct packet_header_t) + len);
			if (!packet) {
				// not enough memory ?
				return;
			}
			memcpy(packet->src_addr, &ip->src, 4);
			packet->src_port = read_s(&udp->src_port);
			packet->dst_port = read_s(&udp->dst_port);
			packet->length = len - sizeof(struct udp_frame_t);
			memcpy(packet->data, p, packet->length);
			ip_stack_globals.udp_packets[ip_stack_globals.udp_packet_count++] = packet;
		}
	}
}

void eth_on_ip_packet(uint8_t *buf, int len, bool broadcast)
{
	struct ip_frame_t *ip = (struct ip_frame_t *)(buf + sizeof(struct ethernet_frame_t));
	if ((ip->version_and_length & 0xf0) == 0x40) {
		uint8_t *p = (uint8_t *)ip;
		p += (ip->version_and_length & 0x0f) * 4;
		if (ip->protocol == 17) {
			on_udp_packet(ip, p, broadcast);
			return;
		}
		if (ip->protocol == 1) {
			struct ethernet_frame_t const *eth = (struct ethernet_frame_t *)buf;
			on_icmp_packet(eth, ip, p, broadcast);
			return;
		}
	}
}

void eth_on_arp_packet(uint8_t *buf, int len, bool broadcast)
{
	struct frame_t {
		struct ethernet_frame_t eth;
		struct arp_frame_t arp;
	} __attribute__ ((packed)) *frame;

	if (len < sizeof(struct frame_t)) {
		return;
	}

	if (!is_valid_ip_address()) {
		return;
	}

	frame = (struct frame_t *)buf;

	int opcode = ntohs(frame->arp.opode);

	if (opcode == 1 && memcmp(&frame->arp.target_ip_addr, ip_stack_globals.ipv4_addr, 4) == 0) {
		send_arp_response(&frame->arp);
		return;
	}

	if (broadcast) {
		return;
	}

	if (opcode == 2) {
		int i;
		for (i = 0; i < ARP_CACHE_SIZE - 1; i++) {
			if (!ip_stack_globals.arp_cache[i].valid || memcmp(ip_stack_globals.arp_cache[i].ipv4, ip_stack_globals.ipv4_addr, 4) == 0) {
				break;
			}
		}
		memcpy(ip_stack_globals.arp_cache[i].ipv4, &frame->arp.sender_ip_addr, 4);
		memcpy(ip_stack_globals.arp_cache[i].mac, frame->arp.sender_mac_addr, 6);
		ip_stack_globals.arp_cache[i].valid = true;
		return;
	}
}

void ip_stack_process()
{
	uint8_t tmp[MAX_FRAME_SIZE];
	while (1) {
		struct ethernet_frame_t *eth;
		unsigned int len = eth_recv_packet(tmp, MAX_FRAME_SIZE);
		if (len == 0) {
			break;
		}
		if (len > MAX_FRAME_SIZE) {
			len = MAX_FRAME_SIZE;
		}
		bool broadcast = false;
		eth = (struct ethernet_frame_t *)tmp;
		if (memcmp(eth->dst, "\xff\xff\xff\xff\xff\xff", 6) == 0) {
			broadcast = true;
		} else if (memcmp(eth->dst, ip_stack_globals.mac_addr, 6) != 0) {
			continue;
		}
		uint16_t type =ntohs(eth->type);
		if (type == 0x0800) {
			eth_on_ip_packet(tmp, len, broadcast);
			continue;
		}
		if (type == 0x0806) {
			eth_on_arp_packet(tmp, len, broadcast);
			continue;
		}
	}
}

static void arp_cache_move_to_front(int i)
{
	if (i < 1 || i >= ARP_CACHE_SIZE) {
		return;
	}
	struct arp_cache_item_t item;
	memcpy(&item, &ip_stack_globals.arp_cache[i], sizeof(struct arp_cache_item_t));
	memmove(ip_stack_globals.arp_cache + 1, ip_stack_globals.arp_cache, sizeof(struct arp_cache_item_t) * i);
	memcpy(&ip_stack_globals.arp_cache[i], &item, sizeof(struct arp_cache_item_t));
}

int find_mac_from_arp_cache(uint8_t const *ipv4)
{
	int i;
	for (i = 0; i < ARP_CACHE_SIZE; i++) {
		if (ip_stack_globals.arp_cache[i].valid && memcmp(ip_stack_globals.arp_cache[i].ipv4, ipv4, 4) == 0) {
			return i;
		}
	}
	return -1;
}

bool get_mac_from_ipv4(uint8_t const *ipv4, uint8_t *mac)
{
	int i;
	int retry;
	i = find_mac_from_arp_cache(ipv4);
	if (i >= 0) {
		goto found;
	}
	retry = 0;
	while (1) {
		uint32_t start_tick = milliseconds();
		send_arp_request(ipv4);
		while (1) {
			if (milliseconds() - start_tick > 1000) {
				break;
			}
			ip_stack_process();
			i = find_mac_from_arp_cache(ipv4);
			if (i >= 0) {
				goto found;
			}
		}
		retry++;
		if (retry >= 5) {
			return false;
		}
	}
found:;
	memcpy(mac, ip_stack_globals.arp_cache[i].mac, 6);
	arp_cache_move_to_front(i);
	return true;
}

void ip_config(uint8_t const *ipv4, uint8_t const *mask, uint8_t const *gateway, uint8_t const *dns)
{
	memcpy(ip_stack_globals.ipv4_addr, ipv4, 4);
	memcpy(ip_stack_globals.subnet_mask, mask, 4);
	memcpy(ip_stack_globals.gateway_addr, gateway, 4);
	memcpy(ip_stack_globals.dns_addr, dns, 4);
}

bool ip_config_with_dhcp()
{
	int retry = 0;
	while (1) {
		send_dhcp_discover();
		ip_stack_globals.dhcp_ack_waiting = 0;
		ip_stack_globals.state = STATE_SENT_DHCP_DISCOVER;
		uint32_t start_tick = milliseconds();
		while (1) {
			if (ip_stack_globals.state == STATE_IDLE) {
				return true;
			}
			ip_stack_process();
			if (milliseconds() - start_tick >= 2000) {
				break;
			}
		}
		retry++;
		if (retry >= 5) {
			break;
		}
	}
	return false;
}

bool send_ip_packet(uint8_t *packet, int length)
{
	struct frame_t {
		struct ethernet_frame_t eth;
		struct ip_frame_t ip;
	} *frame;

	if (length < sizeof(struct ethernet_frame_t) + sizeof(struct ip_frame_t)) {
		return false;
	}

	frame = (struct frame_t *)packet;

	memcpy(frame->eth.src, ip_stack_globals.mac_addr, 6);

	frame->ip.version_and_length = 0x45; // version=4; length=20
	write_s(&frame->ip.flags_and_fragment_offset, 0);
	frame->ip.time_to_live = 64;

	if ((frame->ip.dst & get_ip_subnet_mask()) == (get_ip_address() & get_ip_subnet_mask())) {
		if (!get_mac_from_ipv4((uint8_t const *)&frame->ip.dst, frame->eth.dst)) {
			return false;
		}
	} else if (frame->ip.dst == 0xffffffff) {
		memset(frame->eth.dst, 0xff, 6);
	} else {
		if (!get_mac_from_ipv4(ip_stack_globals.gateway_addr, frame->eth.dst)) {
			return false;
		}
	}

	memcpy(&frame->ip.src, ip_stack_globals.ipv4_addr, 4);
	write_s(&frame->eth.type, 0x0800);

	write_s(&frame->ip.total_length, length - sizeof(struct ethernet_frame_t));

	set_ip_identifier(&frame->ip);

	if (frame->ip.protocol == 17) {
		struct udp_frame_t *udp = (struct udp_frame_t *)(packet + sizeof(struct ethernet_frame_t) + sizeof(struct ip_frame_t));
		set_udp_checksum(udp, &frame->ip);
	}

	prepare_ip_packet(&frame->ip, packet + length);

	set_ip_checksum(&frame->ip);
	eth_send_packet(packet, length);

	return true;
}

bool send_udp_packet(uint8_t const *dstipv4, uint16_t dstport, uint16_t srcport, uint8_t const *ptr, uint16_t len)
{
	uint8_t tmp[MAX_FRAME_SIZE];

	if (sizeof(struct eth_ip_udp_frame_t) + len > MAX_FRAME_SIZE) {
		return false;
	}

	uint8_t *p = tmp + sizeof(struct eth_ip_udp_frame_t);
	memcpy(p, ptr, len);
	p += len;

	prepare_udp_packet((struct eth_ip_udp_frame_t *)tmp, dstipv4, dstport, srcport, p);

	return send_ip_packet(tmp, p - tmp);
}

struct packet_header_t *take_udp_packet()
{
	struct packet_header_t *packet;
	if (ip_stack_globals.udp_packet_count < 1) {
		return 0;
	}
	packet = ip_stack_globals.udp_packets[0];
	ip_stack_globals.udp_packet_count--;
	memmove(ip_stack_globals.udp_packets, ip_stack_globals.udp_packets + 1, sizeof(struct packet_header_t *) * ip_stack_globals.udp_packet_count);
	return packet;
}

bool query_dns(char const *name, uint8_t *ipv4)
{
	uint8_t tmp[MAX_FRAME_SIZE];
	struct frame_t {
		struct eth_ip_udp_frame_t header;
		struct dns_frame_t dns;
	}  __attribute__ ((packed)) *frame;

	uint8_t *p;
	uint8_t *end;
	uint16_t packetlength;


	memset(tmp, 0, sizeof(tmp));

	frame = (struct frame_t *)tmp;
	p = tmp + sizeof(struct frame_t);
	end = tmp + MAX_FRAME_SIZE;

	write_s(&frame->dns.flags, 0x0100);
	write_s(&frame->dns.questions, 1);
	write_s(&frame->dns.answer_rrs, 0);
	write_s(&frame->dns.authority_rrs, 0);
	write_s(&frame->dns.additional_rrs, 0);

	char const *s = name;
	while (*s) {
		int n;
		for (n = 0; s[n]; n++) {
			if (s[n] == '.') {
				break;
			}
			if (s[n] == '/') {
				return false;
			}
		}
		if (n > 255) {
			return false;
		}
		if (p + 1 + n > end) {
			return false;
		}
		*p++ = n;
		memcpy(p, s, n);
		p += n;
		s += n;
		if (*s != '.') {
			break;
		}
		s++;
	}
	if (p + 5 > end) {
		return false;
	}
	*p++ = 0;
	write_s(p, 0x0001);
	p += 2;
	write_s(p, 0x0001);
	p += 2;

	prepare_udp_packet(&frame->header, ip_stack_globals.dns_addr, 53, 1024, p);
	packetlength = p - tmp;

	int index;
	for (index = 0; index < DNS_CACHE_SIZE - 1; index++) {
		if (!ip_stack_globals.dns_cache[index]) {
			break;
		}
	}
	struct dns_cache_item_t *item = ip_stack_globals.dns_cache[index];
	if (item) {
		free(item);
	}
	if (index > 0) {
		memmove(&ip_stack_globals.dns_cache[1], ip_stack_globals.dns_cache, sizeof(struct dns_cache_item_t *) * index);
	}
	int n = sizeof(struct dns_cache_item_t) + strlen(name);
	item = (struct dns_cache_item_t *)malloc(n);
	memset(item, 0, n);
	strcpy(item->name, name);
	ip_stack_globals.dns_cache[0] = item;

	int retry = -1;
	uint32_t tick = 0;
	while (1) {
		if (retry == -1 || milliseconds() - tick >= 5000) {
			retry++;
			if (retry >= 12) {
				return false;
			}
			write_s(&item->transaction_id, ip_stack_globals.dns_transaction_id);
			ip_stack_globals.dns_transaction_id++;
			if (!send_ip_packet(tmp, packetlength)) {
				return false;
			}
			tick = milliseconds();
		}
		ip_stack_process();
		if (ip_stack_globals.state == STATE_IDLE) {
			for (index = 0; index < DNS_CACHE_SIZE; index++) {
				item = ip_stack_globals.dns_cache[index];
				if (item && item->valid_address && strcmp(item->name, name) == 0) {
					memcpy(ipv4, item->ipv4, 4);
					return true;
				}
			}
		}
	}
}

bool gethostbyname(char const *name, uint8_t *ipv4)
{
	int i;
	uint8_t addr[4];
	uint8_t const *p;
	p = (uint8_t const *)name;
	if (isdigit(*p)) {
		int n;
		i = 0;
		while (1) {
			if (i == 4) {
				if (*p == 0) {
					memcpy(ipv4, addr, 4);
					return true;
				}
			}
			if (i > 0) {
				if (*p != '.') {
					goto L1;
				}
				p++;
			}
			if (!isdigit(*p)) {
				goto L1;
			}
			n = 0;
			if (*p == '0') {
				p++;
			} else {
				while (isdigit(*p)) {
					n = n * 10 + (*p - '0');
					if (n > 255) {
						goto L1;
					}
					p++;
				}
			}
			addr[i] = n;
			i++;
		}
	}
L1:;
	for (i = 0; i < DNS_CACHE_SIZE; i++) {
		struct dns_cache_item_t *item = ip_stack_globals.dns_cache[i];
		if (item && strcmp(name, item->name) == 0) {
			if (item->valid_address) {
				memcpy(ipv4, item->ipv4, 4);
				memmove(&ip_stack_globals.dns_cache[1], ip_stack_globals.dns_cache, sizeof(struct dns_cache_item_t *) * i);
				ip_stack_globals.dns_cache[0] = item;
				return true;
			}
			free(item);
			ip_stack_globals.dns_cache[i] = 0;
		}
	}

	if (query_dns(name, addr)) {
		memcpy(ipv4, addr, 4);
		return true;
	}

	return false;
}


//


