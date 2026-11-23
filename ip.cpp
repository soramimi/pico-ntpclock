/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#include "ip.h"
#include "pico/rand.h"
#include "pico/stdlib.h"
#include <ctype.h>
#include <string.h>

#define MAX_FRAME_SIZE 1518

uint16_t ntohs(uint16_t v)
{
	return ((v << 8) & 0xff00) | ((v >> 8) & 0x00ff);
}

uint16_t htons(uint16_t v)
{
	return ((v << 8) & 0xff00) | ((v >> 8) & 0x00ff);
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
} __attribute__((packed));

struct tcp_frame_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t sequence_number;
	uint32_t acknowledgment_number;
	uint16_t flags;
	uint16_t window_size_value;
	uint16_t checksum;
	uint16_t urgent_pointer;
} __attribute__((packed));

struct udp_frame_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
} __attribute__((packed));

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
} __attribute__((packed));

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
} __attribute__((packed));

struct icmp_frame_t {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t sequence_number;
} __attribute__((packed));

struct dns_frame_t {
	uint16_t transaction_id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answer_rrs;
	uint16_t authority_rrs;
	uint16_t additional_rrs;
} __attribute__((packed));

enum dhcp_state_t : uint8_t {
	DHCP_IDLE,
	DHCP_SELECTING,
	DHCP_REQUESTING,
	DHCP_BOUND,
	DHCP_RENEWING,
	DHCP_REBINDING,
};

struct dhcp_transaction_t {
	dhcp_state_t state;
	uint32_t xid;
	uint64_t next_action_ms;
	uint32_t offered_address;
	uint32_t server_identifier;
	bool awaiting_reply;
};
static constexpr uint32_t DHCP_REPLY_TIMEOUT_MS = 4000;
static constexpr uint32_t NETWORK_RETRY_MS = 1000;

struct dhcp_lease_t {
	uint64_t renew_at_ms;
	uint64_t rebind_at_ms;
	uint64_t expires_at_ms;
	uint32_t server_identifier;
};

#define ARP_CACHE_SIZE 10
#define DNS_CACHE_SIZE 10

struct arp_cache_item_t {
	uint64_t expires_at_ms;
	uint8_t ipv4[4];
	uint8_t mac[6];
};

struct dns_name_t {
	uint8_t wire[255];
	uint16_t length;
};

struct dns_cache_item_t {
	dns_name_t name;
	uint64_t expires_at_ms;
	uint8_t ipv4[4];
};

struct dns_query_t {
	dns_name_t name;
	uint32_t local_address;
	uint32_t server_address;
	uint64_t next_action_ms;
	uint32_t ttl_seconds;
	uint16_t id;
	uint16_t port;
	uint8_t ipv4[4];
	bool pending;
	bool answered;
};

static constexpr uint32_t DNS_REPLY_TIMEOUT_MS = 5000;

struct ntp_reply_t {
	uint8_t server[4];
	uint8_t timestamp[8];
	uint16_t port;
	bool received;
	uint8_t data[NTP_PACKET_SIZE];
};

enum tcp_state_t : uint8_t {
	TCP_CLOSED,
	TCP_SYN_RECEIVED,
	TCP_ESTABLISHED,
	TCP_FIN_SENT,
	TCP_TIME_WAIT,
};

struct tcp_peer_t {
	uint32_t address;
	uint16_t port;
	uint8_t mac[6];
};

static constexpr unsigned HTTP_RESPONSE_CAPACITY = 192;
static constexpr unsigned HTTP_REQUEST_LINE_CAPACITY = 256;
static constexpr unsigned HTTP_HEADER_LIMIT = 1024;
static constexpr uint32_t HTTP_REQUEST_TIMEOUT_MS = 5000;

struct tcp_connection_t {
	tcp_peer_t peer;
	uint32_t receive_next;
	uint32_t send_next;
	uint32_t send_unacknowledged;
	uint32_t last_activity;
	uint32_t last_send;
	uint32_t opened_at_ms;
	uint16_t response_length;
	uint16_t header_length;
	tcp_state_t state;
	uint8_t retries;
	uint8_t header_end;
	uint16_t request_line_length;
	bool peer_fin;
	bool request_line_complete;
	char request_line[HTTP_REQUEST_LINE_CAPACITY];
	// Keep the response for retransmission, even if the application data changes.
	char response[HTTP_RESPONSE_CAPACITY];
};

struct eth_ip_tcp_frame_t {
	struct ethernet_frame_t eth;
	struct ip_frame_t ip;
	struct tcp_frame_t tcp;
} __attribute__((packed));

struct eth_ip_udp_frame_t {
	struct ethernet_frame_t eth;
	struct ip_frame_t ip;
	struct udp_frame_t udp;
} __attribute__((packed));

struct ip_stack_globals_t {
	uint8_t mac_addr[6];
	uint8_t ipv4_addr[4];
	uint8_t subnet_mask[4];
	uint8_t gateway_addr[4];
	uint8_t dns_addr[4];
	uint16_t ip_identifier;
	struct arp_cache_item_t arp_cache[ARP_CACHE_SIZE];
	dns_cache_item_t dns_cache[DNS_CACHE_SIZE];
	dns_query_t dns_query;
	ntp_reply_t ntp_reply;
	dhcp_transaction_t dhcp;
	dhcp_lease_t lease;
	tcp_connection_t tcp_connections[16];
	uint64_t next_link_check_ms;
	bool controller_ready;
	bool link_up;
} ip_stack_globals;

static uint32_t network_generation;

static uint64_t monotonic_ms()
{
	return time_us_64() / 1000;
}

void ip_cancel_ntp_reply()
{
	ip_stack_globals.ntp_reply = { };
}

void ip_expect_ntp_reply(uint8_t const *server, uint16_t port, uint8_t const *timestamp)
{
	auto &reply = ip_stack_globals.ntp_reply;
	reply = { };
	memcpy(reply.server, server, sizeof(reply.server));
	memcpy(reply.timestamp, timestamp, sizeof(reply.timestamp));
	reply.port = port;
}

bool ip_take_ntp_reply(uint8_t *data)
{
	auto &reply = ip_stack_globals.ntp_reply;
	if (!reply.received) {
		return false;
	}
	memcpy(data, reply.data, sizeof(reply.data));
	reply.received = false;
	return true;
}

static void clear_network_sessions()
{
	memset(ip_stack_globals.arp_cache, 0, sizeof(ip_stack_globals.arp_cache));
	memset(ip_stack_globals.dns_cache, 0, sizeof(ip_stack_globals.dns_cache));
	memset(ip_stack_globals.tcp_connections, 0, sizeof(ip_stack_globals.tcp_connections));
	ip_stack_globals.dns_query = { };
	ip_cancel_ntp_reply();
	++network_generation;
}

void ip_stack_init(uint8_t const *macaddr)
{
	memset(&ip_stack_globals, 0, sizeof(ip_stack_globals));
	memcpy(ip_stack_globals.mac_addr, macaddr, 6);
	++network_generation;
}

//

uint32_t get_ip_address()
{
	uint32_t address;
	memcpy(&address, ip_stack_globals.ipv4_addr, sizeof(address));
	return address;
}

uint32_t get_ip_subnet_mask()
{
	uint32_t mask;
	memcpy(&mask, ip_stack_globals.subnet_mask, sizeof(mask));
	return mask;
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

uint32_t read_l(void const *ptr)
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

uint16_t read_s(void const *ptr)
{
	uint8_t const *p = (uint8_t const *)ptr;
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

static uint16_t transport_checksum(struct ip_frame_t const *ip, void const *segment, uint16_t len)
{
	struct {
		uint32_t src;
		uint32_t dst;
		uint8_t zero;
		uint8_t protocol;
		uint16_t length;
	} header;
	header.src = ip->src;
	header.dst = ip->dst;
	header.zero = 0;
	header.protocol = ip->protocol;
	write_s(&header.length, len);

	uint16_t sum = compute_sum(0, &header, sizeof(header));
	return ~compute_sum(sum, segment, len);
}

void set_udp_checksum(struct ip_frame_t *ip)
{
	struct udp_frame_t *udp = (struct udp_frame_t *)(ip + 1);
	udp->checksum = 0;
	uint16_t checksum = transport_checksum(ip, udp, read_s(&udp->length));
	write_s(&udp->checksum, checksum ? checksum : 0xffff);
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

void prepare_ip_packet(struct ip_frame_t *ip, void *end)
{
	ip->version_and_length = 0x45; // version=4; length=20
	set_ip_identifier(ip);
	ip->time_to_live = 64;
	if (end) {
		uint16_t len = (uint8_t const *)end - (uint8_t const *)ip;
		write_s(&ip->total_length, len);
	}
}

void prepare_tcp_packet(struct eth_ip_tcp_frame_t *frame, uint32_t dstipv4, uint16_t dstport, uint16_t srcport)
{
	frame->ip.protocol = 6;
	frame->ip.dst = dstipv4;
	write_s(&frame->tcp.dst_port, dstport);
	write_s(&frame->tcp.src_port, srcport);
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
} __attribute__((packed));

static bool send_ip_packet(uint8_t *packet, int length);

static bool send_dhcp_message(dhcp_transaction_t const &transaction)
{
	uint8_t packet[sizeof(dhcp_header_frame_t) + 64] = { };
	auto *frame = reinterpret_cast<dhcp_header_frame_t *>(packet);
	auto &dhcp = frame->dhcp;
	auto const *mac = ip_stack_globals.mac_addr;
	bool configuring = transaction.state == DHCP_SELECTING || transaction.state == DHCP_REQUESTING;
	bool unicast = transaction.state == DHCP_RENEWING;

	dhcp.msg_type = 1;
	dhcp.hw_type = 1;
	dhcp.hw_addr_len = 6;
	write_l(&dhcp.transaction_id, transaction.xid);
	write_s(&dhcp.bootp_flags, configuring ? 0x8000 : 0);
	memcpy(dhcp.client_mac_addr, mac, 6);
	if (!configuring) {
		dhcp.client_ip_addr = get_ip_address();
		frame->header.ip.src = dhcp.client_ip_addr;
	}
	write_l(&dhcp.magic_cookie, DHCP_MAGIC_COOKIE);
	write_s(&frame->header.ip.flags_and_fragment_offset, 0x4000);

	uint8_t *p = packet + sizeof(*frame);
	*p++ = 53; // Message Type
	*p++ = 1;
	*p++ = transaction.state == DHCP_SELECTING ? 1 : 3;
	*p++ = 61; // Client Identifier
	*p++ = 7;
	*p++ = 1;
	memcpy(p, mac, 6);
	p += 6;
	if (transaction.state == DHCP_REQUESTING) {
		*p++ = 50; // Requested IP Address
		*p++ = 4;
		memcpy(p, &transaction.offered_address, 4);
		p += 4;
		*p++ = 54; // Server Identifier
		*p++ = 4;
		memcpy(p, &transaction.server_identifier, 4);
		p += 4;
	}
	static constexpr uint8_t options[] = { 55, 6, 1, 3, 6, 51, 58, 59, 255 };
	memcpy(p, options, sizeof(options));
	p += sizeof(options);

	uint32_t destination = unicast ? transaction.server_identifier : UINT32_MAX;
	prepare_udp_packet(&frame->header, reinterpret_cast<uint8_t const *>(&destination), 67, 68, p);
	if (unicast) {
		return send_ip_packet(packet, p - packet);
	}
	memset(frame->header.eth.dst, 0xff, 6);
	memcpy(frame->header.eth.src, mac, 6);
	write_s(&frame->header.eth.type, 0x0800);
	prepare_ip_packet(&frame->header.ip, p);
	set_udp_checksum(&frame->header.ip);
	set_ip_checksum(&frame->header.ip);
	return eth_send_packet(packet, p - packet);
}

void send_arp_request(uint8_t const *ipv4)
{
	struct frame_t {
		struct ethernet_frame_t eth;
		struct arp_frame_t arp;
	} __attribute__((packed)) frame;

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
	} __attribute__((packed)) frame;

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

void send_icmp_echo_reply(struct ethernet_frame_t const *eth, struct ip_frame_t const *ip, struct icmp_frame_t const *icmp, int icmp_length)
{
	// Sending directly at the Ethernet layer does not re-enter packet processing.
	static uint8_t tmp[MAX_FRAME_SIZE];
	struct frame_t {
		struct ethernet_frame_t eth;
		struct ip_frame_t ip;
		struct icmp_frame_t icmp;
	} __attribute__((packed)) * frame;

	frame = (struct frame_t *)tmp;

	memset(frame, 0, sizeof(*frame));

	memcpy(frame->eth.dst, eth->src, 6);
	memcpy(frame->eth.src, ip_stack_globals.mac_addr, 6);
	write_s(&frame->eth.type, 0x0800);

	write_s(&frame->ip.flags_and_fragment_offset, 0);
	frame->ip.protocol = 0x01; // icmp
	frame->ip.dst = ip->src;
	memcpy(&frame->ip.src, ip_stack_globals.ipv4_addr, 4);

	uint8_t *p = (uint8_t *)&frame->icmp;
	memcpy(p, icmp, icmp_length);
	p += icmp_length;

	frame->icmp.type = 0; // reply

	prepare_ip_packet(&frame->ip, p);
	set_ip_checksum(&frame->ip);
	set_icmp_checksum(&frame->icmp, &frame->ip);
	eth_send_packet(tmp, p - tmp);
}

//

void on_icmp_packet(struct ethernet_frame_t const *eth, struct ip_frame_t const *ip, uint8_t const *p, unsigned icmp_length)
{
	if (icmp_length < sizeof(struct icmp_frame_t) || compute_sum(0, p, icmp_length) != 0xffff) {
		return;
	}
	struct icmp_frame_t const *icmp = (struct icmp_frame_t const *)p;
	if (icmp->type == 8 && icmp->code == 0) { // echo request
		send_icmp_echo_reply(eth, ip, icmp, icmp_length);
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

struct dhcp_options_t {
	uint8_t message_type;
	uint32_t server_identifier;
	uint32_t lease_seconds;
	uint32_t renew_seconds;
	uint32_t rebind_seconds;
	uint8_t subnet_mask[4];
	uint8_t gateway[4];
	uint8_t dns[4];
};

static bool read_dhcp_options(uint8_t const *options, size_t length, dhcp_options_t &result)
{
	while (length > 0) {
		uint8_t code = *options++;
		--length;
		if (code == 0) {
			continue;
		}
		if (code == 255) {
			return result.message_type != 0 && result.server_identifier != 0;
		}
		if (length == 0) {
			return false;
		}
		uint8_t size = *options++;
		--length;
		if (size > length) {
			return false;
		}
		switch (code) {
		case 53: // DHCP Message Type
			if (size != 1 || result.message_type != 0 || options[0] == 0) {
				return false;
			}
			result.message_type = options[0];
			break;
		case 54: // Server Identifier
			if (size != 4 || result.server_identifier != 0 || is_addr_zero(options)) {
				return false;
			}
			memcpy(&result.server_identifier, options, 4);
			break;
		case 1: // Subnet Mask
			if (size != 4) {
				return false;
			}
			memcpy(result.subnet_mask, options, 4);
			break;
		case 3: // Router
		case 6: // DNS
			if (size < 4 || size % 4 != 0) {
				return false;
			}
			memcpy(code == 3 ? result.gateway : result.dns, options, 4);
			break;
		case 51: // Lease time
		case 58: // Renewal time (T1)
		case 59: // Rebinding time (T2)
			if (size != 4) {
				return false;
			}
			if (code == 51) {
				result.lease_seconds = read_l(options);
			} else if (code == 58) {
				result.renew_seconds = read_l(options);
			} else {
				result.rebind_seconds = read_l(options);
			}
			break;
		}
		options += size;
		length -= size;
	}
	return false;
}

static void drop_network_configuration()
{
	clear_network_sessions();
	memset(ip_stack_globals.ipv4_addr, 0, sizeof(ip_stack_globals.ipv4_addr));
	memset(ip_stack_globals.subnet_mask, 0, sizeof(ip_stack_globals.subnet_mask));
	memset(ip_stack_globals.gateway_addr, 0, sizeof(ip_stack_globals.gateway_addr));
	memset(ip_stack_globals.dns_addr, 0, sizeof(ip_stack_globals.dns_addr));
	ip_stack_globals.dhcp = { };
	ip_stack_globals.lease = { };
}

static void send_current_dhcp_message()
{
	auto &transaction = ip_stack_globals.dhcp;
	transaction.awaiting_reply = send_dhcp_message(transaction);
	uint64_t now = monotonic_ms();
	uint64_t delay = transaction.awaiting_reply ? DHCP_REPLY_TIMEOUT_MS : NETWORK_RETRY_MS;
	if (transaction.awaiting_reply && (transaction.state == DHCP_RENEWING || transaction.state == DHCP_REBINDING)) {
		auto const &lease = ip_stack_globals.lease;
		uint64_t boundary = transaction.state == DHCP_RENEWING ? lease.rebind_at_ms : lease.expires_at_ms;
		uint64_t half_remaining = boundary > now ? (boundary - now) / 2 : 0;
		delay = half_remaining > 60000 ? half_remaining : 60000;
	}
	transaction.next_action_ms = now + delay;
}

static void set_dhcp_lease(dhcp_options_t const &options, uint64_t now)
{
	auto &lease = ip_stack_globals.lease;
	lease.server_identifier = options.server_identifier;
	if (options.lease_seconds == UINT32_MAX) {
		lease.renew_at_ms = UINT64_MAX;
		lease.rebind_at_ms = UINT64_MAX;
		lease.expires_at_ms = UINT64_MAX;
		return;
	}
	uint64_t lifetime = uint64_t(options.lease_seconds) * 1000;
	uint64_t renew = options.renew_seconds != 0 ? uint64_t(options.renew_seconds) * 1000 : lifetime / 2;
	uint64_t rebind = options.rebind_seconds != 0 ? uint64_t(options.rebind_seconds) * 1000 : lifetime * 7 / 8;
	if (renew >= rebind || rebind >= lifetime) {
		renew = lifetime / 2;
		rebind = lifetime * 7 / 8;
	}
	lease.renew_at_ms = now + renew;
	lease.rebind_at_ms = now + rebind;
	lease.expires_at_ms = now + lifetime;
}

static void on_dhcp_reply(uint32_t destination, uint8_t const *data, size_t length)
{
	auto &transaction = ip_stack_globals.dhcp;
	uint64_t now = monotonic_ms();
	if (!transaction.awaiting_reply || now >= transaction.next_action_ms || length < sizeof(dhcp_frame_t)) {
		return;
	}
	bool renewing = transaction.state == DHCP_RENEWING || transaction.state == DHCP_REBINDING;
	auto const &lease = ip_stack_globals.lease;
	if (renewing && (now >= lease.expires_at_ms || (transaction.state == DHCP_RENEWING && now >= lease.rebind_at_ms))) {
		return;
	}
	auto const *reply = reinterpret_cast<dhcp_frame_t const *>(data);
	if (reply->msg_type != 2 || reply->hw_type != 1 || reply->hw_addr_len != 6 || read_l(&reply->magic_cookie) != DHCP_MAGIC_COOKIE || read_l(&reply->transaction_id) != transaction.xid || memcmp(reply->client_mac_addr, ip_stack_globals.mac_addr, 6) != 0) {
		return;
	}

	uint32_t offered = reply->user_ip_addr;
	uint32_t expected_address = transaction.state == DHCP_SELECTING ? offered : transaction.offered_address;
	if (destination != UINT32_MAX && (destination == 0 || destination != expected_address)) {
		return;
	}

	dhcp_options_t options = { };
	if (renewing) {
		memcpy(options.subnet_mask, ip_stack_globals.subnet_mask, 4);
		memcpy(options.gateway, ip_stack_globals.gateway_addr, 4);
		memcpy(options.dns, ip_stack_globals.dns_addr, 4);
	}
	if (!read_dhcp_options(data + sizeof(*reply), length - sizeof(*reply), options)) {
		return;
	}
	if (transaction.state == DHCP_SELECTING) {
		if (options.message_type == 2 && offered != 0 && offered != UINT32_MAX) { // OFFER
			transaction.offered_address = offered;
			transaction.server_identifier = options.server_identifier;
			transaction.state = DHCP_REQUESTING;
			send_current_dhcp_message();
		}
		return;
	}

	if (transaction.state != DHCP_REBINDING && options.server_identifier != transaction.server_identifier) {
		return;
	}
	if (options.message_type == 6) { // NAK
		drop_network_configuration();
		transaction.next_action_ms = now + NETWORK_RETRY_MS;
	} else if (options.message_type == 5 && offered == transaction.offered_address && options.lease_seconds != 0 && !is_addr_zero(options.subnet_mask) && !is_addr_zero(options.dns)) { // ACK
		uint8_t address[4];
		memcpy(address, &offered, sizeof(address));
		ip_config(address, options.subnet_mask, options.gateway, options.dns);
		set_dhcp_lease(options, now);
		transaction.state = DHCP_BOUND;
		transaction.awaiting_reply = false;
	}
}

static void poll_dhcp(uint64_t now)
{
	auto &transaction = ip_stack_globals.dhcp;
	auto const &lease = ip_stack_globals.lease;
	if (lease.expires_at_ms != 0 && now >= lease.expires_at_ms) {
		drop_network_configuration();
	}
	if (transaction.state == DHCP_BOUND && now < lease.renew_at_ms) {
		return;
	}
	if (transaction.state == DHCP_BOUND || (transaction.state == DHCP_RENEWING && now >= lease.rebind_at_ms)) {
		dhcp_state_t next = now >= lease.rebind_at_ms ? DHCP_REBINDING : DHCP_RENEWING;
		transaction = { next, get_rand_32(), now, get_ip_address(), lease.server_identifier, false };
	}
	if (now < transaction.next_action_ms) {
		return;
	}
	if (transaction.state != DHCP_RENEWING && transaction.state != DHCP_REBINDING) {
		transaction = { DHCP_SELECTING, get_rand_32(), now, 0, 0, false };
	}
	send_current_dhcp_message();
}

// Store expanded names in wire format so label boundaries survive comparison.
static uint8_t dns_lowercase(uint8_t byte)
{
	return byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte;
}

static bool dns_names_equal(dns_name_t const &a, dns_name_t const &b)
{
	return a.length == b.length && memcmp(a.wire, b.wire, a.length) == 0;
}

static bool read_dns_name(uint8_t const *message, size_t length, size_t &offset, dns_name_t *name = nullptr)
{
	size_t position = offset;
	size_t resume = 0;
	size_t expanded_length = 0;
	unsigned jumps = 0;
	while (position < length) {
		size_t label_offset = position;
		uint8_t label = message[position++];
		if ((label & 0xc0) == 0xc0) {
			if (position == length || ++jumps > 32) {
				return false;
			}
			size_t target = ((label & 0x3f) << 8) | message[position++];
			if (target < sizeof(dns_frame_t) || target >= label_offset) {
				return false;
			}
			if (resume == 0) {
				resume = position;
			}
			position = target;
			continue;
		}
		if (label > 63 || label > length - position || expanded_length + 1 + label > sizeof(dns_name_t::wire)) {
			return false;
		}
		if (name) {
			name->wire[expanded_length] = label;
			for (size_t i = 0; i < label; ++i) {
				name->wire[expanded_length + 1 + i] = dns_lowercase(message[position + i]);
			}
		}
		expanded_length += 1 + label;
		position += label;
		if (label == 0) {
			offset = resume != 0 ? resume : position;
			if (name) {
				name->length = expanded_length;
			}
			return true;
		}
	}
	return false;
}

struct dns_record_t {
	size_t data_offset;
	uint32_t ttl;
	uint16_t type;
	uint16_t record_class;
	uint16_t data_length;
};

static bool read_dns_record(uint8_t const *message, size_t length, size_t &offset,
	dns_record_t &record, dns_name_t *owner = nullptr)
{
	if (!read_dns_name(message, length, offset, owner) || length - offset < 10) {
		return false;
	}
	record.type = read_s(message + offset);
	record.record_class = read_s(message + offset + 2);
	record.ttl = read_l(message + offset + 4);
	record.data_length = read_s(message + offset + 8);
	offset += 10;
	record.data_offset = offset;
	if (record.data_length > length - offset) {
		return false;
	}
	offset += record.data_length;
	if (record.record_class == 1) {
		if (record.type == 1) { // A
			return record.data_length == 4;
		}
		if (record.type == 5) { // CNAME
			size_t target = record.data_offset;
			return read_dns_name(message, offset, target) && target == offset;
		}
	}
	return true;
}

static bool find_dns_answer(uint8_t const *message, size_t length, size_t answer_offset,
	unsigned answer_count, dns_name_t name, uint8_t *address, uint32_t &ttl)
{
	ttl = UINT32_MAX;
	for (unsigned hop = 0; hop <= 8; ++hop) {
		size_t offset = answer_offset;
		bool followed_alias = false;
		for (unsigned i = 0; i < answer_count; ++i) {
			dns_name_t owner;
			dns_record_t record;
			if (!read_dns_record(message, length, offset, record, &owner)) {
				return false;
			}
			if (record.record_class != 1 || !dns_names_equal(owner, name)) {
				continue;
			}
			if (record.type == 1) { // A
				memcpy(address, message + record.data_offset, 4);
				ttl = record.ttl < ttl ? record.ttl : ttl;
				return true;
			}
			if (record.type == 5) { // CNAME
				size_t target = record.data_offset;
				if (!read_dns_name(message, offset, target, &name)) {
					return false;
				}
				ttl = record.ttl < ttl ? record.ttl : ttl;
				followed_alias = true;
				break;
			}
		}
		if (!followed_alias) {
			break;
		}
	}
	return false;
}

static void on_dns_reply(uint8_t const *message, size_t length)
{
	auto &query = ip_stack_globals.dns_query;
	if (length < sizeof(dns_frame_t)) {
		return;
	}
	auto const *header = reinterpret_cast<dns_frame_t const *>(message);
	if (read_s(&header->transaction_id) != query.id || read_s(&header->questions) != 1 || (read_s(&header->flags) & 0xfa4f) != 0x8000) { // Standard, complete reply with no error.
		return;
	}
	size_t offset = sizeof(*header);
	dns_name_t question;
	if (!read_dns_name(message, length, offset, &question) || !dns_names_equal(question, query.name) || length - offset < 4 || read_s(message + offset) != 1 || read_s(message + offset + 2) != 1) {
		return;
	}
	offset += 4;
	size_t answer_offset = offset;
	unsigned answers = read_s(&header->answer_rrs);
	unsigned records = answers + read_s(&header->authority_rrs) + read_s(&header->additional_rrs);
	if (records > (length - offset) / 11) {
		return;
	}
	for (unsigned i = 0; i < records; ++i) {
		dns_record_t record;
		if (!read_dns_record(message, length, offset, record)) {
			return;
		}
	}
	if (offset == length && find_dns_answer(message, length, answer_offset, answers, query.name, query.ipv4, query.ttl_seconds)) {
		query.answered = true;
		query.pending = false;
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
	ip_stack_globals.arp_cache[0] = item;
}

static int find_mac_from_arp_cache(uint8_t const *ipv4)
{
	uint64_t now = monotonic_ms();
	for (int i = 0; i < ARP_CACHE_SIZE; i++) {
		auto const &entry = ip_stack_globals.arp_cache[i];
		if (entry.expires_at_ms > now && memcmp(entry.ipv4, ipv4, 4) == 0) {
			return i;
		}
	}
	return -1;
}

static bool get_mac_from_ipv4(uint8_t const *ipv4, uint8_t *mac)
{
	int i = find_mac_from_arp_cache(ipv4);
	if (i < 0) {
		if (!is_addr_zero(ipv4)) {
			send_arp_request(ipv4);
		}
		// DNS, DHCP renewal and NTP retry on their own timers.
		return false;
	}
	memcpy(mac, ip_stack_globals.arp_cache[i].mac, 6);
	arp_cache_move_to_front(i);
	return true;
}

static bool send_ip_packet(uint8_t *packet, int length)
{
	struct frame_t {
		struct ethernet_frame_t eth;
		struct ip_frame_t ip;
	} *frame;

	if (!ip_stack_globals.link_up || get_ip_address() == 0 || length < (int)sizeof(*frame)) {
		return false;
	}

	frame = (struct frame_t *)packet;

	memcpy(frame->eth.src, ip_stack_globals.mac_addr, 6);

	if (frame->ip.dst == UINT32_MAX) {
		memset(frame->eth.dst, 0xff, 6);
	} else if ((frame->ip.dst & get_ip_subnet_mask()) == (get_ip_address() & get_ip_subnet_mask())) {
		if (!get_mac_from_ipv4((uint8_t const *)&frame->ip.dst, frame->eth.dst)) {
			return false;
		}
	} else {
		if (!get_mac_from_ipv4(ip_stack_globals.gateway_addr, frame->eth.dst)) {
			return false;
		}
	}

	memcpy(&frame->ip.src, ip_stack_globals.ipv4_addr, 4);
	write_s(&frame->eth.type, 0x0800);

	write_s(&frame->ip.total_length, length - sizeof(struct ethernet_frame_t));

	set_ip_identifier(&frame->ip);

	if (frame->ip.protocol == 17) { // UDP
		set_udp_checksum(&frame->ip);
	}

	prepare_ip_packet(&frame->ip, packet + length);

	set_ip_checksum(&frame->ip);
	return eth_send_packet(packet, length);
}

bool send_udp_packet(uint8_t const *dstipv4, uint16_t dstport, uint16_t srcport, uint8_t const *ptr, uint16_t len)
{
	uint8_t tmp[MAX_FRAME_SIZE];

	if (sizeof(struct eth_ip_udp_frame_t) + len > MAX_FRAME_SIZE) {
		return false;
	}

	memset(tmp, 0, sizeof(struct eth_ip_udp_frame_t));
	uint8_t *p = tmp + sizeof(struct eth_ip_udp_frame_t);
	memcpy(p, ptr, len);
	p += len;

	prepare_udp_packet((struct eth_ip_udp_frame_t *)tmp, dstipv4, dstport, srcport, p);

	return send_ip_packet(tmp, p - tmp);
}

static constexpr uint16_t HTTP_PORT = 80;
static constexpr uint32_t TCP_RETRY_MS = 1000;
static constexpr uint32_t TCP_IDLE_MS = 30000;
static constexpr uint32_t TCP_TIME_WAIT_MS = 120000;

enum : uint16_t {
	TCP_FIN = 0x01,
	TCP_SYN = 0x02,
	TCP_RST = 0x04,
	TCP_PSH = 0x08,
	TCP_ACK = 0x10,
};

static bool tcp_sequence_before(uint32_t a, uint32_t b)
{
	return a - b > UINT32_MAX / 2;
}

static void send_tcp_segment(tcp_peer_t const &peer, uint32_t sequence, uint32_t acknowledgment,
	uint16_t flags, char const *payload = nullptr, unsigned payload_length = 0)
{
	uint8_t bytes[sizeof(eth_ip_tcp_frame_t) + HTTP_RESPONSE_CAPACITY] = { };
	auto *frame = (struct eth_ip_tcp_frame_t *)bytes;
	memcpy(frame->eth.dst, peer.mac, 6);
	memcpy(frame->eth.src, ip_stack_globals.mac_addr, 6);
	write_s(&frame->eth.type, 0x0800);

	prepare_tcp_packet(frame, peer.address, peer.port, HTTP_PORT);
	memcpy(&frame->ip.src, ip_stack_globals.ipv4_addr, 4);
	write_s(&frame->ip.flags_and_fragment_offset, 0x4000);
	write_s(&frame->tcp.flags, (sizeof(frame->tcp) << 10) | flags);
	write_l(&frame->tcp.sequence_number, sequence);
	write_l(&frame->tcp.acknowledgment_number, acknowledgment);
	write_s(&frame->tcp.window_size_value, (flags & TCP_RST) ? 0 : 4096);
	if (payload_length != 0) {
		memcpy(bytes + sizeof(*frame), payload, payload_length);
	}

	unsigned length = sizeof(*frame) + payload_length;
	prepare_ip_packet(&frame->ip, bytes + length);
	write_s(&frame->tcp.checksum, transport_checksum(&frame->ip, &frame->tcp, sizeof(frame->tcp) + payload_length));
	set_ip_checksum(&frame->ip);
	// The incoming Ethernet source is the next hop for this reply.
	eth_send_packet(bytes, length);
}

static void send_tcp_ack(tcp_connection_t const &connection)
{
	send_tcp_segment(connection.peer, connection.send_next, connection.receive_next, TCP_ACK);
}

static void send_pending_tcp_segment(tcp_connection_t &connection, uint32_t now)
{
	connection.last_send = now;
	if (connection.state == TCP_SYN_RECEIVED) {
		send_tcp_segment(connection.peer, connection.send_unacknowledged, connection.receive_next, TCP_SYN | TCP_ACK);
		return;
	}

	// An outstanding FIN occupies the last sequence number after the response.
	unsigned remaining = connection.send_next - connection.send_unacknowledged - 1;
	uint16_t flags = TCP_ACK | TCP_FIN;
	char const *payload = nullptr;
	if (remaining != 0) {
		flags |= TCP_PSH;
		payload = connection.response + (connection.response_length - remaining);
	}
	send_tcp_segment(connection.peer, connection.send_unacknowledged, connection.receive_next, flags, payload, remaining);
}

static tcp_connection_t *find_tcp_connection(tcp_peer_t const &peer)
{
	for (auto &connection : ip_stack_globals.tcp_connections) {
		if (connection.state != TCP_CLOSED && connection.peer.address == peer.address && connection.peer.port == peer.port) {
			return &connection;
		}
	}
	return nullptr;
}

static void accept_tcp_connection(tcp_peer_t const &peer, uint32_t sequence, uint32_t now)
{
	tcp_connection_t *slot = nullptr;
	for (auto &connection : ip_stack_globals.tcp_connections) {
		if (connection.state == TCP_CLOSED) {
			slot = &connection;
			break;
		}
		if (connection.state == TCP_TIME_WAIT && (!slot || now - connection.last_activity > now - slot->last_activity)) {
			slot = &connection;
		}
	}
	if (!slot) {
		return;
	}

	*slot = { };
	slot->peer = peer;
	slot->state = TCP_SYN_RECEIVED;
	slot->receive_next = sequence + 1;
	slot->send_unacknowledged = get_rand_32();
	slot->send_next = slot->send_unacknowledged + 1;
	slot->last_activity = now;
	slot->opened_at_ms = now;
	send_pending_tcp_segment(*slot, now);
}

enum http_header_result_t {
	HTTP_HEADERS_PENDING,
	HTTP_HEADERS_COMPLETE,
	HTTP_URI_TOO_LONG,
	HTTP_HEADERS_TOO_LARGE,
};

static http_header_result_t receive_http_headers(tcp_connection_t &connection, uint8_t const *data, unsigned length)
{
	static constexpr char end_of_headers[] = "\r\n\r\n";
	for (unsigned i = 0; i < length; i++) {
		if (++connection.header_length > HTTP_HEADER_LIMIT) {
			return HTTP_HEADERS_TOO_LARGE;
		}
		uint8_t byte = data[i];
		if (!connection.request_line_complete) {
			if (byte == '\r' || byte == '\n') {
				connection.request_line_complete = true;
			} else if (connection.request_line_length < sizeof(connection.request_line) - 1) {
				connection.request_line[connection.request_line_length++] = byte;
			} else {
				return HTTP_URI_TOO_LONG;
			}
		}
		if (byte == end_of_headers[connection.header_end]) {
			if (++connection.header_end == sizeof(end_of_headers) - 1) {
				return HTTP_HEADERS_COMPLETE;
			}
		} else {
			connection.header_end = byte == '\r' ? 1 : 0;
		}
	}
	return HTTP_HEADERS_PENDING;
}

static bool http_request_expired(tcp_connection_t const &connection, uint32_t now)
{
	return (connection.state == TCP_SYN_RECEIVED || connection.state == TCP_ESTABLISHED) && now - connection.opened_at_ms >= HTTP_REQUEST_TIMEOUT_MS;
}

static void on_tcp_packet(struct ethernet_frame_t const *eth, struct ip_frame_t const *ip,
	uint8_t const *segment, unsigned segment_length)
{
	if (segment_length < sizeof(struct tcp_frame_t)) {
		return;
	}
	auto *tcp = (struct tcp_frame_t const *)segment;
	if (read_s(&tcp->dst_port) != HTTP_PORT || transport_checksum(ip, segment, segment_length) != 0) {
		return;
	}
	uint16_t flags = read_s(&tcp->flags);
	unsigned header_length = (flags >> 12) * 4;
	if (header_length < sizeof(*tcp) || header_length > segment_length) {
		return;
	}

	uint8_t const *data = segment + header_length;
	unsigned data_length = segment_length - header_length;
	tcp_peer_t peer = { ip->src, read_s(&tcp->src_port), { } };
	memcpy(peer.mac, eth->src, 6);

	uint32_t sequence = read_l(&tcp->sequence_number);
	uint32_t acknowledgment = read_l(&tcp->acknowledgment_number);
	bool fin = (flags & TCP_FIN) != 0;
	bool opening = (flags & (TCP_SYN | TCP_FIN | TCP_RST | TCP_ACK)) == TCP_SYN;
	uint32_t now = milliseconds();
	tcp_connection_t *connection = find_tcp_connection(peer);
	if (connection && http_request_expired(*connection, now)) {
		connection->state = TCP_CLOSED;
		connection = nullptr;
	}

	if (!connection) {
		if (opening) {
			accept_tcp_connection(peer, sequence, now);
		} else if (!(flags & TCP_RST)) {
			if (flags & TCP_ACK) {
				send_tcp_segment(peer, acknowledgment, 0, TCP_RST);
			} else {
				uint32_t next = sequence + data_length + ((flags & TCP_SYN) != 0) + fin;
				send_tcp_segment(peer, 0, next, TCP_RST | TCP_ACK);
			}
		}
		return;
	}

	if (connection->state == TCP_TIME_WAIT) {
		if (!(flags & TCP_RST) && fin && sequence + data_length + 1 == connection->receive_next) {
			connection->last_activity = now;
			send_tcp_ack(*connection);
		}
		return;
	}

	if (flags & TCP_RST) {
		if (sequence == connection->receive_next) {
			connection->state = TCP_CLOSED;
		}
		return;
	}

	if (connection->state == TCP_SYN_RECEIVED) {
		if (opening && sequence + 1 == connection->receive_next) {
			send_pending_tcp_segment(*connection, now);
			return;
		}
		if (!(flags & TCP_ACK) || (flags & TCP_SYN) || acknowledgment != connection->send_next || sequence != connection->receive_next) {
			return;
		}
		connection->state = TCP_ESTABLISHED;
	}

	if (!(flags & TCP_ACK) || (flags & TCP_SYN)) {
		return;
	}

	uint32_t overlap = connection->receive_next - sequence;
	if (overlap > data_length || (overlap != 0 && overlap == data_length && !fin) || tcp_sequence_before(connection->send_next, acknowledgment)) {
		if (data_length != 0 || fin || sequence == connection->receive_next || tcp_sequence_before(connection->receive_next, sequence)) {
			send_tcp_ack(*connection);
		}
		return;
	}

	connection->peer = peer;
	connection->last_activity = now;
	if (tcp_sequence_before(connection->send_unacknowledged, acknowledgment)) {
		connection->send_unacknowledged = acknowledgment;
		connection->retries = 0;
	}

	data += overlap;
	data_length -= overlap;
	bool acknowledge_data = data_length != 0 || fin;
	http_header_result_t headers = HTTP_HEADERS_PENDING;
	if (!connection->peer_fin) {
		connection->receive_next += data_length + fin;
		connection->peer_fin = fin;
		if (connection->state == TCP_ESTABLISHED) {
			headers = receive_http_headers(*connection, data, data_length);
		}
	}

	if (connection->state == TCP_ESTABLISHED && (headers != HTTP_HEADERS_PENDING || connection->peer_fin)) {
		if (headers == HTTP_HEADERS_COMPLETE) {
			unsigned length = handle_http_request(connection->request_line, connection->response, sizeof(connection->response));
			if (length <= sizeof(connection->response)) {
				connection->response_length = length;
			}
		} else if (headers != HTTP_HEADERS_PENDING) {
			static constexpr char uri_error[] = "HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
			static constexpr char header_error[] = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
			char const *response = headers == HTTP_URI_TOO_LONG ? uri_error : header_error;
			connection->response_length = strlen(response);
			memcpy(connection->response, response, connection->response_length);
		}
		connection->state = TCP_FIN_SENT;
		connection->send_next += connection->response_length + 1;
		send_pending_tcp_segment(*connection, now);
		return;
	}
	if (acknowledge_data) {
		send_tcp_ack(*connection);
	}
	if (connection->state == TCP_FIN_SENT && connection->peer_fin && connection->send_unacknowledged == connection->send_next) {
		connection->state = TCP_TIME_WAIT;
	}
}

static void process_tcp_timers()
{
	uint32_t now = milliseconds();
	unsigned retransmits = 0;
	for (auto &connection : ip_stack_globals.tcp_connections) {
		if (connection.state == TCP_CLOSED) {
			continue;
		}
		uint32_t idle_limit = connection.state == TCP_TIME_WAIT ? TCP_TIME_WAIT_MS : TCP_IDLE_MS;
		if (http_request_expired(connection, now) || now - connection.last_activity >= idle_limit) {
			connection.state = TCP_CLOSED;
			continue;
		}
		if (connection.send_unacknowledged != connection.send_next && now - connection.last_send >= TCP_RETRY_MS) {
			if (connection.retries == 4) {
				connection.state = TCP_CLOSED;
				continue;
			}
			if (retransmits < 2) {
				++connection.retries;
				++retransmits;
				send_pending_tcp_segment(connection, now);
			}
		}
	}
}

static void on_udp_packet(struct ip_frame_t const *ip, uint8_t const *segment, size_t length, bool local_unicast)
{
	if (length < sizeof(udp_frame_t)) {
		return;
	}
	auto const *udp = reinterpret_cast<udp_frame_t const *>(segment);
	uint16_t len = read_s(&udp->length);
	if (len < sizeof(*udp) || len > length || (udp->checksum != 0 && transport_checksum(ip, udp, len) != 0)) {
		return;
	}
	uint16_t src_port = read_s(&udp->src_port);
	uint16_t dst_port = read_s(&udp->dst_port);
	uint8_t const *payload = segment + sizeof(*udp);
	uint16_t payload_length = len - sizeof(*udp);
	if (dst_port == 68) {
		if (src_port == 67) {
			on_dhcp_reply(ip->dst, payload, payload_length);
		}
		return;
	}
	if (!local_unicast) {
		return;
	}

	auto const &query = ip_stack_globals.dns_query;
	if (src_port == 53) {
		if (query.pending && dst_port == query.port && ip->src == query.server_address && ip->dst == query.local_address && monotonic_ms() < query.next_action_ms) {
			on_dns_reply(payload, payload_length);
		}
		return;
	}

	auto &reply = ip_stack_globals.ntp_reply;
	if (src_port == 123 && reply.port != 0 && dst_port == reply.port && !reply.received && payload_length >= NTP_PACKET_SIZE && memcmp(&ip->src, reply.server, sizeof(reply.server)) == 0 && memcmp(payload + 24, reply.timestamp, sizeof(reply.timestamp)) == 0) {
		memcpy(reply.data, payload, sizeof(reply.data));
		reply.received = true;
	}
}

void eth_on_ip_packet(uint8_t *buf, int len, bool broadcast)
{
	int ip_length = len - (int)sizeof(struct ethernet_frame_t);
	if (ip_length < (int)sizeof(struct ip_frame_t)) {
		return;
	}
	auto const *eth = reinterpret_cast<ethernet_frame_t const *>(buf);
	auto const *ip = reinterpret_cast<ip_frame_t const *>(buf + sizeof(*eth));
	int header_length = (ip->version_and_length & 0x0f) * 4;
	int total_length = read_s(&ip->total_length);
	if ((ip->version_and_length >> 4) != 4 || header_length < (int)sizeof(*ip) || total_length < header_length || total_length > ip_length || (read_s(&ip->flags_and_fragment_offset) & 0xbfff) != 0 || compute_sum(0, ip, header_length) != 0xffff) {
		return;
	}

	uint8_t const *payload = reinterpret_cast<uint8_t const *>(ip) + header_length;
	unsigned payload_length = total_length - header_length;
	bool local_unicast = !broadcast && ip->dst != 0 && ip->dst != UINT32_MAX && ip->dst == get_ip_address();
	if (ip->protocol == 17) { // UDP, including DHCP before the local address is configured.
		on_udp_packet(ip, payload, payload_length, local_unicast);
	} else if (local_unicast && ip->protocol == 6) { // TCP
		on_tcp_packet(eth, ip, payload, payload_length);
	} else if (local_unicast && ip->protocol == 1) { // ICMP
		on_icmp_packet(eth, ip, payload, payload_length);
	}
}

void eth_on_arp_packet(uint8_t *buf, int len, bool broadcast)
{
	struct frame_t {
		struct ethernet_frame_t eth;
		struct arp_frame_t arp;
	} __attribute__((packed)) * frame;

	if (len < (int)sizeof(struct frame_t)) {
		return;
	}

	if (!is_valid_ip_address()) {
		return;
	}

	frame = (struct frame_t *)buf;
	if (read_s(&frame->arp.hardware_type) != 1 || read_s(&frame->arp.protocol_type) != 0x0800 || frame->arp.hardware != 6 || frame->arp.protocol != 4 || memcmp(frame->eth.src, frame->arp.sender_mac_addr, 6) != 0) {
		return;
	}

	int opcode = ntohs(frame->arp.opode);

	if (opcode == 1 && memcmp(&frame->arp.target_ip_addr, ip_stack_globals.ipv4_addr, 4) == 0) {
		send_arp_response(&frame->arp);
		return;
	}

	if (broadcast || opcode != 2 || frame->arp.sender_ip_addr == 0 || frame->arp.sender_ip_addr == UINT32_MAX || frame->arp.target_ip_addr != get_ip_address() || memcmp(frame->arp.target_mac_addr, ip_stack_globals.mac_addr, 6) != 0) {
		return;
	}

	uint8_t sender[4];
	memcpy(sender, &frame->arp.sender_ip_addr, sizeof(sender));
	int index = find_mac_from_arp_cache(sender);
	if (index < 0) {
		uint64_t now = monotonic_ms();
		index = ARP_CACHE_SIZE - 1;
		for (int i = 0; i < ARP_CACHE_SIZE - 1; ++i) {
			if (ip_stack_globals.arp_cache[i].expires_at_ms <= now) {
				index = i;
				break;
			}
		}
	}
	auto &entry = ip_stack_globals.arp_cache[index];
	memcpy(entry.ipv4, sender, sizeof(entry.ipv4));
	memcpy(entry.mac, frame->arp.sender_mac_addr, sizeof(entry.mac));
	entry.expires_at_ms = monotonic_ms() + 60000;
	arp_cache_move_to_front(index);
}

static void controller_failed()
{
	ip_stack_globals.controller_ready = false;
	ip_stack_globals.link_up = false;
	ip_stack_globals.next_link_check_ms = monotonic_ms() + NETWORK_RETRY_MS;
	drop_network_configuration();
}

static void poll_link(uint64_t now)
{
	if (now < ip_stack_globals.next_link_check_ms) {
		return;
	}
	if (!ip_stack_globals.controller_ready) {
		if (!eth_init(ip_stack_globals.mac_addr)) {
			ip_stack_globals.next_link_check_ms = monotonic_ms() + NETWORK_RETRY_MS;
			return;
		}
		ip_stack_globals.controller_ready = true;
	}
	int status = eth_link_status();
	if (status < 0) {
		controller_failed();
		return;
	}
	ip_stack_globals.next_link_check_ms = monotonic_ms() + 250;
	if (ip_stack_globals.link_up && status == 0) {
		drop_network_configuration();
	}
	ip_stack_globals.link_up = status != 0;
}

void ip_stack_process()
{
	poll_link(monotonic_ms());
	if (!ip_stack_globals.link_up) {
		return;
	}
	poll_dhcp(monotonic_ms());

	uint8_t tmp[MAX_FRAME_SIZE];
	uint64_t receive_deadline = time_us_64() + 3000;
	for (unsigned count = 0; count < 8 && time_us_64() < receive_deadline; ++count) {
		int len = eth_recv_packet(tmp, sizeof(tmp));
		if (len < 0) {
			controller_failed();
			return;
		}
		if (len == 0) {
			break;
		}
		auto const &lease = ip_stack_globals.lease;
		if (lease.expires_at_ms != 0 && monotonic_ms() >= lease.expires_at_ms) {
			drop_network_configuration();
			break;
		}
		if (len < (int)sizeof(struct ethernet_frame_t) || len > MAX_FRAME_SIZE) {
			continue;
		}
		bool broadcast = false;
		auto const *eth = reinterpret_cast<ethernet_frame_t const *>(tmp);
		if (memcmp(eth->dst, "\xff\xff\xff\xff\xff\xff", 6) == 0) {
			broadcast = true;
		} else if (memcmp(eth->dst, ip_stack_globals.mac_addr, 6) != 0) {
			continue;
		}
		uint16_t type = ntohs(eth->type);
		if (type == 0x0800) { // IPv4
			eth_on_ip_packet(tmp, len, broadcast);
			continue;
		}
		if (type == 0x0806) { // ARP
			eth_on_arp_packet(tmp, len, broadcast);
			continue;
		}
	}
	process_tcp_timers();
}

void ip_config(uint8_t const *ipv4, uint8_t const *mask, uint8_t const *gateway, uint8_t const *dns)
{
	if (memcmp(ip_stack_globals.ipv4_addr, ipv4, 4) != 0 || memcmp(ip_stack_globals.subnet_mask, mask, 4) != 0 || memcmp(ip_stack_globals.gateway_addr, gateway, 4) != 0 || memcmp(ip_stack_globals.dns_addr, dns, 4) != 0) {
		clear_network_sessions();
	}
	memcpy(ip_stack_globals.ipv4_addr, ipv4, 4);
	memcpy(ip_stack_globals.subnet_mask, mask, 4);
	memcpy(ip_stack_globals.gateway_addr, gateway, 4);
	memcpy(ip_stack_globals.dns_addr, dns, 4);
}

bool ip_link_up()
{
	return ip_stack_globals.link_up;
}

uint32_t ip_network_generation()
{
	return network_generation;
}

void ip_get_address(uint8_t *ipv4)
{
	memcpy(ipv4, ip_stack_globals.ipv4_addr, 4);
}

static bool encode_dns_name(char const *text, dns_name_t &name)
{
	size_t size = 0;
	while (*text != '\0') {
		size_t label_length = strcspn(text, ".");
		if (label_length == 0 || label_length > 63 || size + label_length + 2 > sizeof(name.wire)) {
			return false;
		}
		name.wire[size++] = label_length;
		for (size_t i = 0; i < label_length; ++i) {
			uint8_t byte = text[i];
			if (byte <= ' ' || byte >= 127 || byte == '/') {
				return false;
			}
			name.wire[size++] = dns_lowercase(byte);
		}
		text += label_length;
		if (*text == '.') {
			++text;
		}
	}
	name.wire[size++] = 0;
	name.length = size;
	return size > 1;
}

static void cache_dns_answer(dns_query_t const &query)
{
	if (query.ttl_seconds == 0 || query.ttl_seconds > INT32_MAX) {
		return;
	}
	auto *entry = &ip_stack_globals.dns_cache[0];
	for (auto &candidate : ip_stack_globals.dns_cache) {
		if (candidate.expires_at_ms < entry->expires_at_ms) {
			entry = &candidate;
		}
	}
	entry->name = query.name;
	memcpy(entry->ipv4, query.ipv4, sizeof(entry->ipv4));
	entry->expires_at_ms = time_us_64() / 1000 + (uint64_t)query.ttl_seconds * 1000;
}

static void send_dns_query(dns_query_t &query)
{
	struct dns_request_frame_t {
		eth_ip_udp_frame_t header;
		dns_frame_t dns;
		uint8_t question[sizeof(dns_name_t::wire) + 4];
	} __attribute__((packed)) frame = { };

	uint32_t random = get_rand_32();
	query.id = random >> 16;
	query.port = 49152 + (random & 0x3fff);
	write_s(&frame.dns.transaction_id, query.id);
	write_s(&frame.dns.flags, 0x0100); // Recursion desired.
	write_s(&frame.dns.questions, 1);
	memcpy(frame.question, query.name.wire, query.name.length);
	uint8_t *end = frame.question + query.name.length;
	write_s(end, 1); // A
	write_s(end + 2, 1); // IN
	end += 4;
	auto *packet = reinterpret_cast<uint8_t *>(&frame);
	prepare_udp_packet(&frame.header, ip_stack_globals.dns_addr, 53, query.port, end);
	query.pending = send_ip_packet(packet, end - packet);
	query.next_action_ms = monotonic_ms() + (query.pending ? DNS_REPLY_TIMEOUT_MS : NETWORK_RETRY_MS);
}

static bool parse_ipv4_address(char const *text, uint8_t *ipv4)
{
	uint8_t address[4];
	for (unsigned i = 0; i < sizeof(address); ++i) {
		if (!isdigit((unsigned char)*text) || (*text == '0' && isdigit((unsigned char)text[1]))) {
			return false;
		}
		unsigned value = 0;
		do {
			value = value * 10 + (*text++ - '0');
			if (value > 255) {
				return false;
			}
		} while (isdigit((unsigned char)*text));
		address[i] = value;
		if (i + 1 < sizeof(address) && *text++ != '.') {
			return false;
		}
	}
	if (*text != '\0') {
		return false;
	}
	memcpy(ipv4, address, sizeof(address));
	return true;
}

bool ip_resolve_name(char const *name, uint8_t *ipv4)
{
	if (!name || !ipv4) {
		return false;
	}
	if (strchr(name, '.') && name[strspn(name, "0123456789.")] == '\0') {
		return parse_ipv4_address(name, ipv4);
	}
	dns_name_t encoded = { };
	if (!ip_stack_globals.link_up || !is_valid_ip_address() || !encode_dns_name(name, encoded)) {
		return false;
	}
	uint64_t now = time_us_64() / 1000;
	for (auto const &entry : ip_stack_globals.dns_cache) {
		if (entry.expires_at_ms > now && dns_names_equal(encoded, entry.name)) {
			memcpy(ipv4, entry.ipv4, sizeof(entry.ipv4));
			return true;
		}
	}
	auto &query = ip_stack_globals.dns_query;
	if (!dns_names_equal(query.name, encoded)) {
		query = { };
		query.name = encoded;
		query.local_address = get_ip_address();
		memcpy(&query.server_address, ip_stack_globals.dns_addr, 4);
	}
	if (query.answered) {
		cache_dns_answer(query);
		memcpy(ipv4, query.ipv4, sizeof(query.ipv4));
		query = { };
		return true;
	}
	if (now >= query.next_action_ms) {
		send_dns_query(query);
	}
	return false;
}
