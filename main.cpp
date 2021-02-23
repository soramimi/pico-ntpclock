/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pico/stdlib.h"
#include "hardware/spi.h"

extern "C" {
#include "lcd.h"
#include "ip.h"
}

#define TIMEZONE (9 * 60 * 60)
#define NTP_SERVER "ntp.nict.jp"

#define LED_PIN 25
void toggle_led()
{
	static int n = 0;
	n++;
	gpio_put(LED_PIN, n & 1);
}

void giveup(char const *msg)
{
	lcd_clear();
	lcd_set_cursor(0, 0);
	lcd_print(msg);
	while (1) {
		gpio_put(LED_PIN, 1);
		sleep_ms(250);
		gpio_put(LED_PIN, 0);
		sleep_ms(250);
	}
}

// NTP

#define NTP_PACKET_SIZE 48

void send_ntp_request(uint8_t const *ntp_server_addr)
{
	uint8_t data[NTP_PACKET_SIZE];
	memset(data, 0, sizeof(data));
	data[0] = 0xdb;
	send_udp_packet(ntp_server_addr, 123, 1024, data, sizeof(data));
}

bool parse_ntp_packet(struct packet_header_t *packet, uint32_t *p_s, uint16_t *p_ms)
{
	if (!packet) {
		return false;
	}
	if (packet->src_port != 123 && packet->dst_port != 123) {
		return false;
	}
	if (packet->length < NTP_PACKET_SIZE) {
		return false;
	}
	unsigned long s = (((unsigned long)packet->data[0x28] << 24) | ((unsigned long)packet->data[0x29] << 16) | ((unsigned long)packet->data[0x2a] << 8) | (unsigned long)packet->data[0x2b]);
	unsigned long ms = (((unsigned long)packet->data[0x2c] << 24) | ((unsigned long)packet->data[0x2d] << 16) | ((unsigned long)packet->data[0x2e] << 8) | (unsigned long)packet->data[0x2f]);
	ms >>= 16;
	ms = (ms * 1000 + 32768) >> 16;
	*p_s = s;
	*p_ms = (int)ms;
	return true;
}

//

void convert_cjd_to_ymd(unsigned long j, int *year, int *month, int *day)
{
	int y, m, d;
	y = (j * 4 + 128179) / 146097;
	d = (j * 4 - y * 146097 + 128179) / 4 * 4 + 3;
	j = d / 1461;
	d = (d - j * 1461) / 4 * 5 + 2;
	m = d / 153;
	d = (d - m * 153) / 5 + 1;
	y = (y - 48) * 100 + j;
	if (m < 10) {
		m += 3;
	} else {
		m -= 9;
		y++;
	}
	*year = y;
	*month = m;
	*day = d;
}

struct Result {
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	int weekday;
};

void display_date_time(struct Result const *r)
{
	lcd_set_cursor(0, 0);
	lcd_print_number(r->month, 2);
	lcd_char('/');
	lcd_print_number(r->day, 2);
	{
		char const *p = "sunmontuewedthufrisat" + r->weekday % 7 * 3;
		lcd_char(p[0]);
		lcd_char(p[1]);
//		lcd_char(p[2]);
	}
	lcd_char(' ');
	lcd_print_number(r->hour, 2);
	lcd_char(':');
	lcd_print_number(r->minute, 2);
	lcd_char(':');
	lcd_print_number(r->second, 2);
}

//

uint64_t milliseconds_diff = 0;

void set_time(uint32_t s, uint16_t ms)
{
	uint64_t m = (uint64_t)s * 1000 + ms;
	uint64_t t = to_us_since_boot(get_absolute_time()) / 1000;
	milliseconds_diff = m - t;
}

uint32_t get_time()
{
	uint64_t m = to_us_since_boot(get_absolute_time()) / 1000 + milliseconds_diff;
	return m / 1000;
}

//

extern "C" int main()
{
	uint32_t now = 0;
	bool valid_time = false;
	bool adjust_time = false;

	gpio_init(LED_PIN);
	gpio_set_dir(LED_PIN, GPIO_OUT);

	// start LCD

	lcd_init();

	lcd_clear();
	lcd_set_cursor(0, 0);

	static const uint8_t macaddr[] = {
		0xfe, 0xff, 0xff, 0x00, 0x00, 0xf0
	};

	// start networking

	uint8_t ntp_server_addr[4];

	ip_stack_init(macaddr);

#if 0
	{
		uint8_t ip_address[] = {
			192, 168, 0, 100
		};
		uint8_t subnet_mask[] = {
			255, 255, 255, 0
		};
		uint8_t gateway_addr[] = {
			192, 168, 0, 1
		};
		uint8_t dns_server[] = {
			192, 168, 0, 1
		};
		ip_config(ip_address, subnet_mask, gateway_addr, dns_server);
	}
#else
	if (!ip_config_with_dhcp()) {
		giveup("DHCP error");
	}
#endif

	if (!gethostbyname(NTP_SERVER, ntp_server_addr)) {
		giveup("Resolve error");
	}

	{
		uint8_t ipv4[4];
		ip_get_address(ipv4);
		char tmp[100];
		sprintf(tmp, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
		lcd_set_cursor(1, 0);
		lcd_print(tmp);
	}

	//

	adjust_time = true;

	while (1) {
		if (adjust_time) {
			send_ntp_request(ntp_server_addr);
			adjust_time = false;
		}

		ip_stack_process();

		struct packet_header_t *packet = take_udp_packet();
		if (packet) {
			uint32_t s;
			uint16_t ms;
			if (parse_ntp_packet(packet, &s, &ms)) {
				set_time(s, ms);
				valid_time = true;
			}
			free(packet);
		}

		if (valid_time) {
			unsigned long t = get_time();
			if (now < t) {
				now = t;
				t += TIMEZONE;
				unsigned long cjd = t / (24 * 60 * 60) + 2415021;
				struct Result r;
				r.hour = t / 3600 % 24;
				r.minute = t / 60 % 60;
				r.second = t % 60;
				r.weekday = (cjd + 1) % 7;
				convert_cjd_to_ymd(cjd, &r.year, &r.month, &r.day);

				display_date_time(&r);

				if (r.minute % 30 == 29 && r.second == 30) {
					adjust_time = true;
				}
			}
		}
	}

	return 0;
}

