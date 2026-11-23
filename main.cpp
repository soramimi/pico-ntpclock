/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#include <algorithm>
#include <array>
#include <stdio.h>
#include <string.h>

#include "hardware/spi.h"
#include "pico/rand.h"
#include "pico/stdlib.h"

extern "C" {
#include "ip.h"
#include "lcd.h"
}

#define TIMEZONE (9 * 60 * 60)
#define NTP_SERVER "ntp.nict.jp"

#define INPUT_PIN 26

#define LED_PIN 25
void toggle_led()
{
	static int n = 0;
	n++;
	gpio_put(LED_PIN, n & 1);
}

// NTP

static constexpr uint16_t NTP_PORT = 123;
static constexpr uint32_t NTP_REPLY_TIMEOUT_MS = 5000;
static constexpr uint64_t NTP_MIN_RETRY_MS = 256000;
static constexpr uint64_t NTP_RESYNC_MS = 30 * 60 * 1000;
static constexpr int NTP_MAX_POLL = 13;

static struct NtpRequest {
	uint64_t reply_deadline_ms;
	uint64_t next_attempt_ms;
	uint32_t generation;
	int poll = 8;
	bool pending;
	bool fast_retry_used;
} ntp_request;

static void send_ntp_request(uint8_t const *server)
{
	uint8_t data[NTP_PACKET_SIZE] = { };
	data[0] = (4 << 3) | 3; // NTPv4, client.
	data[2] = ntp_request.poll;
	uint16_t port = 49152 + (get_rand_32() & 0x3fff);
	uint64_t timestamp = get_rand_64();
	if (timestamp == 0) {
		timestamp = 1;
	}
	for (unsigned i = 0; i < 8; ++i) {
		data[40 + i] = timestamp >> (56 - i * 8);
	}
	ntp_request.pending = send_udp_packet(server, NTP_PORT, port, data, sizeof(data));
	uint64_t now = time_us_64() / 1000;
	ntp_request.next_attempt_ms = now + (ntp_request.pending ? NTP_MIN_RETRY_MS : 1000);
	if (ntp_request.pending) {
		ip_expect_ntp_reply(server, port, data + 40);
		ntp_request.reply_deadline_ms = now + NTP_REPLY_TIMEOUT_MS;
	}
}

static uint32_t read_ntp_word(uint8_t const *data)
{
	return (uint32_t(data[0]) << 24) | (uint32_t(data[1]) << 16) | (uint32_t(data[2]) << 8) | data[3];
}

static bool parse_ntp_packet(uint8_t const *data, uint64_t now, uint32_t *p_s, uint16_t *p_ms)
{
	unsigned version = (data[0] >> 3) & 7;
	if ((data[0] & 7) != 4 || (version != 3 && version != 4)) {
		return false;
	}
	if (data[1] == 0 && memcmp(data + 12, "RATE", 4) == 0) {
		int server_poll = data[2] < 128 ? data[2] : int(data[2]) - 256;
		ntp_request.poll = std::min(NTP_MAX_POLL, std::max(ntp_request.poll + 1, server_poll));
		ntp_request.next_attempt_ms = now + (1000u << ntp_request.poll);
		ntp_request.pending = false;
		ntp_request.fast_retry_used = true;
		return false;
	}

	uint32_t seconds = read_ntp_word(data + 40);
	uint32_t fraction = read_ntp_word(data + 44);
	if ((data[0] >> 6) == 3 || data[1] == 0 || data[1] > 15 || (seconds == 0 && fraction == 0)) {
		return false;
	}
	ntp_request.pending = false;
	*p_s = seconds;
	*p_ms = ((fraction >> 16) * 1000 + 32768) >> 16;
	return true;
}

//

static void convert_cjd_to_ymd(uint64_t j, int *year, int *month, int *day)
{
	uint64_t y = (j * 4 + 128179) / 146097;
	int d = (j * 4 + 128179 - y * 146097) / 4 * 4 + 3;
	j = d / 1461;
	d = (d - j * 1461) / 4 * 5 + 2;
	int m = d / 153;
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

static Result local_date_time(uint64_t seconds)
{
	uint64_t t = seconds + TIMEZONE;
	uint64_t cjd = t / (24 * 60 * 60) + 2415021;
	Result r;
	r.hour = t / 3600 % 24;
	r.minute = t / 60 % 60;
	r.second = t % 60;
	r.weekday = (cjd + 1) % 7;
	convert_cjd_to_ymd(cjd, &r.year, &r.month, &r.day);
	return r;
}

static void display_date_time(struct Result const *r, bool stale)
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
	lcd_char(stale ? '*' : ' ');
	lcd_print_number(r->hour, 2);
	lcd_char(':');
	lcd_print_number(r->minute, 2);
	lcd_char(':');
	lcd_print_number(r->second, 2);
}

//

static constexpr uint64_t NTP_ERA_SECONDS = uint64_t { 1 } << 32;
static constexpr uint64_t CLOCK_STALE_AFTER_MS = 2 * NTP_RESYNC_MS;

enum class ClockStatus { waiting,
	synchronized,
	stale };

struct ClockReading {
	uint64_t seconds;
	ClockStatus status;
};

static struct Clock {
	uint64_t ntp_ms_at_sync;
	uint64_t last_sync_ms;
	bool has_time;
} clock_state;

static constexpr unsigned leap_days_before(unsigned year)
{
	--year;
	return year / 4 - year / 100 + year / 400;
}

static constexpr uint64_t initial_ntp_reference()
{
	// Use January 1 of the build year until the first NTP sample is available.
	constexpr char date[] = __DATE__;
	constexpr unsigned year = (date[7] - '0') * 1000 + (date[8] - '0') * 100 + (date[9] - '0') * 10 + (date[10] - '0');
	static_assert(year >= 1900, "A build year is required to decode the first NTP timestamp");
	return (365ull * (year - 1900) + leap_days_before(year) - leap_days_before(1900)) * 86400;
}

static uint64_t unfold_ntp_seconds(uint32_t seconds, uint64_t reference)
{
	// Select the era whose timestamp is nearest to the reference.
	uint64_t candidate = (reference & ~(NTP_ERA_SECONDS - 1)) + seconds;
	if (candidate < reference && reference - candidate > NTP_ERA_SECONDS / 2) {
		return candidate + NTP_ERA_SECONDS;
	}
	if (candidate > reference && candidate - reference > NTP_ERA_SECONDS / 2 && candidate >= NTP_ERA_SECONDS) {
		return candidate - NTP_ERA_SECONDS;
	}
	return candidate;
}

static ClockReading read_clock(uint64_t now_ms)
{
	if (!clock_state.has_time) {
		return { 0, ClockStatus::waiting };
	}
	uint64_t age_ms = now_ms - clock_state.last_sync_ms;
	return { (clock_state.ntp_ms_at_sync + age_ms) / 1000,
		age_ms >= CLOCK_STALE_AFTER_MS ? ClockStatus::stale : ClockStatus::synchronized };
}

static void set_time(uint32_t seconds, uint16_t fraction_ms, uint64_t now_ms)
{
	uint64_t reference = clock_state.has_time ? read_clock(now_ms).seconds : initial_ntp_reference();
	uint64_t unfolded = unfold_ntp_seconds(seconds, reference);
	clock_state = { unfolded * 1000 + fraction_ms, now_ms, true };
}

static void poll_ntp()
{
	uint64_t now = time_us_64() / 1000;
	uint32_t generation = ip_network_generation();
	if (ntp_request.generation != generation) {
		ntp_request.generation = generation;
		if (ntp_request.pending) {
			ntp_request.reply_deadline_ms = now;
		}
	}
	if (ntp_request.pending) {
		uint8_t reply[NTP_PACKET_SIZE];
		if (now >= ntp_request.reply_deadline_ms) {
			ntp_request.pending = false;
			if (!clock_state.has_time && !ntp_request.fast_retry_used) {
				ntp_request.fast_retry_used = true;
				ntp_request.next_attempt_ms = now + 1000;
			}
		} else if (ip_take_ntp_reply(reply)) {
			uint32_t seconds;
			uint16_t milliseconds;
			if (parse_ntp_packet(reply, now, &seconds, &milliseconds)) {
				set_time(seconds, milliseconds, now);
				ntp_request.next_attempt_ms = now + std::max(NTP_RESYNC_MS, uint64_t(1000u << ntp_request.poll));
			}
		}
		if (!ntp_request.pending) {
			ip_cancel_ntp_reply();
		}
	}
	uint8_t server[4];
	if (!ntp_request.pending && now >= ntp_request.next_attempt_ms && ip_resolve_name(NTP_SERVER, server)) {
		send_ntp_request(server);
	}
}

extern "C" unsigned int handle_http_request(char const *request_line, char *response, unsigned int capacity)
{
	char const *method_end = strchr(request_line, ' ');
	bool head = method_end && method_end - request_line == 4 && memcmp(request_line, "HEAD", 4) == 0;
	bool clock_path = false;
	if (method_end) {
		char const *path = method_end + 1;
		size_t path_length = strcspn(path, " ?");
		static constexpr char index_path[] = "/index.html";
		bool root = path_length == 1 && path[0] == '/';
		bool index = path_length == sizeof(index_path) - 1 && memcmp(path, index_path, path_length) == 0;
		clock_path = path[path_length] != '\0' && (root || index);
	}

	char const *status = "404 Not Found";
	char const *body = "";
	char const *clock_header = "";
	char time_text[56];
	if (clock_path) {
		ClockReading reading = read_clock(time_us_64() / 1000);
		if (reading.status != ClockStatus::waiting) {
			bool stale = reading.status == ClockStatus::stale;
			Result r = local_date_time(reading.seconds);
			snprintf(time_text, sizeof(time_text), "%04d-%02d-%02d %02d:%02d:%02d JST%s\n",
				r.year, r.month, r.day, r.hour, r.minute, r.second, stale ? " (stale)" : "");
			status = "200 OK";
			body = time_text;
			clock_header = stale ? "X-Clock-Status: stale\r\n" : "X-Clock-Status: synchronized\r\n";
		} else {
			status = "503 Service Unavailable";
			body = "Time not synchronized\n";
			clock_header = "X-Clock-Status: waiting\r\n";
		}
	}

	char const *headers = clock_path ? "Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n" : "";
	int length = snprintf(response, capacity, "HTTP/1.1 %s\r\nContent-Length: %u\r\n%s%sConnection: close\r\n\r\n%s",
		status, (unsigned)strlen(body), headers, clock_header, head ? "" : body);
	return length >= 0 && (unsigned)length < capacity ? (unsigned)length : 0;
}

static void poll_display()
{
	static uint64_t retry_at_ms = 0;
	static uint64_t last_second = 0;
	static ClockStatus last_clock_status = ClockStatus::waiting;
	static uint8_t last_address[4] = { };
	static bool last_link = false;
	uint64_t now = time_us_64() / 1000;
	bool redraw = false;
	if (!lcd_ready()) {
		if (now < retry_at_ms) {
			return;
		}
		lcd_init();
		if (!lcd_ready()) {
			retry_at_ms = now + 1000;
			return;
		}
		redraw = true;
	}

	uint8_t address[4];
	ip_get_address(address);
	bool link = ip_link_up();
	if (redraw || link != last_link || memcmp(address, last_address, sizeof(address)) != 0) {
		char line[17];
		if (address[0] || address[1] || address[2] || address[3]) {
			char ip_text[16];
			snprintf(ip_text, sizeof(ip_text), "%d.%d.%d.%d", address[0], address[1], address[2], address[3]);
			snprintf(line, sizeof(line), "%-16s", ip_text);
		} else {
			snprintf(line, sizeof(line), "%-16s", link ? "Getting address" : "Waiting for LAN");
		}
		lcd_set_cursor(1, 0);
		lcd_print(line);
		memcpy(last_address, address, sizeof(address));
		last_link = link;
	}
	ClockReading reading = read_clock(time_us_64() / 1000);
	if (redraw || reading.seconds != last_second || reading.status != last_clock_status) {
		if (reading.status == ClockStatus::waiting) {
			lcd_set_cursor(0, 0);
			lcd_print("Waiting for NTP ");
		} else {
			Result r = local_date_time(reading.seconds);
			display_date_time(&r, reading.status == ClockStatus::stale);
		}
		last_second = reading.seconds;
		last_clock_status = reading.status;
	}
	if (!lcd_ready()) {
		retry_at_ms = now + 1000;
	}
}

extern "C" int main()
{
	gpio_init(LED_PIN);
	gpio_set_dir(LED_PIN, GPIO_OUT);

	static const uint8_t macaddr[] = {
		0xfe, 0xff, 0xff, 0x00, 0x00, 0xf0
	};

	ip_stack_init(macaddr);
	while (1) {
		ip_stack_process();
		poll_ntp();
		poll_display();
	}
}
