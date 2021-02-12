
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "pico/binary_info.h"
#include "lcd.h"

// commands
const int LCD_CLEARDISPLAY = 0x01;
const int LCD_RETURNHOME = 0x02;
const int LCD_ENTRYMODESET = 0x04;
const int LCD_DISPLAYCONTROL = 0x08;
const int LCD_CURSORSHIFT = 0x10;
const int LCD_FUNCTIONSET = 0x20;
const int LCD_SETCGRAMADDR = 0x40;
const int LCD_SETDDRAMADDR = 0x80;

// flags for display entry mode
const int LCD_ENTRYSHIFTINCREMENT = 0x01;
const int LCD_ENTRYLEFT = 0x02;

// flags for display and cursor control
const int LCD_BLINKON = 0x01;
const int LCD_CURSORON = 0x02;
const int LCD_DISPLAYON = 0x04;

// flags for display and cursor shift
const int LCD_MOVERIGHT = 0x04;
const int LCD_DISPLAYMOVE = 0x08;

// flags for function set
const int LCD_5x10DOTS = 0x04;
const int LCD_2LINE = 0x08;
const int LCD_8BITMODE = 0x10;

// flag for backlight control
const int LCD_BACKLIGHT = 0x08;

const int LCD_ENABLE_BIT = 0x04;

#define I2C_PORT i2c0
#define I2C_SDA 16
#define I2C_SCL 17

// By default these LCD display drivers are on bus address 0x27
static int addr = 0x27;

// Modes for lcd_send_byte
#define LCD_CHARACTER  1
#define LCD_COMMAND    0

#define MAX_LINES      2
#define MAX_CHARS      16

/* Quick helper function for single byte transfers */
void i2c_write_byte(uint8_t val)
{
	i2c_write_blocking(I2C_PORT, addr, &val, 1, false);
}

void lcd_toggle_enable(uint8_t val)
{
	// Toggle enable pin on LCD display
	// We cannot do this too quickly or things don't work
#define DELAY_US 600
	sleep_us(DELAY_US);
	i2c_write_byte(val | LCD_ENABLE_BIT);
	sleep_us(DELAY_US);
	i2c_write_byte(val & ~LCD_ENABLE_BIT);
	sleep_us(DELAY_US);
}

// The display is sent a byte as two separate nibble transfers
void lcd_send_byte(uint8_t val, int mode)
{
	uint8_t high = mode | (val & 0xF0) | LCD_BACKLIGHT;
	uint8_t low = mode | ((val << 4) & 0xF0) | LCD_BACKLIGHT;

	i2c_write_byte(high);
	lcd_toggle_enable(high);
	i2c_write_byte(low);
	lcd_toggle_enable(low);
}

void lcd_clear()
{
	lcd_send_byte(LCD_CLEARDISPLAY, LCD_COMMAND);
	sleep_us(500);
}

// go to location on LCD
void lcd_set_cursor(int line, int position)
{
	int val = (line == 0) ? 0x80 + position : 0xC0 + position;
	lcd_send_byte(val, LCD_COMMAND);
}

void lcd_char(char val)
{
	lcd_send_byte(val, LCD_CHARACTER);
}

void lcd_print(const char *s)
{
	while (*s) {
		lcd_char(*s++);
	}
}

void lcd_init()
{
	i2c_init(I2C_PORT, 100 * 1000);
	gpio_set_function(I2C_SDA, GPIO_FUNC_I2C);
	gpio_set_function(I2C_SCL, GPIO_FUNC_I2C);
	gpio_pull_up(I2C_SDA);
	gpio_pull_up(I2C_SCL);
	bi_decl(bi_2pins_with_func(I2C_SDA, I2C_SCL, GPIO_FUNC_I2C));

	lcd_send_byte(0x03, LCD_COMMAND);
	lcd_send_byte(0x03, LCD_COMMAND);
	lcd_send_byte(0x03, LCD_COMMAND);
	lcd_send_byte(0x02, LCD_COMMAND);

	lcd_send_byte(LCD_ENTRYMODESET | LCD_ENTRYLEFT, LCD_COMMAND);
	lcd_send_byte(LCD_FUNCTIONSET | LCD_2LINE, LCD_COMMAND);
	lcd_send_byte(LCD_DISPLAYCONTROL | LCD_DISPLAYON, LCD_COMMAND);
	lcd_clear();
}

void lcd_print_number(unsigned int v, int n)
{
	int i;
	char tmp[20];
	char *p = tmp + sizeof(tmp);
	*--p = 0;
	for (i = 0; i < n; i++) {
		*--p = v % 10 + '0';
		v /= 10;
	}
	lcd_print(p);
}




