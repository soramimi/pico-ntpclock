#ifndef LCD_H
#define LCD_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void lcd_init();
bool lcd_ready(void);
void lcd_clear();
void lcd_set_cursor(int line, int position);
void lcd_char(char val);
void lcd_print(const char *s);
void lcd_print_number(unsigned int v, int n);

#ifdef __cplusplus
}
#endif

#endif // LCD_H
