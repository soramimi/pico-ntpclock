/**
 * Copyright (C) 2021 S.Fuchita (@soramimi_jp)
 * MIT License
 */

#ifndef ENC28J60IO_H
#define ENC28J60IO_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t milliseconds();
void enc28j60_cs(bool f);
int enc28j60_io(uint8_t c);

#ifdef __cplusplus
}
#endif

#endif // ENC28J60IO_H
