/*
 * domain.h
 * Copyright (C) 2015, basil
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __DOMAIN_H
#define __DOMAIN_H

#include <stdint.h>

#define ADDR_BASE               0x2C000000      // 44.0.0.0/24 (AMPRNet)
#define ADDR_MAX                0x2CFFFFFF

static inline bool is_fake_addr(uint32_t addr)
{
    return addr >= ADDR_BASE && addr <= ADDR_MAX;
}

struct name
{
    LONG ref_count;
    uint8_t msb;
    char name[];
} __attribute__((__packed__));

extern void domain_init(void);
extern uint32_t domain_lookup_addr(const char *name);
extern struct name *domain_lookup_name(uint32_t addr);
extern void domain_deref(struct name *name);
extern void domain_cleanup(size_t count);

#endif
