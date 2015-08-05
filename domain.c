/*
 * domain.c
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "domain.h"
#include "main.h"

#define RATE_LIMIT                  8000

#define rand16()                    \
    (rand() & 0xFF) | ((rand() & 0xFF) << 8)

// Domain blacklist:
struct blacklist
{
    size_t size;
    size_t len;
    char **names;
};
static struct blacklist *blacklist = NULL;

// State:
static struct name *names[UINT16_MAX] = {NULL};
static uint8_t sbox[UINT8_MAX] = {0};
static uint8_t sbox1[UINT8_MAX] = {0};
static uint16_t key[4] = {0};
static LONGLONG counter = 0;
static LONGLONG counter_0 = 0;
static LONGLONG counter_1 = 0;
static LONGLONG rate = 0;

static HANDLE names_lock = NULL;

// Prototypes:
static uint16_t domain_encrypt(uint16_t count);
static void domain_ref(struct name *name);
static struct blacklist *domain_blacklist_read(void);
static bool domain_blacklist_lookup(struct blacklist *blacklist,
    const char *name);
static int __cdecl domain_blacklist_compare_0(const void *x, const void *y);
static int domain_blacklist_compare(const char *name0, size_t len,
    const char *name1);

// "Encrypt" the count to give the IPs a random look-and-feel.  Not security
// critical.
static uint16_t domain_encrypt(uint16_t count) 
{
    for (size_t i = 0; i < sizeof(key) / sizeof(uint16_t); i++)
    {
        count = (count << 3) | (count >> 13);           // Mix
        count ^= key[i];                                // Round-key
        count = (uint16_t)sbox[count & 0xFF] |          // S-Box
                ((uint16_t)sbox[count >> 8] << 8);
    }
    return count;
}

// Initialize this module:
extern void domain_init(void)
{
    // Load the domain blacklist.
    blacklist = domain_blacklist_read();

    // Init S-BOXes:
    for (size_t i = 1; i <= UINT8_MAX; i++)
    {
        uint8_t idx = (uint8_t)rand16();
        while (sbox[idx] != 0)
            idx += 23;
        sbox[idx] = (uint8_t)i;
        if (i % 16 == 0)
            srand(random());
    }
    srand(random());
    for (size_t i = 1; i <= UINT8_MAX; i++)
    {
        uint8_t idx = (uint8_t)rand16();
        while (sbox1[idx] != 0)
            idx += 23;
        sbox1[idx] = (uint8_t)i;
    }

    // Init the key sched.
    for (size_t i = 0; i < sizeof(key) / sizeof(uint16_t); i++)
        key[i] = (uint16_t)random();

    counter = rand16();
    counter <<= 8;
    counter |= (LONGLONG)rand16();
    counter_1 = counter_0 = counter;
    names_lock = create_lock();
}

// Lookup an address given a domain name.  If the name does not exist then
// create one.
extern uint32_t domain_lookup_addr(const char *name0)
{
    if (name0[0] == '.')
        name0++;

    if (domain_blacklist_lookup(blacklist, name0))
    {
        debug("Block %s\n", name0);
        return 0;       // Blocked!
    }

    if (InterlockedIncrement64(&rate) >= RATE_LIMIT)
    {
        debug("Block (rate limit)\n");
        return 0;
    }

    uint64_t idx0 = (uint64_t)InterlockedIncrement64(&counter);
    uint16_t idx = domain_encrypt((uint16_t)idx0);
    uint8_t msb = sbox1[(idx0 >> 16) & 0xFF];
    uint32_t addr = ADDR_BASE | ((uint32_t)msb << 16) | (uint32_t)idx;

    if (names[idx] != NULL)
    {
        // Name table is full!
        debug("Block %s (name entry is full)\n", name0);
        return 0;
    }

    size_t len = strlen(name0);
    size_t size = sizeof(struct name) + (len + 1) * sizeof(char);
    struct name *name = (struct name *)malloc(size);
    if (name == NULL)
    {
        warning("failed to allocate %u bytes for domain name", size);
        exit(EXIT_FAILURE);
    }

    name->ref_count = 1;
    name->msb = msb;
    memcpy(name->name, name0, len+1);
    
    names[idx] = name;

    return addr;
}

// Lookup a name based on the address.
extern struct name *domain_lookup_name(uint32_t addr)
{
    if (!is_fake_addr(addr))
        return NULL;
    uint8_t msb = (uint8_t)(addr >> 16);
    uint16_t idx = (uint16_t)addr;
    lock(names_lock);
    struct name *name = names[idx];
    if (name == NULL || name->msb != msb)
    {
        unlock(names_lock);
        return NULL;
    }
    domain_ref(name);
    unlock(names_lock);
    return name;
}

// Reference counting:
static void domain_ref(struct name *name)
{
    if (name == NULL)
        return;
    name->ref_count++;
}
extern void domain_deref(struct name *name)
{
    if (name == NULL)
        return;
    LONG old = InterlockedDecrement(&name->ref_count);
    if (old == 0)
        free(name);
}

// Cleanup old names.
extern void domain_cleanup(size_t count)
{
    InterlockedExchange64(&rate, 0);

    if (count % 16 != 0)
        return;

    LONGLONG start = counter_1, end = counter_0;

    counter_1 = counter_0;
    counter_0 = counter;

    for (; start < end; start++)
    {
        uint16_t idx = (uint16_t)start;
        idx = domain_encrypt(idx);

        lock(names_lock);
        struct name *old_name = names[idx];
        names[idx] = NULL;
        unlock(names_lock);

        if (old_name != NULL)
            debug("Cleanup name %s\n", old_name->name);
        domain_deref(old_name);
    }
}

// Read the blacklist file:
static struct blacklist *domain_blacklist_read(void)
{
    struct blacklist *blacklist =
        (struct blacklist *)malloc(sizeof(struct blacklist));
    if (blacklist == NULL)
    {
        warning("failed to allocate %u bytes for domain blacklist",
            sizeof(struct blacklist));
        exit(EXIT_FAILURE);
    }
    blacklist->size = 0;
    blacklist->len = 0;
    blacklist->names = NULL;

    const char *filename = "hosts.deny";
    FILE *stream = fopen(filename, "r");
    if (stream == NULL)
    {
        warning("failed to open \"%s\" for reading", filename);
        return blacklist;
    }

    // Read blocked domains:
    int c;
    char buf[256];
    while (true)
    {
        while (isspace(c = getc(stream)))
            ;
        if (c == EOF)
            break;
        if (c == '#')
        {
            while ((c = getc(stream)) != '\n' && c != EOF)
                ;
            continue;
        }
        size_t i = 0;
        while (i < sizeof(buf)-1 && (c == '-' || c == '.' || isalnum(c)))
        {
            buf[i++] = c;
            c = getc(stream);
        }
        if (i >= sizeof(buf)-1 || !isspace(c))
        {
            warning("failed to parse domain blacklist from the \"%s\" file",
                filename);
            exit(EXIT_FAILURE);
        }
        buf[i] = '\0';
        if (blacklist->len >= blacklist->size)
        {
            blacklist->size = (blacklist->size == 0? 32: 2 * blacklist->size);
            blacklist->names = (char **)realloc(blacklist->names,
                blacklist->size * sizeof(char *));
            if (blacklist->names == NULL)
            {
                warning("failed to (re)allocate %u bytes for domain blacklist",
                    blacklist->size * sizeof(char *));
                exit(EXIT_FAILURE);
            }
        }
        size_t size = (i+1) * sizeof(char);
        char *name = (char *)malloc(size);
        if (name == NULL)
        {
            warning("failed to allocate %u bytes for domain blacklist entry",
                size);
            exit(EXIT_FAILURE);
        }
        for (size_t j = 0; j < i; j++)
            name[j] = buf[i - 1 - j];
        name[i] = '\0';
        blacklist->names[blacklist->len++] = name;
    }

    fclose(stream);

    qsort(blacklist->names, blacklist->len, sizeof(char *),
        domain_blacklist_compare_0);
    return blacklist;
}

// Check if a domain matches the blacklist or not:
static bool domain_blacklist_lookup(struct blacklist *blacklist,
    const char *name)
{
    if (blacklist->len == 0)
        return false;

    size_t len = strlen(name);
    ssize_t lo = 0, hi = blacklist->len-1;
    while (lo <= hi)
    {
        ssize_t mid = (lo + hi) / 2;
        int cmp = domain_blacklist_compare(name, len, blacklist->names[mid]);
        if (cmp > 0)
            hi = mid-1;
        else if (cmp < 0)
            lo = mid+1;
        else
            return true;
    }
    return false;
}

// Domain compare function(s):
static int __cdecl domain_blacklist_compare_0(const void *x, const void *y)
{
    const char *name0 = *(const char **)x;
    const char *name1 = *(const char **)y;
    return strcmp(name0, name1);
}
static int domain_blacklist_compare(const char *name0, size_t len,
    const char *name1)
{
    size_t i = 0;
    ssize_t j = (ssize_t)len - 1;
    for (; j >= 0 && name1[i] != '\0'; i++, j--)
    {
        int cmp = (int)name1[i] - (int)name0[j];
        if (cmp != 0)
            return cmp;
    }
    if (j < 0 && name1[i] != '\0')
        return 1;
    return 0;
}

