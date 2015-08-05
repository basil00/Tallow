/*
 * main.h
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
#ifndef __MAIN_H
#define __MAIN_H

#define PROGNAME            "Tallow"

#define STR2(s)             #s
#define STR(s)              STR2(s)

#define TOR_PORT            49097
#define TOR_ICON            49001

#define ADDR0(a)            ((a) >> 24)
#define ADDR1(a)            (((a) >> 16) & 0xFF)
#define ADDR2(a)            (((a) >> 8) & 0xFF)
#define ADDR3(a)            ((a) & 0xFF)

extern void status(const char *message, ...);
extern void warning(const char *message, ...);

// Options:
extern bool option_force_socks4a;
extern bool option_force_web_only;

// Locking functions:
static inline HANDLE create_lock(void)
{
    HANDLE lock = CreateMutex(NULL, FALSE, NULL);
    if (lock == NULL)
    {
        warning("failed to create lock");
        exit(EXIT_FAILURE);
    }
    return lock;
}
static inline void lock(HANDLE lock)
{
    DWORD result = WaitForSingleObject(lock, INFINITE);
    if (result != WAIT_OBJECT_0)
    {
        warning("failed to acquire lock");
        exit(EXIT_FAILURE);
    }
}
static inline void unlock(HANDLE lock)
{
    if (!ReleaseMutex(lock))
    {
        warning("failed to release lock");
        exit(EXIT_FAILURE);
    }
}

// (Strong) random number:
errno_t __cdecl rand_s(unsigned int *);
static inline unsigned random(void)
{
    unsigned r;
    if (rand_s(&r) != 0)
    {
        warning("failed to get random number");
        exit(EXIT_FAILURE);
    }
    return r;
}

// Debugging:
#define debug(msg, ...)                                                 \
    fprintf(stderr, msg, ## __VA_ARGS__)

#endif
