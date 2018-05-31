/*
 * main.c
 * Copyright (C) 2018, basil
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

#include <windows.h>

#include "allow.h"
#include "main.h"

/***************************************************************************/
/* IP HELPER                                                               */
/***************************************************************************/

/*
 * The MinGW IP helper API definitions are currently broken.  So we just
 * use our own correct definitions.
 */
typedef enum 
{
    TcpConnectionOffloadStateInHost     = 0,
    TcpConnectionOffloadStateOffloading = 1,
    TcpConnectionOffloadStateOffloaded  = 2,
    TcpConnectionOffloadStateUploading  = 3,
    TcpConnectionOffloadStateMax        = 4
} TCP_CONNECTION_OFFLOAD_STATE;
typedef struct
{
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
    TCP_CONNECTION_OFFLOAD_STATE dwOffloadState;
} MIB_TCPROW2, *PMIB_TCPROW2;
typedef struct
{
      DWORD dwNumEntries;
      MIB_TCPROW2 table[];
} MIB_TCPTABLE2, *PMIB_TCPTABLE2;

ULONG WINAPI GetTcpTable2(PMIB_TCPTABLE2 TcpTable, PULONG SizePointer,
    WINBOOL Order);

/***************************************************************************/

#include "main.h"

static bool inited = false;
static DWORD pid = 0;
static MIB_TCPTABLE2 *table = NULL;
static ULONG table_size = 0;
static HANDLE table_lock = NULL;
static bool conns[UINT16_MAX+1] = {false};

static bool is_tor(uint32_t addr, uint16_t port);

// Find Tor connections.
static DWORD WINAPI allow_thread(LPVOID arg)
{
    HANDLE handle = WinDivertOpen(
        "!loopback and outbound and ip and tcp and "
        "((tcp.Syn and !tcp.Ack) or tcp.Fin or tcp.Rst)",
        WINDIVERT_LAYER_NETWORK, -901, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        warning("failed to open WinDivert filter");
        exit(EXIT_FAILURE);
    }

    char packet[MAX_PACKET];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    while (true)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
        {
            // Ignore error.
            continue;
        }

        PWINDIVERT_IPHDR iphdr = NULL;
        PWINDIVERT_TCPHDR tcphdr = NULL;

        WinDivertHelperParsePacket(packet, packet_len, &iphdr, NULL, NULL,
            NULL, &tcphdr, NULL, NULL, NULL);
        if (iphdr == NULL || tcphdr == NULL)
            continue;
        uint16_t src_port = ntohs(tcphdr->SrcPort);
        if (tcphdr->Syn)
        {
            uint32_t src_addr = ntohl(iphdr->SrcAddr);
            conns[src_port] = is_tor(src_addr, src_port);
            if (conns[src_port])
            {
                uint32_t dst_addr = ntohl(iphdr->DstAddr);
                uint16_t dst_port = ntohs(tcphdr->DstPort);
                debug("Allowing Tor connection to %u.%u.%u.%u:%u\n",
                    ADDR0(dst_addr), ADDR1(dst_addr), ADDR2(dst_addr),
                    ADDR3(dst_addr), dst_port);
            }
        }
        else
            conns[src_port] = false;
        if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
            debug("Send packet failed (err=%d)\n", (int)GetLastError());
    }
}

// Initialize this module.
void allow_init(DWORD tor_pid)
{
    debug("Tor process ID is %d\n", (int)tor_pid);
    pid = tor_pid;
    table_lock = create_lock();
    inited = true;
    HANDLE thread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)allow_thread, NULL, 0, NULL);
    if (thread == NULL)
    {
        warning("failed to create Tor-allow thread");
        exit(EXIT_FAILURE);
    }
    CloseHandle(thread);
}

// Test if we should allow the packet.
bool allow(PWINDIVERT_ADDRESS addr, PWINDIVERT_TCPHDR tcphdr)
{
    if (tcphdr == NULL)
        return false;
    uint16_t port = ntohs(addr->Direction == WINDIVERT_DIRECTION_OUTBOUND?
        tcphdr->SrcPort: tcphdr->DstPort);
    return conns[port];
}

// Lookup a table entry.
static bool find_entry(uint32_t addr, uint16_t port)
{
    if (table == NULL)
        return false;

    // Linear search :(
    for (DWORD i = 0; i < table->dwNumEntries; i++)
    {
        if (ntohl(table->table[i].dwLocalAddr) == addr &&
                ntohs((uint16_t)table->table[i].dwLocalPort) == port &&
                table->table[i].dwOwningPid == pid)
        {
            return true;
        }
    }
    return false;
}

// Returns TRUE if the given connect belongs to the Tor PID or not.
// This function is slow, but should be OK (unnoticable) for most user
// applications.
static bool is_tor(uint32_t addr, uint16_t port)
{
    if (!inited)
        return false;

    lock(table_lock);
    if (find_entry(addr, port))
    {
        // Fast path:
        unlock(table_lock);
        return true;
    }

    if (table == NULL)
    {
        table_size = sizeof(MIB_TCPTABLE2);
        table = (MIB_TCPTABLE2 *)malloc(table_size);
        if (table == NULL)
        {
out_of_memory:
            warning("failed to allocate %u bytes for tcp table", table_size);
            exit(EXIT_FAILURE);
        }
    }

    // Entry not found; our table might be out-of-date so refresh:
    DWORD err = 0;
    while (true)
    {
        err = GetTcpTable2(table, &table_size, FALSE);
        if (err != ERROR_INSUFFICIENT_BUFFER)
            break;
        free(table);
        table = (MIB_TCPTABLE2 *)malloc(table_size);
        if (table == NULL)
            goto out_of_memory;
    }
    if (err != 0)
    {
        free(table);
        table = NULL;
        unlock(table_lock);
        debug("Failed to get TCP table (err=%d)\n", (int)err);
        return false;           // Assume non-Tor failsafe.
    }

    // Table is now up-to-date:
    bool found = find_entry(addr, port);
    unlock(table_lock);
    return found;
}

