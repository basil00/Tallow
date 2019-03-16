/*
 * redirect.c
 * Copyright (C) 2019, basil
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

#include "windivert.h"

#include "domain.h"
#include "main.h"
#include "redirect.h"

#define PRIORITY            1750
#define NUM_WORKERS         2
#define MAX_FILTER          (1024-1)
#define INET4_ADDRSTRLEN    16

// SOCKS4a headers
#define SOCKS_USERID_SIZE   (256 + 8)
struct socks4a_req
{
    uint8_t vn;
    uint8_t cd;
    uint16_t dst_port;
    uint32_t dst_addr;
    char userid[SOCKS_USERID_SIZE];
} __attribute__((__packed__));

struct socks4a_rep
{
    uint8_t vn;
    uint8_t cd;
    uint16_t port;
    uint32_t addr;
} __attribute__((__packed__));

// DNS headers
#define DNS_MAX_NAME    254
struct dnshdr
{
    uint16_t id;
    uint16_t options;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__));

struct dnsq
{
    uint16_t type;
    uint16_t class;
} __attribute__((__packed__));

struct dnsa
{
    uint16_t name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
    uint32_t addr;
} __attribute__((__packed__));

// Pended SYN.
struct syn
{
    WINDIVERT_ADDRESS addr;
    UINT packet_len;
    uint8_t packet[];
};

// Connections:
#define STATE_NOT_CONNECTED         0
#define STATE_SYN_WAIT              1
#define STATE_SYN_SEEN              2
#define STATE_SYNACK_SEEN           3
#define STATE_ESTABLISHED           4
#define STATE_FIN_WAIT              5
#define STATE_WHITELISTED           0xFF
struct connection
{
    uint8_t state;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t local_addr;
    uint32_t remote_addr;
    uint32_t if_idx;
    uint32_t sub_if_idx;
    struct syn *syn;
} __attribute__((__packed__));

// Cleanup.
struct cleanup
{
    uint32_t addr;
    uint16_t port;
    struct cleanup *next;
};

// Prototypes:
static void flush_dns_cache(void);
static DWORD redirect_worker(LPVOID arg);
static DWORD whitelist_worker(LPVOID arg);
static void reset(HANDLE handle, PWINDIVERT_IPHDR iphdr,
    PWINDIVERT_TCPHDR tcphdr, size_t data_len, PWINDIVERT_ADDRESS addr);
static void redirect_tcp(HANDLE handle, PWINDIVERT_ADDRESS addr,
    PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr, char *packet,
    size_t packet_len, char *data, size_t data_len);
static void handle_dns(HANDLE handle, PWINDIVERT_ADDRESS addr,
    PWINDIVERT_IPHDR iphdr, PWINDIVERT_UDPHDR udphdr, char *data,
    size_t data_len);
static void socks4a_connect_1_of_2(struct connection *conn, HANDLE handle,
    PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr);
static void socks4a_connect_2_of_2(struct connection *conn, HANDLE handle,
    PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr,
    struct socks4a_rep *sockshdr);
extern bool filter_read(const char *filename, char *filter, size_t len);

// State:
static uint32_t loopback_addr;
static char filter[MAX_FILTER+1];
static bool redirect_on = false;
static HANDLE handle = INVALID_HANDLE_VALUE;
static HANDLE handle_drop = INVALID_HANDLE_VALUE;
static HANDLE workers[NUM_WORKERS] = {NULL};    // Worker threads
static struct connection conns[UINT16_MAX+1] = {{0}};
static HANDLE conns_lock;

// Flush the DNS cache:
static void flush_dns_cache(void)
{
    debug(YELLOW, "FLUSH", "DNS cache");
    char dllname[MAX_PATH];
    UINT len = GetSystemDirectory(dllname, sizeof(dllname));
    if (len == 0)
    {
dir_error:
        warning("failed to get the system directory");
        exit(EXIT_FAILURE);
    }
    const char filename[] = "dnsapi.dll";
    if (sizeof(dllname) - len <= sizeof(filename) + 2)
        goto dir_error;
    dllname[len] = '\\';
    strcpy(dllname + len + 1, filename);
    HMODULE lib = LoadLibrary(dllname);
    if (lib == NULL)
    {
        warning("failed to load library \"%s\"", dllname);
        exit(EXIT_FAILURE);
    }
    BOOL WINAPI (*DnsFlushResolverCache)(void);
    DnsFlushResolverCache =
        (BOOL WINAPI (*)(void))GetProcAddress(lib, "DnsFlushResolverCache");
    if (DnsFlushResolverCache == NULL || !DnsFlushResolverCache())
        warning("failed to flush DNS cache");
    FreeLibrary(lib);
}

// Send a packet:
static void send_packet(HANDLE handle, void *packet, size_t packet_len,
    PWINDIVERT_ADDRESS addr)
{
    addr->Outbound = 1;
    WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);
    if (!WinDivertSend(handle, packet, packet_len, NULL, addr))
        debug(RED, "ERROR", "Send packet failed (err=%d)",
            (int)GetLastError());
}

// Reset worker thread:
static void reset_worker(LPVOID arg)
{
    HANDLE handle = (LPVOID)arg;

    char packet[MAX_PACKET];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    while (true)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
            continue;

        PWINDIVERT_IPHDR iphdr = NULL;
        PWINDIVERT_TCPHDR tcphdr = NULL;
        UINT data_len;
        WinDivertHelperParsePacket(packet, packet_len, &iphdr, NULL, NULL,
            NULL, NULL, &tcphdr, NULL, NULL, &data_len, NULL, NULL);
   
        if (iphdr == NULL || tcphdr == NULL)
            continue;
    
        reset(handle, iphdr, tcphdr, data_len, &addr);
    }
}

// Init this module:
extern void redirect_init(void)
{
    (void)WinDivertHelperParseIPv4Address("127.0.0.1", &loopback_addr);
    loopback_addr = ntohl(loopback_addr);
    conns_lock = create_lock();

    // Prevent "fake" IPs leaking to the internet.
    HANDLE handle = WinDivertOpen(
        "outbound and ip.DstAddr >= " ADDR_BASE_STR " and ip.DstAddr <= "
            ADDR_MAX_STR,
        WINDIVERT_LAYER_NETWORK, -1755, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        warning("failed to open WinDivert filter");
        exit(EXIT_FAILURE);
    }
    HANDLE thread = CreateThread(NULL, 1,
        (LPTHREAD_START_ROUTINE)reset_worker, (LPVOID)handle, 0, NULL);
    if (thread == NULL)
    {
        warning("failed to create reset worker thread");
        exit(EXIT_FAILURE);
    }
    CloseHandle(thread);

    // Read the filter:
    if (!filter_read("traffic.deny", filter, sizeof(filter)))
    {
        // Use the default filter:
        const char *default_filter = "ipv6 or (not tcp and udp.DstPort != 53)";
        size_t len = strlen(default_filter);
        if (len+1 > sizeof(filter))
        {
            warning("failed to create default filter");
            exit(EXIT_FAILURE);
        }
        memcpy(filter, default_filter, len+1);
    }
    debug(GREEN, "INFO", "Filter is \"%s\"", filter);
}

// Start traffic redirect through Tor:
extern void redirect_start(void)
{
    debug(GREEN, "INFO", "Tor divert START");

    if (handle != INVALID_HANDLE_VALUE)
        return;

    // Drop traffic from the loaded filter:
    debug(GREEN, "INFO", "Traffic deny filter is \"%s\"", filter);
    handle_drop = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, PRIORITY+1,
        WINDIVERT_FLAG_DROP);
    if (handle_drop == INVALID_HANDLE_VALUE)
    {
redirect_start_error:
        warning("failed to open WinDivert filter");
        exit(EXIT_FAILURE);
    }

    char tor_filter[MAX_FILTER+1];
    if (!filter_read("traffic.divert", tor_filter, sizeof(tor_filter)-1))
    {
        // Use the default filter:
        const char *default_filter = "true";
        size_t len = strlen(default_filter);
        if (len+1 > sizeof(tor_filter))
        {
            warning("failed to create default filter");
            exit(EXIT_FAILURE);
        }
        memcpy(tor_filter, default_filter, len+1);
    }
    debug(GREEN, "INFO", "Traffic divert filter is \"%s\"", tor_filter);
    handle = WinDivertOpen(tor_filter, WINDIVERT_LAYER_NETWORK, PRIORITY, 0);
    if (handle == INVALID_HANDLE_VALUE)
        goto redirect_start_error;

    flush_dns_cache();

    // Max-out the packet queue:
    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH,
        WINDIVERT_PARAM_QUEUE_LENGTH_MAX);
    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE,
        WINDIVERT_PARAM_QUEUE_SIZE_MAX);
    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME,
        WINDIVERT_PARAM_QUEUE_TIME_MAX);

    // Launch threads:
    redirect_on = true;
    for (size_t i = 0; i < UINT16_MAX; i++)
    {
        lock(conns_lock);
        uint8_t state = conns[i].state;
        memset(&conns[i], 0, sizeof(conns[i]));
        if (state == STATE_WHITELISTED)
            conns[i].state = state;
        unlock(conns_lock);
    }
    for (size_t i = 0; i < NUM_WORKERS; i++)
    {
        workers[i] = CreateThread(NULL, MAX_PACKET*3,
            (LPTHREAD_START_ROUTINE)redirect_worker, (LPVOID)handle, 0, NULL);
        if (workers[i] == NULL)
        {
            warning("failed to create WinDivert worker thread");
            exit(EXIT_FAILURE);
        }
    }
}

// Stop traffic redirect through Tor:
extern void redirect_stop(void)
{
    debug(GREEN, "INFO", "Tor divert STOP");

    if (handle == INVALID_HANDLE_VALUE)
        return;

    // Shutdown the WinDivert handle; will cause the workers to exit.
    if (!WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_RECV))
    {
        warning("failed to close WinDivert filter");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < NUM_WORKERS; i++)
    {
        WaitForSingleObject(workers[i], INFINITE);
        CloseHandle(workers[i]);
        workers[i] = NULL;
    }

    WinDivertClose(handle);
    WinDivertClose(handle_drop);

    // Reset all connections:
    for (size_t i = 0; i < UINT16_MAX; i++)
    {
        lock(conns_lock);
        switch (conns[i].state)
        {
            case STATE_WHITELISTED:
                break;
            default:
                memset(&conns[i], 0, sizeof(conns[i]));
                break;
        }
        unlock(conns_lock);
    }
    handle = INVALID_HANDLE_VALUE;
    handle_drop = INVALID_HANDLE_VALUE;

    redirect_on = false;
    flush_dns_cache();
}

// Redirect worker thread:
static DWORD redirect_worker(LPVOID arg)
{
    HANDLE handle = (HANDLE)arg;

    // Packet processing loop:
    char packet[MAX_PACKET];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;

    while (true)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            if (GetLastError() == ERROR_NO_DATA)
                break;
            debug(RED, "ERROR", "Receive packet failed (err=%d)",
                (int)GetLastError());
            continue;
        }

        PWINDIVERT_IPHDR iphdr = NULL;
        PWINDIVERT_TCPHDR tcphdr = NULL;
        PWINDIVERT_UDPHDR udphdr = NULL;
        PVOID data = NULL;
        UINT data_len;
        WinDivertHelperParsePacket(packet, packet_len, &iphdr, NULL, NULL,
            NULL, NULL, &tcphdr, &udphdr, &data, &data_len, NULL, NULL);

        if (udphdr != NULL && ntohs(udphdr->DstPort) == 53)
            handle_dns(handle, &addr, iphdr, udphdr, data, data_len);
        else if (tcphdr != NULL)
            redirect_tcp(handle, &addr, iphdr, tcphdr, packet, packet_len,
                data, data_len);
    }
    return 0;
}

// Handle a SYN:
static void handle_syn(HANDLE handle, struct connection *conn)
{
    // Assumes we are holding conns_lock...

    struct syn *syn = conn->syn;
    conn->syn = NULL;
    if (syn == NULL)
    {
        unlock(conns_lock);
        return;
    }
    PWINDIVERT_IPHDR iphdr = NULL;
    PWINDIVERT_TCPHDR tcphdr = NULL;
    WinDivertHelperParsePacket(syn->packet, syn->packet_len, &iphdr, NULL,
        NULL, NULL, NULL, &tcphdr, NULL, NULL, NULL, NULL, NULL);
    if (iphdr == NULL || tcphdr == NULL)
    {
        unlock(conns_lock);
        free(syn);
        return;
    }

    switch (conn->state)
    {
        case STATE_WHITELISTED:
            // This connection has been whitelisted.  Send the SYN using
            // the normal (non-Tor) path:
            unlock(conns_lock);
            send_packet(handle, syn->packet, syn->packet_len, &syn->addr);

            char local_addr_str[INET4_ADDRSTRLEN],
                 remote_addr_str[INET4_ADDRSTRLEN];
            WinDivertHelperFormatIPv4Address(ntohl(iphdr->SrcAddr),
                local_addr_str, sizeof(local_addr_str));
            WinDivertHelperFormatIPv4Address(ntohl(iphdr->DstAddr),
                remote_addr_str, sizeof(remote_addr_str));
            debug(GREEN, "WHITELIST", "Tor connection %s:%u ---> %s:%u",
                local_addr_str, ntohs(tcphdr->SrcPort),
                remote_addr_str, ntohs(tcphdr->DstPort));
            free(syn);
            return;

        case STATE_SYN_WAIT:
        {
            // This connection must be redirected to Tor:
            uint16_t remote_port = ntohs(tcphdr->DstPort);
            if (option_force_web_only &&
                remote_port != 80 &&            // HTTP
                remote_port != 443)             // HTTPS
            {
                unlock(conns_lock);
                uint32_t srcaddr = ntohl(iphdr->SrcAddr),
                         dstaddr = ntohl(iphdr->DstAddr);
                char srcaddr_str[INET4_ADDRSTRLEN+1];
                WinDivertHelperFormatIPv4Address(srcaddr, srcaddr_str,
                    sizeof(srcaddr_str));
                struct name *name = domain_lookup_name(dstaddr);
                if (name != NULL)
                {
                    debug(GREEN, "INFO", "Ignoring non-web connect %s:%u ---> "
                        "%s:%u", srcaddr_str, ntohs(tcphdr->SrcPort),
                        name->name, remote_port);
                    domain_deref(name);
                }
                else
                {
                    char dstaddr_str[INET4_ADDRSTRLEN+1];
                    WinDivertHelperFormatIPv4Address(dstaddr, dstaddr_str,
                        sizeof(dstaddr_str));
                    debug(GREEN, "INFO", "Ignoring non-web connect %s:%u ---> "
                        "%s:%u", srcaddr_str, ntohs(tcphdr->SrcPort),
                        dstaddr_str, remote_port);
                }
                free(syn);
                return;
            }

            conn->state       = STATE_SYN_SEEN;
            conn->remote_port = tcphdr->DstPort;
            conn->remote_addr = iphdr->DstAddr;
            conn->local_port  = tcphdr->SrcPort;
            conn->local_addr  = iphdr->SrcAddr;
            conn->if_idx      = syn->addr.Network.IfIdx;
            conn->sub_if_idx  = syn->addr.Network.SubIfIdx;
            unlock(conns_lock);

            // Adjust the TCP seq number so a SOCKS4a header can be
            // injected into the stream.  This makes it possible to
            // "glue" the TCP connection to a SOCKS4a connection.
            tcphdr->SeqNum = htonl(ntohl(tcphdr->SeqNum) -
                sizeof(struct socks4a_req));
            tcphdr->DstPort = htons(TOR_PORT);
            syn->addr.Network.IfIdx = 1;            // Loopback
            syn->addr.Network.SubIfIdx = 0;
            syn->addr.Loopback = 1;
            iphdr->DstAddr = loopback_addr;
            iphdr->SrcAddr = loopback_addr;
            send_packet(handle, syn->packet, syn->packet_len, &syn->addr);
            free(syn);
            return;
        }

        default:
            unlock(conns_lock);
            return;
    }
}

// Pend a SYN:
static void pend_syn(HANDLE handle, uint16_t local_port, char *packet,
    size_t packet_len, PWINDIVERT_ADDRESS addr)
{
    struct syn *syn = (struct syn *)malloc(sizeof(struct syn) + packet_len);
    if (syn == NULL)
    {
        warning("failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    memcpy(&syn->addr, addr, sizeof(syn->addr));
    syn->packet_len = packet_len;
    memcpy(&syn->packet, packet, packet_len);

    struct connection *conn = conns + local_port;
    struct syn *old_syn = NULL;
    lock(conns_lock);
    old_syn = conn->syn;
    conn->syn = syn;
    handle_syn(handle, conn);
    free(old_syn);
}

// Pend a CONNECT:
static void pend_connect(HANDLE handle, uint16_t local_port, uint8_t state)
{
    if (!redirect_on)
        return;

    struct connection *conn = conns + local_port;
    lock(conns_lock);
    switch (conn->state)
    {
        case STATE_NOT_CONNECTED:
        case STATE_FIN_WAIT:
            conn->state = state;
            handle_syn(handle, conn);
            break;
        default:
            unlock(conns_lock);
            break;
    }
}

// Redirect TCP:
static void redirect_tcp(HANDLE handle, PWINDIVERT_ADDRESS addr,
    PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr, char *packet,
    size_t packet_len, char *data, size_t data_len)
{
    uint16_t local_port;
    struct connection conn_copy, *conn = NULL;

#if 0
    {
        char src_addr_str[INET4_ADDRSTRLEN+1],
             dst_addr_str[INET4_ADDRSTRLEN+1];
        WinDivertHelperFormatIPv4Address(ntohl(iphdr->SrcAddr), src_addr_str,
            sizeof(src_addr_str));
        WinDivertHelperFormatIPv4Address(ntohl(iphdr->DstAddr), dst_addr_str,
            sizeof(dst_addr_str));
        debug(GREEN, "PACKET", "%s:%u %s %s:%u [Len=%u Syn=%u Ack=%u]",
            src_addr_str, ntohs(tcphdr->SrcPort),
            (addr->Outbound? "---->": "<----"),
            dst_addr_str, ntohs(tcphdr->DstPort),
            data_len, tcphdr->Syn, tcphdr->Ack);
    }
#endif

    if (addr->Loopback &&
            ntohs(tcphdr->SrcPort) != TOR_PORT &&
            ntohs(tcphdr->DstPort) != TOR_PORT)
    {
        // Allow unrelated loopback traffic.
        ;
    }
    else if (addr->Outbound && !addr->Loopback)
    {
        // OUTBOUND PATH: PC ---> Tor
        local_port = tcphdr->SrcPort;
        conn = conns + local_port;

        if (tcphdr->Syn && !tcphdr->Ack)
        {
            pend_syn(handle, local_port, packet, packet_len, addr);
            return;
        }
 
        lock(conns_lock);
        switch (conn->state)
        {
            case STATE_WHITELISTED:
                unlock(conns_lock);
                send_packet(handle, packet, packet_len, addr);
                return;

            case STATE_FIN_WAIT:
                if ((tcphdr->Fin || tcphdr->Rst) && 
                    iphdr->DstAddr == conn->remote_addr &&
                    tcphdr->DstPort == conn->remote_port)
                {
                    unlock(conns_lock);
                    send_packet(handle, packet, packet_len, addr);
                    return;
                }
                // Fallthrough:

            case STATE_NOT_CONNECTED:
            case STATE_SYN_SEEN:
            case STATE_SYNACK_SEEN:
                unlock(conns_lock);
                return;

            default:
                unlock(conns_lock);
                break;
        }

        // Redirect this packet to Tor
        tcphdr->DstPort = htons(TOR_PORT);
        addr->Network.IfIdx = 1;            // Loopback
        addr->Network.SubIfIdx = 0;
        addr->Loopback = 1;
        iphdr->DstAddr = loopback_addr;
        iphdr->SrcAddr = loopback_addr;
    }
    else if (addr->Outbound && addr->Loopback)
    {
        // REVERSE PATH: Tor ---> PC
        local_port = tcphdr->DstPort;
        conn = conns + local_port;
        
        lock(conns_lock);
        switch (conn->state)
        {
            case STATE_NOT_CONNECTED:
            case STATE_FIN_WAIT:
                unlock(conns_lock);
                return;
            case STATE_SYN_SEEN:
                if (!tcphdr->Syn || !tcphdr->Ack)
                {
                    unlock(conns_lock);
                    return;
                }

                // SYN-ACK
                memcpy(&conn_copy, conn, sizeof(conn_copy));
                conn->state = STATE_SYNACK_SEEN;
                unlock(conns_lock);
                socks4a_connect_1_of_2(&conn_copy, handle, addr, iphdr,
                    tcphdr);
                return;
            
            case STATE_SYNACK_SEEN:
                if (data_len != sizeof(struct socks4a_rep))
                {
                    unlock(conns_lock);
                    return;
                }
                memcpy(&conn_copy, conn, sizeof(conn_copy));
                conn->state = STATE_ESTABLISHED;
                unlock(conns_lock);
                struct socks4a_rep *rep = (struct socks4a_rep *)data;
                socks4a_connect_2_of_2(&conn_copy, handle, addr, iphdr, tcphdr,
                    rep);
                return;

            default:
                break;
        }

        // Redirect this packet to the PC (inbound)
        tcphdr->SrcPort = conn->remote_port;
        addr->Network.IfIdx = conn->if_idx;
        addr->Network.SubIfIdx = conn->sub_if_idx;
        addr->Loopback = 0;
        addr->Outbound = 0;
        iphdr->DstAddr = conn->local_addr;
        iphdr->SrcAddr = conn->remote_addr;
        unlock(conns_lock);
    }
    else if (!addr->Outbound)
    {
        // Only whitelisted inbound traffic is allowed:
        local_port = tcphdr->DstPort;
        conn = conns + local_port;
    
        lock(conns_lock);
        if (conn->state != STATE_WHITELISTED)
        {
            unlock(conns_lock);
            return;
        }
        unlock(conns_lock);
    }

    send_packet(handle, packet, packet_len, addr);
}

// Reset a connection.
static void reset(HANDLE handle, PWINDIVERT_IPHDR iphdr,
    PWINDIVERT_TCPHDR tcphdr, size_t data_len, PWINDIVERT_ADDRESS addr)
{
    struct
    {
        WINDIVERT_IPHDR iphdr;
        WINDIVERT_TCPHDR tcphdr;
    } rst;
    
    memset(&rst.iphdr, 0, sizeof(rst.iphdr));
    rst.iphdr.Version = 4;
    rst.iphdr.HdrLength = sizeof(rst.iphdr) / sizeof(uint32_t);
    rst.iphdr.Id = htons(0xDEAD);
    WINDIVERT_IPHDR_SET_DF(&rst.iphdr, 1);
    rst.iphdr.Length = htons(sizeof(rst));
    rst.iphdr.TTL = 64;
    rst.iphdr.Protocol = IPPROTO_TCP;
    rst.iphdr.SrcAddr = iphdr->DstAddr;
    rst.iphdr.DstAddr = iphdr->SrcAddr;
    
    memset(&rst.tcphdr, 0, sizeof(rst.tcphdr));
    rst.tcphdr.SrcPort = tcphdr->DstPort;
    rst.tcphdr.DstPort = tcphdr->SrcPort;
    rst.tcphdr.SeqNum = tcphdr->AckNum;
    rst.tcphdr.AckNum = (tcphdr->Syn?
        htonl(ntohl(tcphdr->SeqNum) + 1) :
        htonl(ntohl(tcphdr->SeqNum) + data_len));
    rst.tcphdr.HdrLength = sizeof(rst.tcphdr) / sizeof(uint32_t);
    rst.tcphdr.Ack = 1;
    rst.tcphdr.Rst = 1;

    send_packet(handle, &rst, sizeof(rst), addr);

    char local_addr_str[INET4_ADDRSTRLEN],
         remote_addr_str[INET4_ADDRSTRLEN];
    WinDivertHelperFormatIPv4Address(ntohl(iphdr->SrcAddr),
        local_addr_str, sizeof(local_addr_str));
    WinDivertHelperFormatIPv4Address(ntohl(iphdr->DstAddr),
        remote_addr_str, sizeof(remote_addr_str));
    debug(YELLOW, "RESET", "%s:%u -/-> %s:%u",
        local_addr_str, ntohs(tcphdr->SrcPort),
        remote_addr_str, ntohs(tcphdr->DstPort));
}

// Glue a normal TCP connection to SOCKS4a connection.
static void socks4a_connect_1_of_2(struct connection *conn, HANDLE handle,
    PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr)
{
    uint32_t dstaddr = ntohl(conn->remote_addr);
    struct name *name = domain_lookup_name(dstaddr);
    char local_addr_str[INET4_ADDRSTRLEN+1],
         remote_addr_str[INET4_ADDRSTRLEN+1];
    if (name == NULL && option_force_socks4a)
    {
        WinDivertHelperFormatIPv4Address(ntohl(conn->local_addr),
            local_addr_str, sizeof(local_addr_str));
        WinDivertHelperFormatIPv4Address(ntohl(conn->remote_addr),
            remote_addr_str, sizeof(remote_addr_str));
        debug(GREEN, "INFO", "Ignoring non-SOCKs4a connect %s:%u ---> %s:%u",
            local_addr_str, ntohs(conn->local_port), remote_addr_str,
            ntohs(conn->remote_port));

        // No corresponding name -- ignore
        return;
    }
    if (name == NULL && is_fake_addr(dstaddr))
    {
        WinDivertHelperFormatIPv4Address(ntohl(iphdr->SrcAddr), local_addr_str,
            sizeof(local_addr_str));
        WinDivertHelperFormatIPv4Address(ntohl(iphdr->DstAddr), remote_addr_str,
            sizeof(remote_addr_str));
        debug(GREEN, "INFO", "Ignoring stale connect %s:%u ---> %s:%u",
            local_addr_str, ntohs(conn->local_port), remote_addr_str,
            ntohs(conn->remote_port));

        // Address is stale -- ignore
        return;
    }

    // Send an ACK back to Tor.  This completes 3-way TCP handshake (Tor-side):
    struct
    {
        WINDIVERT_IPHDR iphdr;
        WINDIVERT_TCPHDR tcphdr;
    } ack;

    memset(&ack.iphdr, 0, sizeof(ack.iphdr));
    ack.iphdr.Version = 4;
    ack.iphdr.HdrLength = sizeof(ack.iphdr) / sizeof(uint32_t);
    ack.iphdr.Id = htons(0xF001);
    WINDIVERT_IPHDR_SET_DF(&ack.iphdr, 1);
    ack.iphdr.Length = htons(sizeof(ack));
    ack.iphdr.TTL = 64;
    ack.iphdr.Protocol = IPPROTO_TCP;
    ack.iphdr.SrcAddr = loopback_addr;
    ack.iphdr.DstAddr = loopback_addr;

    memset(&ack.tcphdr, 0, sizeof(ack.tcphdr));
    ack.tcphdr.SrcPort = tcphdr->DstPort;
    ack.tcphdr.DstPort = tcphdr->SrcPort;
    ack.tcphdr.SeqNum = tcphdr->AckNum;
    ack.tcphdr.AckNum = htonl(ntohl(tcphdr->SeqNum) + 1);
    ack.tcphdr.HdrLength = sizeof(ack.tcphdr) / sizeof(uint32_t);
    ack.tcphdr.Ack = 1;
    ack.tcphdr.Window = htons(8192);

    addr->Network.IfIdx = 1;                // Loopback
    addr->Network.SubIfIdx = 0;
    addr->Loopback = 1;
    send_packet(handle, &ack, sizeof(ack), addr);

    // Send a SOCKS4a CONNECT request to Tor.
    struct
    {
        WINDIVERT_IPHDR iphdr;
        WINDIVERT_TCPHDR tcphdr;
        struct socks4a_req sockshdr;
    } req;

    memset(&req.iphdr, 0, sizeof(req.iphdr));
    req.iphdr.Version = 4;
    req.iphdr.HdrLength = sizeof(req.iphdr) / sizeof(uint32_t);
    req.iphdr.Id = htons(0xF002);
    WINDIVERT_IPHDR_SET_DF(&req.iphdr, 1);
    req.iphdr.Length = htons(sizeof(req));
    req.iphdr.TTL = 64;
    req.iphdr.Protocol = IPPROTO_TCP;
    req.iphdr.SrcAddr = loopback_addr;
    req.iphdr.DstAddr = loopback_addr;

    memset(&req.tcphdr, 0, sizeof(req.tcphdr));
    req.tcphdr.SrcPort = tcphdr->DstPort;
    req.tcphdr.DstPort = tcphdr->SrcPort;
    req.tcphdr.SeqNum = ack.tcphdr.SeqNum;
    req.tcphdr.AckNum = ack.tcphdr.AckNum;
    req.tcphdr.HdrLength = sizeof(req.tcphdr) / sizeof(uint32_t);
    req.tcphdr.Psh = 1;
    req.tcphdr.Ack = 1;
    req.tcphdr.Window = htons(8192);

    req.sockshdr.vn = 0x04;                 // SOCKS4a
    req.sockshdr.cd = 0x01;                 // Stream connection
    req.sockshdr.dst_port = conn->remote_port;

    (void)WinDivertHelperFormatIPv4Address(ntohl(conn->local_addr),
        local_addr_str, sizeof(local_addr_str));
    if (name != NULL)
    {
        debug(GREEN, "CONNECT", "%s:%u ---> %s:%u", local_addr_str,
            ntohs(conn->local_port), name->name, ntohs(conn->remote_port));
        
        req.sockshdr.dst_addr = ntohl(0x00000001);

        // Write fake userid:
        size_t name_len = strlen(name->name);
        size_t userid_len = SOCKS_USERID_SIZE - 1 - name_len - 1;
        size_t i;
        for (i = 0; i < userid_len; i++)
            req.sockshdr.userid[i] = 'A';
        req.sockshdr.userid[i++] = '\0';

        // Write domain:
        for (size_t j = 0; j < name_len; j++)
            req.sockshdr.userid[i + j] = name->name[j];
        domain_deref(name);
    }
    else
    {
        char remote_addr_str[INET4_ADDRSTRLEN+1];
        (void)WinDivertHelperFormatIPv4Address(ntohl(conn->local_addr),
            remote_addr_str, sizeof(remote_addr_str));
        debug(GREEN, "CONNECT", "%s:%u ---> %s:%u",
            local_addr_str, ntohs(conn->local_port), remote_addr_str,
                ntohs(conn->remote_port));

        req.sockshdr.dst_addr = conn->remote_addr;

        // SOCKS4 direct connection:
        for (size_t i = 0; i < SOCKS_USERID_SIZE - 1; i++)
            req.sockshdr.userid[i] = '4';
    }
    req.sockshdr.userid[SOCKS_USERID_SIZE-1] = '\0';
    send_packet(handle, &req, sizeof(req), addr);

    // The original SYN-ACK is dropped.  A "replacement" SYN-ACK will be sent
    // by the socks4a_connect_2_of_2() function.
}

static void socks4a_connect_2_of_2(struct connection *conn, HANDLE handle,
    PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr,
    struct socks4a_rep *sockshdr)
{
    addr->Network.IfIdx = conn->if_idx;
    addr->Network.SubIfIdx = conn->sub_if_idx;
    addr->Loopback = 0;
    addr->Outbound = 0;

    if (sockshdr->vn != 0 || sockshdr->cd != 0x5A)
    {
        reset(handle, iphdr, tcphdr, sizeof(struct socks4a_rep), addr);
        return;
    }

    // SYN-ACK to complete 3-way handshake (PC-side):
    struct
    {
        WINDIVERT_IPHDR iphdr;
        WINDIVERT_TCPHDR tcphdr;
    } synack;

    memset(&synack.iphdr, 0, sizeof(synack.iphdr));
    synack.iphdr.Version = 4;
    synack.iphdr.HdrLength = sizeof(synack.iphdr) / sizeof(uint32_t);
    synack.iphdr.Id = htons(0xF004);
    WINDIVERT_IPHDR_SET_DF(&synack.iphdr, 1);
    synack.iphdr.Length = htons(sizeof(synack));
    synack.iphdr.TTL = 64;
    synack.iphdr.Protocol = IPPROTO_TCP;
    synack.iphdr.SrcAddr = conn->remote_addr;
    synack.iphdr.DstAddr = conn->local_addr;

    memset(&synack.tcphdr, 0, sizeof(synack.tcphdr));
    synack.tcphdr.SrcPort = conn->remote_port;
    synack.tcphdr.DstPort = conn->local_port;
    synack.tcphdr.SeqNum = htonl(ntohl(tcphdr->SeqNum) +
        sizeof(struct socks4a_rep) - 1);
    synack.tcphdr.AckNum = tcphdr->AckNum;
    synack.tcphdr.HdrLength = sizeof(synack.tcphdr) / sizeof(uint32_t);
    synack.tcphdr.Syn = 1;
    synack.tcphdr.Ack = 1;
    synack.tcphdr.Window = tcphdr->Window;

    send_packet(handle, &synack, sizeof(synack), addr);
}

// Handle DNS requests.
// NOTES:
// - If anything goes wrong, we simply drop the packet without error.
// - An alternative approach would be to let Tor resolve the address, however,
//   this would be slow.
static void handle_dns(HANDLE handle, PWINDIVERT_ADDRESS addr,
    PWINDIVERT_IPHDR iphdr, PWINDIVERT_UDPHDR udphdr, char *data,
    size_t data_len)
{
    // We only handle standard DNS queries.

    if (!addr->Outbound)
        return;
    if (data_len <= sizeof(struct dnshdr))
        return;
    if (data_len > 512)                     // Max DNS packet size.
        return;

    struct dnshdr *dnshdr = (struct dnshdr *)data;
    data += sizeof(struct dnshdr);
    data_len -= sizeof(struct dnshdr);

    // Check request:
    if (ntohs(dnshdr->options) != 0x0100)   // Standard query
        return;
    if (ntohs(dnshdr->qdcount) != 1)        // Only 1 req-per-packet supported
        return;
    if (ntohs(dnshdr->ancount) != 0)
        return;
    if (ntohs(dnshdr->nscount) != 0)
        return;
    if (ntohs(dnshdr->arcount) != 0)
        return;

    char name[DNS_MAX_NAME + 8];            // 8 bytes extra.
    size_t i = 0;
    while (i < data_len && data[i] != 0)
    {
        size_t len = data[i];
        if (i + len >= DNS_MAX_NAME || i + len >= data_len)
            return;
        name[i++] = '.';
        for (size_t j = 0; j < len; j++, i++)
            name[i] = data[i];
    }
    if (i >= data_len)
        return;
    name[i++] = '\0';
    if (data_len - i != sizeof(struct dnsq))
        return;

    // Generate a fake IP address and associate it with this domain name:
    uint32_t fake_addr = domain_lookup_addr(name);
    if (fake_addr == 0)
    {
        // This domain is blocked; so ignore the request.
        return;
    }

    char fake_addr_str[INET4_ADDRSTRLEN+1];
    (void)WinDivertHelperFormatIPv4Address(fake_addr, fake_addr_str,
        sizeof(fake_addr_str));
    debug(GREEN, "INTERCEPT", "Domain %s mapped to address %s",
        (name[0] == '.'? name+1: name), fake_addr_str);

    // Construct a query response:
    size_t len = sizeof(struct dnshdr) + data_len + sizeof(struct dnsa);
    if (len > 512)                          // Max DNS packet size.
        return;
    len += sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR);

    char buf[len + 8];                      // 8 bytes extra.
    PWINDIVERT_IPHDR riphdr = (PWINDIVERT_IPHDR)buf;
    PWINDIVERT_UDPHDR rudphdr = (PWINDIVERT_UDPHDR)(riphdr + 1);
    struct dnshdr *rdnshdr = (struct dnshdr *)(rudphdr + 1);
    char *rdata = (char *)(rdnshdr + 1);

    memset(riphdr, 0, sizeof(WINDIVERT_IPHDR));
    riphdr->Version   = 4;
    riphdr->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(uint32_t);
    riphdr->Length    = htons(len);
    riphdr->Id        = htons(0xF00D);
    WINDIVERT_IPHDR_SET_DF(riphdr, 1);
    riphdr->TTL       = 64;
    riphdr->Protocol  = IPPROTO_UDP;
    riphdr->SrcAddr   = iphdr->DstAddr;
    riphdr->DstAddr   = iphdr->SrcAddr;

    memset(rudphdr, 0, sizeof(WINDIVERT_UDPHDR));
    rudphdr->SrcPort  = htons(53);          // DNS
    rudphdr->DstPort  = udphdr->SrcPort;
    rudphdr->Length   = htons(len - sizeof(WINDIVERT_IPHDR));

    rdnshdr->id = dnshdr->id;
    rdnshdr->options = htons(0x8180);       // Standard DNS response.
    rdnshdr->qdcount = htons(1);
    rdnshdr->ancount = htons(1);
    rdnshdr->nscount = 0;
    rdnshdr->arcount = 0;

    memcpy(rdata, data, data_len);
    struct dnsa *rdnsa = (struct dnsa *)(rdata + data_len);
    rdnsa->name   = htons(0xC00C);
    rdnsa->type   = htons(0x0001);          // (A)
    rdnsa->class  = htons(0x0001);          // (IN)
    rdnsa->ttl    = htonl(1) ;              // 1 second
    rdnsa->length = htons(4);
    rdnsa->addr   = htonl(fake_addr);       // Fake address

    send_packet(handle, &buf, len, addr);
}

// Read traffic filter.
extern bool filter_read(const char *filename, char *filter, size_t len)
{
    FILE *stream = fopen(filename, "r");
    if (stream == NULL)
    {
        warning("failed to open \"%s\" for reading", filename);
        return false;
    }
    
    int c;
    size_t i = 0;
    bool space = false;
    while (true)
    {
        c = getc(stream);
        switch (c)
        {
            case EOF:
            {
                fclose(stream);
                if (i >= len)
                    goto length_error;
                filter[i++] = '\0';

                // Check the filter for errors:
                const char *err_str;
                if (!WinDivertHelperCompileFilter(filter,
                        WINDIVERT_LAYER_NETWORK, NULL, 0, &err_str, NULL))
                {
                    warning("failed to verify \"%s\"; filter error \"%s\"",
                        filename, err_str);
                    return false;
                }
                return true;
            }
            case '#':
                space = true;
                while ((c = getc(stream)) != '\n' && c != EOF)
                    ;
                continue;
            case '\n': case '\t': case ' ': case '\r':
                space = true;
                continue;
            default:
                if (space)
                {
                    if (i >= len)
                        goto length_error;
                    filter[i++] = ' ';
                }
                space = false;
                break;
        }
        if (i >= len)
            goto length_error;
        filter[i++] = c;
    }

length_error:

    fclose(stream);
    warning("failed to read \"%s\"; filter length is too long (max=%u)",
        filename, len);
    return false;
}

// Whitelist TOR connections.
static DWORD whitelist_worker(LPVOID arg)
{
    DWORD tor_pid = (DWORD)arg;

    HANDLE handle = WinDivertOpen(
        "tcp and (event == CONNECT or event == CLOSE) and "
        "localAddr != :: and remoteAddr != ::",
        WINDIVERT_LAYER_SOCKET, 12234,
        WINDIVERT_FLAG_RECV_ONLY | WINDIVERT_FLAG_SNIFF);
    HANDLE inject = WinDivertOpen("false", WINDIVERT_LAYER_NETWORK,
        PRIORITY+1, WINDIVERT_FLAG_SEND_ONLY);

    if (handle == INVALID_HANDLE_VALUE || inject == INVALID_HANDLE_VALUE)
    {
        warning("failed to open WinDivert filter");
        exit(EXIT_FAILURE);
    }

    while (true)
    {
        WINDIVERT_ADDRESS addr;
        if (!WinDivertRecv(handle, NULL, 0, NULL, &addr))
            continue;

        uint16_t local_port = htons(addr.Socket.LocalPort);
        switch (addr.Event)
        {
            case WINDIVERT_EVENT_SOCKET_CLOSE:
            {
                // Close an existing connection:
                struct connection *conn = conns + local_port;
                lock(conns_lock);
                if (conn->state == STATE_NOT_CONNECTED ||
                    conn->state == STATE_FIN_WAIT)
                {
                    unlock(conns_lock);
                    continue;
                }
                conn->state = STATE_FIN_WAIT;
                struct syn *syn = conn->syn;
                conn->syn = NULL;
                unlock(conns_lock);
                free(syn);

                struct name *name =
                    domain_lookup_name(addr.Socket.RemoteAddr[0]);
                char local_addr_str[INET4_ADDRSTRLEN];
                WinDivertHelperFormatIPv4Address(addr.Socket.LocalAddr[0],
                    local_addr_str, sizeof(local_addr_str));
                if (name == NULL)
                {
                    char remote_addr_str[INET4_ADDRSTRLEN];
                    WinDivertHelperFormatIPv4Address(addr.Socket.RemoteAddr[0],
                        remote_addr_str, sizeof(remote_addr_str));
                    debug(YELLOW, "DISCONNECT", "%s:%u -/-> %s:%u",
                        local_addr_str, addr.Socket.LocalPort,
                        remote_addr_str, addr.Socket.RemotePort);
                }
                else
                {
                    debug(YELLOW, "DISCONNECT", "%s:%u -/-> %s:%u",
                        local_addr_str, addr.Socket.LocalPort,
                        name->name, addr.Socket.RemotePort);
                    domain_deref(name);
                }
                break;
            }

            case WINDIVERT_EVENT_SOCKET_CONNECT:
                if (addr.Socket.ProcessId == tor_pid)
                {
                    // This is a Tor connect, so whitelist it:
                    pend_connect(inject, local_port, STATE_WHITELISTED);
                }
                else
                {
                    // This connection must be redirected to Tor:
                    pend_connect(inject, local_port, STATE_SYN_WAIT);
                }
                break;

            default:
                break;
        }
    }
}

// Initialize whitelisting.
void redirect_whitelist_init(DWORD tor_pid)
{
    HANDLE worker = CreateThread(NULL, MAX_PACKET*3,
        (LPTHREAD_START_ROUTINE)whitelist_worker, (LPVOID)tor_pid, 0, NULL);
    if (worker == NULL)
    {
        warning("failed to create whitelist worker thread");
        exit(EXIT_FAILURE);
    }
    CloseHandle(worker);
}

