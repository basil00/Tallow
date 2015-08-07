/*
 * redirect.c
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

#include "windivert.h"

#include "domain.h"
#include "main.h"
#include "redirect.h"

#define MAX_PACKET          4096
#define NUM_WORKERS         4
#define MAX_FILTER          (1024-1)

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

// Connections:
#define STATE_NOT_CONNECTED         0
#define STATE_SYN_SEEN              1
#define STATE_SYNACK_SEEN           2
#define STATE_ESTABLISHED           3
#define STATE_FIN_SEEN              4
struct conn
{
    uint16_t port;
    uint8_t state;
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
static void redirect_tcp(HANDLE handle, PWINDIVERT_ADDRESS addr,
    PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr, char *packet,
    size_t packet_len, char *data, size_t data_len);
static void handle_dns(HANDLE handle, PWINDIVERT_ADDRESS addr,
    PWINDIVERT_IPHDR iphdr, PWINDIVERT_UDPHDR udphdr, char *data,
    size_t data_len);
static void socks4a_connect_1_of_2(struct conn *conn, HANDLE handle,
    PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr);
static void socks4a_connect_2_of_2(struct conn *conn, HANDLE handle,
    PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr,
    struct socks4a_rep *sockshdr);
extern bool filter_read(char *filter, size_t len);
static void queue_cleanup(uint32_t addr, uint16_t port);
static void debug_addr(uint32_t addr, uint16_t port);

// State:
static char filter[MAX_FILTER+1];
static bool redirect_on = false;
static HANDLE handle = INVALID_HANDLE_VALUE;
static HANDLE handle_drop = INVALID_HANDLE_VALUE;
static HANDLE workers[NUM_WORKERS] = {NULL};    // Worker threads
static struct conn conns[UINT16_MAX] = {{0}};
static struct cleanup *queue = NULL;            // Cleanup queue.
static struct cleanup *queue_0 = NULL;

// Flush the DNS cache:
static void flush_dns_cache(void)
{
    debug("Flush DNS cache\n");
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

// Send a packet asynchronously:
static void send_packet(HANDLE handle, void *packet, size_t packet_len,
    PWINDIVERT_ADDRESS addr)
{
    addr->Direction = WINDIVERT_DIRECTION_INBOUND;
    WinDivertHelperCalcChecksums(packet, packet_len, 0);
    if (!WinDivertSend(handle, packet, packet_len, addr, NULL))
        debug("Send packet failed (err=%d)\n", (int)GetLastError());
}

// Init this module:
extern void redirect_init(void)
{
    // Stop external connections to Tor:
    HANDLE handle = WinDivertOpen(
        "inbound and tcp.DstPort == " STR(TOR_PORT),
        WINDIVERT_LAYER_NETWORK, -755, WINDIVERT_FLAG_DROP);
    if (handle == INVALID_HANDLE_VALUE)
    {
redirect_init_error:
        warning("failed to open WinDivert filter");
        exit(EXIT_FAILURE);
    }

    // Prevent "fake" IPs leaking to the internet (which may indicate the use
    // of this program):
    handle = WinDivertOpen(
        "outbound and ip.DstAddr >= " STR(ADDR_BASE) " and ip.DstAddr <= "
            STR(ADDR_MAX),
        WINDIVERT_LAYER_NETWORK, 755, WINDIVERT_FLAG_DROP);
    if (handle == INVALID_HANDLE_VALUE)
        goto redirect_init_error;

    // Read the filter:
    if (!filter_read(filter, sizeof(filter)))
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
    debug("Filter is \"%s\"\n", filter);
}

// Start traffic redirect through Tor:
extern void redirect_start(void)
{
    debug("Tor divert START\n");

    if (handle != INVALID_HANDLE_VALUE)
        return;

    // Drop traffic from the loaded filter:
    handle_drop = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, -753,
        WINDIVERT_FLAG_DROP);
    if (handle_drop == INVALID_HANDLE_VALUE)
    {
redirect_start_error:
        warning("failed to open WinDivert filter");
        exit(EXIT_FAILURE);
    }

    handle = WinDivertOpen(
        "(ipv6 or ip.DstAddr != 127.0.0.1) and "
        "(not tcp or (tcp and tcp.DstPort != 9001 and "
            "tcp.SrcPort != 9001 and "
            "tcp.DstPort != 9030 and "
            "tcp.SrcPort != 9030))",
        WINDIVERT_LAYER_NETWORK, -752, 0);
    if (handle == INVALID_HANDLE_VALUE)
        goto redirect_start_error;

    flush_dns_cache();

    // Max-out the packet queue:
    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192);
    WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);

    // Launch threads:
    redirect_on = true;
    memset(conns, 0, sizeof(conns));
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
    debug("Tor divert STOP\n");

    if (handle == INVALID_HANDLE_VALUE)
        return;

    // Close the WinDivert handle; will cause the workers to exit.
    redirect_on = false;
    if (!WinDivertClose(handle) || !WinDivertClose(handle_drop))
    {
        warning("failed to close WinDivert filter");
        exit(EXIT_FAILURE);
    }
    handle = INVALID_HANDLE_VALUE;
    handle_drop = INVALID_HANDLE_VALUE;

    for (size_t i = 0; i < NUM_WORKERS; i++)
    {
        WaitForSingleObject(workers[i], INFINITE);
        workers[i] = NULL;
    }

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

    while (redirect_on)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
        {
            // Silently ignore any error.
            continue;
        }

        PWINDIVERT_IPHDR iphdr = NULL;
        PWINDIVERT_TCPHDR tcphdr = NULL;
        PWINDIVERT_UDPHDR udphdr = NULL;
        PVOID data = NULL;
        UINT data_len;
        WinDivertHelperParsePacket(packet, packet_len, &iphdr, NULL, NULL,
            NULL, &tcphdr, &udphdr, &data, &data_len);

        if (addr.Direction == WINDIVERT_DIRECTION_INBOUND)
        {
            // All inbound traffic is dropped:
            continue;
        }
        if (udphdr != NULL && ntohs(udphdr->DstPort) == 53)
            handle_dns(handle, &addr, iphdr, udphdr, data, data_len);
        else if (tcphdr != NULL)
            redirect_tcp(handle, &addr, iphdr, tcphdr, packet, packet_len,
                data, data_len);
    }
    return 0;
}

// Redirect TCP:
static void redirect_tcp(HANDLE handle, PWINDIVERT_ADDRESS addr,
    PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr, char *packet,
    size_t packet_len, char *data, size_t data_len)
{
    struct conn *conn;

    bool drop = false;
    uint16_t port;
    if (ntohs(tcphdr->SrcPort) == TOR_PORT)
    {
        // Tor ---> PC
        port = tcphdr->DstPort;
        conn = conns + port;

        switch (conn->state)
        {
            case STATE_NOT_CONNECTED:
                return;
            case STATE_SYN_SEEN:
                if (!tcphdr->Syn || !tcphdr->Ack)
                {
                    drop = true;
                    break;
                }

                // SYN-ACK
                socks4a_connect_1_of_2(conn, handle, addr, iphdr,
                    tcphdr);
                conn->state = STATE_SYNACK_SEEN;
                return;
            
            case STATE_SYNACK_SEEN:
                if (data_len != sizeof(struct socks4a_rep))
                {
                    drop = true;
                    break;
                }
                conn->state = STATE_ESTABLISHED;
                struct socks4a_rep *rep = (struct socks4a_rep *)data;
                socks4a_connect_2_of_2(conn, handle, addr, iphdr, tcphdr, rep);
                return;

            default:
                break;
        }

        tcphdr->SrcPort = conn->port;
    }
    else
    {
        // PC ---> Tor
        port = tcphdr->SrcPort;
        conn = conns + port;

        switch (conn->state)
        {
            case STATE_SYN_SEEN:
            case STATE_SYNACK_SEEN:
                drop = true;
                break;

            case STATE_NOT_CONNECTED:
                if (tcphdr->Syn && !tcphdr->Ack && !tcphdr->Fin &&
                    !tcphdr->Rst)
                {
                    // SYN
                    uint16_t dstport = ntohs(tcphdr->DstPort);
                    if (option_force_web_only &&
                        dstport != 80 &&            // HTTP
                        dstport != 443)             // HTTPS
                    {
                        uint32_t srcaddr = ntohl(iphdr->SrcAddr);
                        debug("Ignoring non-web connect %u.%u.%u.%u:%u ---> ",
                            ADDR0(srcaddr), ADDR1(srcaddr), ADDR2(srcaddr),
                            ADDR3(srcaddr), ntohs(tcphdr->SrcPort));
                        debug_addr(ntohl(iphdr->DstAddr), dstport);

                        drop = true;
                        break;
                    }

                    tcphdr->SeqNum = htonl(ntohl(tcphdr->SeqNum) -
                        sizeof(struct socks4a_req));
                    conn->state = STATE_SYN_SEEN;
                    conn->port  = tcphdr->DstPort;
                    queue_cleanup(ntohl(iphdr->DstAddr), port);
                    break;
                }
                return;
            
            default:
                break;
        }

        tcphdr->DstPort = htons(TOR_PORT);
    }

    if (conn->state != STATE_FIN_SEEN && (tcphdr->Fin || tcphdr->Rst))
    {
        drop = false;
        conn->state = STATE_FIN_SEEN;
        queue_cleanup((ntohs(tcphdr->SrcPort) == TOR_PORT?
            ntohl(iphdr->SrcAddr): ntohl(iphdr->DstAddr)), port);
    }

    if (!drop)
    {
        uint32_t dst_addr = iphdr->DstAddr;
        iphdr->DstAddr = iphdr->SrcAddr;
        iphdr->SrcAddr = dst_addr;
        send_packet(handle, packet, packet_len, addr);
    }
}

// Glue a normal TCP conn to SOCKS4a
static void socks4a_connect_1_of_2(struct conn *conn, HANDLE handle,
    PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr)
{
    uint32_t srcaddr = ntohl(iphdr->SrcAddr), dstaddr = ntohl(iphdr->DstAddr);
    struct name *name = domain_lookup_name(dstaddr);
    if (name == NULL && option_force_socks4a)
    {
        debug("Ignoring non-SOCKs4a connect %u.%u.%u.%u:%u ---> "
                "%u.%u.%u.%u:%u\n",
            ADDR0(srcaddr), ADDR1(srcaddr), ADDR2(srcaddr), ADDR3(srcaddr),
            ntohs(tcphdr->DstPort),
            ADDR0(dstaddr), ADDR1(dstaddr), ADDR2(dstaddr), ADDR3(dstaddr),
            ntohs(conn->port));

        // No corresponding name -- ignore
        return;
    }
    if (name == NULL && !is_fake_addr(dstaddr))
    {
        debug("Ignoring stale connect %u.%u.%u.%u:%u ---> "
                "%u.%u.%u.%u:%u\n",
            ADDR0(srcaddr), ADDR1(srcaddr), ADDR2(srcaddr), ADDR3(srcaddr),
            ntohs(tcphdr->DstPort),
            ADDR0(dstaddr), ADDR1(dstaddr), ADDR2(dstaddr), ADDR3(dstaddr),
            ntohs(conn->port));

        // Address is stale -- ignore
        return;
    }
    
    // ACK to complete 3-way handshake (Tor-side):
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
    ack.iphdr.SrcAddr = iphdr->DstAddr;
    ack.iphdr.DstAddr = iphdr->SrcAddr;

    memset(&ack.tcphdr, 0, sizeof(ack.tcphdr));
    ack.tcphdr.SrcPort = tcphdr->DstPort;
    ack.tcphdr.DstPort = tcphdr->SrcPort;
    ack.tcphdr.SeqNum = tcphdr->AckNum;
    ack.tcphdr.AckNum = htonl(ntohl(tcphdr->SeqNum) + 1);
    ack.tcphdr.HdrLength = sizeof(ack.tcphdr) / sizeof(uint32_t);
    ack.tcphdr.Ack = 1;
    ack.tcphdr.Window = htons(8192);

    send_packet(handle, &ack, sizeof(ack), addr);

    // SOCKS4a CONNECT request:
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
    req.iphdr.SrcAddr = iphdr->DstAddr;
    req.iphdr.DstAddr = iphdr->SrcAddr;

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
    req.sockshdr.dst_port = conn->port;

    if (name != NULL)
    {
        debug("Connect %u.%u.%u.%u:%u ---> %s:%u\n",
            ADDR0(srcaddr), ADDR1(srcaddr), ADDR2(srcaddr), ADDR3(srcaddr),
            ntohs(tcphdr->DstPort), name->name, ntohs(conn->port));
        
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
        debug("Connect %u.%u.%u.%u:%u ---> %u.%u.%u.%u:%u\n",
            ADDR0(srcaddr), ADDR1(srcaddr), ADDR2(srcaddr), ADDR3(srcaddr),
            ntohs(tcphdr->DstPort),
            ADDR0(dstaddr), ADDR1(dstaddr), ADDR2(dstaddr), ADDR3(dstaddr),
            ntohs(conn->port));

        req.sockshdr.dst_addr = iphdr->DstAddr;

        // SOCKS4 direct connection:
        for (size_t i = 0; i < SOCKS_USERID_SIZE - 1; i++)
            req.sockshdr.userid[i] = '4';
    }
    req.sockshdr.userid[SOCKS_USERID_SIZE-1] = '\0';

    send_packet(handle, &req, sizeof(req), addr);
}

static void socks4a_connect_2_of_2(struct conn *conn, HANDLE handle,
    PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR iphdr, PWINDIVERT_TCPHDR tcphdr,
    struct socks4a_rep *sockshdr)
{
    if (sockshdr->vn != 0 || sockshdr->cd != 0x5A)
    {
        // Something went wrong; close the connnection:
        struct
        {
            WINDIVERT_IPHDR iphdr;
            WINDIVERT_TCPHDR tcphdr;
        } rst;

        memset(&rst.iphdr, 0, sizeof(rst.iphdr));
        rst.iphdr.Version = 4;
        rst.iphdr.HdrLength = sizeof(rst.iphdr) / sizeof(uint32_t);
        rst.iphdr.Id = htons(0xF003);
        WINDIVERT_IPHDR_SET_DF(&rst.iphdr, 1);
        rst.iphdr.Length = htons(sizeof(rst));
        rst.iphdr.TTL = 64;
        rst.iphdr.Protocol = IPPROTO_TCP;
        rst.iphdr.SrcAddr = iphdr->DstAddr;
        rst.iphdr.DstAddr = iphdr->SrcAddr;

        memset(&rst.tcphdr, 0, sizeof(rst.tcphdr));
        rst.tcphdr.SrcPort = conn->port;
        rst.tcphdr.DstPort = tcphdr->DstPort;
        rst.tcphdr.SeqNum = htonl(0);
        rst.tcphdr.AckNum = tcphdr->AckNum;
        rst.tcphdr.HdrLength = sizeof(rst.tcphdr) / sizeof(uint32_t);
        rst.tcphdr.Rst = 1;

        send_packet(handle, &rst, sizeof(rst), addr);
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
    synack.iphdr.SrcAddr = iphdr->DstAddr;
    synack.iphdr.DstAddr = iphdr->SrcAddr;

    memset(&synack.tcphdr, 0, sizeof(synack.tcphdr));
    synack.tcphdr.SrcPort = conn->port;
    synack.tcphdr.DstPort = tcphdr->DstPort;
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
        if (i + len >= DNS_MAX_NAME)
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

    debug("Intercept DNS %s\n", (name[0] == '.'? name+1: name));

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

// Queue a cleanup operation.
static void queue_cleanup(uint32_t addr, uint16_t port)
{
    struct cleanup *entry = (struct cleanup *)malloc(
        sizeof(struct cleanup));
    if (entry == NULL)
    {
        warning("failed to allocate %u bytes for cleanup entry",
            sizeof(struct cleanup));
        exit(EXIT_FAILURE);
    }
    entry->addr = addr;
    entry->port = port;

    while (true)
    {
        entry->next = queue;
        if (InterlockedCompareExchangePointer((PVOID *)&queue, (PVOID)entry,
                (PVOID)entry->next) == entry->next)
            break;
    }
}

// Cleanup stale connections.
extern void redirect_cleanup(size_t count)
{
    if (count % 2 != 0)
        return;

    struct cleanup *q0 = (struct cleanup *)InterlockedExchangePointer(
        (PVOID)&queue, NULL);
    struct cleanup *q = queue_0;
    queue_0 = q0;

    while (q != NULL)
    {
        struct conn *conn = conns + q->port;
        if (conn->state != STATE_ESTABLISHED &&
            conn->state != STATE_NOT_CONNECTED)
        {
            debug("Cleanup %s connection ",
                (conn->state == STATE_FIN_SEEN? "closed": "stalled"));
            debug_addr(q->addr, conn->port);
            conn->state = STATE_NOT_CONNECTED;
            conn->port = 0;
        }
        q0 = q;
        q = q->next;
        free(q0);
    }
}

// Read traffic filter.
extern bool filter_read(char *filter, size_t len)
{
    const char *filename = "traffic.deny";
    FILE *stream = fopen(filename, "r");
    if (stream == NULL)
    {
        warning("failed to read \"%s\" for reading", filename);
        return false;
    }
    
    int c;
    size_t i = 0;
    while (true)
    {
        c = getc(stream);
        switch (c)
        {
            case EOF:
            {
                if (i >= len)
                    goto length_error;
                filter[i++] = '\0';
                fclose(stream);

                // Check the filter for errors:
                const char *err_str;
                if (!WinDivertHelperCheckFilter(filter,
                        WINDIVERT_LAYER_NETWORK, &err_str, NULL))
                {
                    warning("failed to verify \"%s\"; filter error \"%s\"",
                        filename, err_str);
                    return false;
                }
                return true;
            }
            case '#':
                while ((c = getc(stream)) != '\n' && c != EOF)
                    ;
                continue;
            case '\n':
                continue;
            default:
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

// Debug address:
static void debug_addr(uint32_t addr, uint16_t port)
{
    struct name *name = domain_lookup_name(addr);
    if (name != NULL)
    {
        debug("%s:%u\n", name->name, ntohs(port));
        domain_deref(name);
    }
    else
        debug("%u.%u.%u.%u:%u\n",
            ADDR0(addr), ADDR1(addr), ADDR2(addr),
            ADDR3(addr), ntohs(port));
}

