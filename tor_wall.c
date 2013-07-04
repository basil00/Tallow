/*
 * tor_wall.c
 * Copyright (C) 2013, basil
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

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <winsock2.h>
#include <windows.h>

#include "divert.h"

#define STR2(s)             #s
#define STR(s)              STR2(s)

/*
 * Config.
 */
#define PROXY               9049

#define MAX_PACKET          0xFFFF
#define NUM_THREADS         4

/*
 * Error Handling.
 */
#define error(message, ...)                                             \
    do {                                                                \
        SetConsoleTextAttribute(console, FOREGROUND_RED);               \
        fprintf(stderr, "error");                                       \
        SetConsoleTextAttribute(console,                                \
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);       \
        fprintf(stderr, ": " message " [error=%d]\n", ##__VA_ARGS__,    \
            GetLastError());                                            \
        cleanup(0);                                                     \
    } while (false)
#define warning(message, ...)                                           \
    do {                                                                \
        SetConsoleTextAttribute(console,                                \
            FOREGROUND_RED | FOREGROUND_GREEN);                         \
        fprintf(stderr, "warning");                                     \
        SetConsoleTextAttribute(console,                                \
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);       \
        fprintf(stderr, ": " message " [error=%d]\n", ##__VA_ARGS__,    \
            GetLastError());                                            \
    } while (false)

/*
 * DNS related.
 */
struct dnshdr_s
{
    uint16_t id;
    uint16_t option;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__));
typedef struct dnshdr_s *dnshdr_t;

struct dnsq_s
{
    uint16_t type;
    uint16_t class;
} __attribute__((__packed__));
typedef struct dnsq_s *dnsq_t;

struct dnsa_s
{
    uint16_t name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
} __attribute__((__packed__));
typedef struct dnsa_s *dnsa_t;

/*
 * Prototypes.
 */
static void redirect(void);
static DWORD redirect_worker(LPVOID arg);
static void dns_handle_query(HANDLE handle, PDIVERT_ADDRESS addr,
    PDIVERT_IPHDR iphdr, PDIVERT_UDPHDR udphdr, char *data, size_t data_len);
static void cleanup(int sig);

/*
 * Global handles.
 */
static HANDLE console = INVALID_HANDLE_VALUE;
static HANDLE privoxy = INVALID_HANDLE_VALUE;
static HANDLE tor = INVALID_HANDLE_VALUE;

/*
 * Main.
 */
int main(void)
{
    /*
     * Welcome banner.
     */
    console = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(console, FOREGROUND_GREEN);
    printf(" _                           _ _\n");
    printf("| |_ ___  _ ____      ____ _| | |\n");
    printf("| __/ _ \\| '__\\ \\ /\\ / / _` | | |\n");
    printf("| || (_) | |   \\ V  V / (_| | | |\n");
    printf(" \\__\\___/|_|    \\_/\\_/ \\__,_|_|_|\n");
    printf("\n");
    SetConsoleTextAttribute(console,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("TorWall.exe: Copyright (C) 2013, basil\n");
    printf("License GPLv3+: GNU GPL version 3 or later "
        "<http://gnu.org/licenses/gpl.html>.\n");
    printf("This is free software: you are free to change and redistribute "
        "it.\n");
    printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
    SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
    printf(">>> Press CONTROL-C to exit <<<\n\n");
    SetConsoleTextAttribute(console, FOREGROUND_RED);
    printf("WARNING");
    SetConsoleTextAttribute(console,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf(": This is prototype software; use at your own risk!\n\n");

    /*
     * Set-up cleanup.
     */
    signal(SIGINT, cleanup);

    /*
     * Start Privoxy (minimized):
     */
    STARTUPINFO si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_MINIMIZE;
    PROCESS_INFORMATION pi;

    printf("Starting Privoxy...");
    if (!CreateProcess("privoxy.exe", NULL, NULL, NULL, FALSE, 0, NULL,
            NULL, &si, &pi))
        error("failed to start Privoxy");
    privoxy = pi.hProcess;
    printf("Done.\n");

    printf("Starting Tor");
    HANDLE out, in;
    SECURITY_ATTRIBUTES attr;
    memset(&attr, 0, sizeof(attr));
    attr.nLength = sizeof(SECURITY_ATTRIBUTES);
    attr.bInheritHandle = TRUE;
    attr.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&out, &in, &attr, 0))
        error("failed to create pipe");
    if (!SetHandleInformation(out, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
        error("failed to search handle information");
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFO);
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = in;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags = STARTF_USESTDHANDLES;
    if (!CreateProcess("tor.exe", NULL, NULL, NULL, TRUE, 0, NULL,
            NULL, &si, &pi))
        error("failed to start Tor");
    tor = pi.hProcess;

    /*
     * Wait for Tor to start:
     */
    // Crude but effective:
    while (TRUE)
    {
        char buf[BUFSIZ];
        DWORD len;
        if (!ReadFile(out, buf, sizeof(buf)-1, &len, NULL) || len == 0)
            error("failed to read Tor output");
        buf[len] = '\0';
        if (strstr(buf, "Bootstrapped 100%: Done.") != NULL)
            break;
        if (strchr(buf, '%') != NULL)
            putchar('.');
        
    }
    printf("Done.\n");

    /*
     * Re-direct packets:
     */
    redirect();

    cleanup(0);

    return 0;
}

/*
 * Start the packet redirection.
 */
extern void redirect(void)
{
    printf("Starting TorWall...");

    /*
     * We only allow some Tor ports (9001 and 9030) and local traffic.
     * Everything else will be blocked or redirected.
     */
    HANDLE handle = DivertOpen(
        "(ipv6 or ip.DstAddr != 127.0.0.1) and "
        "(not tcp or (tcp and tcp.DstPort != 9001 and "
            "tcp.SrcPort != 9001 and "
            "tcp.DstPort != 9030 and "
            "tcp.SrcPort != 9030))",
        DIVERT_LAYER_NETWORK, -101, 0);
    if (handle == INVALID_HANDLE_VALUE)
        error("failed to open the WinDivert device");

    /*
     * Extra protection against inbound TCP connections using Tor ports:
     */
    HANDLE handle_drop = DivertOpen(
        "inbound and tcp.Syn and tcp.DstPort == " STR(PROXY),
        DIVERT_LAYER_NETWORK, -30, DIVERT_FLAG_DROP);
    if (handle_drop == INVALID_HANDLE_VALUE)
        error("failed to open the WinDivert device");
 
    // Max-out the packet queue:
    if (!DivertSetParam(handle, DIVERT_PARAM_QUEUE_LEN, 8192))
        error("failed to set packet queue length");
    if (!DivertSetParam(handle, DIVERT_PARAM_QUEUE_TIME, 1024))
        error("failed to set packet queue time");
 
    printf("Done.\n");
    printf("TorWall is now running.\n");
 
    // Create worker threads:
    for (size_t i = 0; i < NUM_THREADS-1; i++)
    {
        HANDLE thread = CreateThread(NULL, MAX_PACKET*2,
            (LPTHREAD_START_ROUTINE)redirect_worker, (LPVOID)handle, 0, NULL);
        if (thread == NULL)
            error("failed to start redirect worker thread");
    }
    redirect_worker((LPVOID)handle);
}

/*
 * Packet redirection (worker).
 *
 * TCP:
 *
 * This function implements part of the following traffic flow:
 *
 * +-----------+  (1)   +-----------+  (2)   +-----------+  (3)   +----------+
 * |  BROWSER  |------->|  PRIVOXY  |------->|    TOR    |------->|  SERVER  |
 * |  a.b.c.d  |<-------|  a.b.c.d  |<-------|  a.b.c.d  |<-------|  x.y.z.w |
 * +-----------+  (6)   +-----------+  (5)   +-----------+  (4)   +----------+
 *
 * Specifically, this function implements:
 *   (1) [a.b.c.d:port, x.y.z.w:80]    ---> [x.y.z.w:port, a.b.c.d:PROXY]
 *   (6) [a.b.c.d:PROXY, x.y.z.w:port] ---> [x.y.z.w:80, a.b.c.d:port]
 * where:
 *   a.b.c.d     = local (source) IP address
 *   x.y.z.w     = destination IP address
 *   [src, dest] = a packet.
 *
 * DNS:
 *
 * Since all proxying is transparent, the browser will still issue DNS
 * requests in the usual way.  However the results of these queries are
 * irrelevant: Privoxy retrieves the domain from the Host header and forwards
 * it (via SOCKSv5 and Tor) to the exit node that does the real DNS lookup.
 * To account for this we intercept DNS queries and send fake replies in
 * the 10.x.x.x (local) address block.
 *
 */
static DWORD redirect_worker(LPVOID arg)
{
    HANDLE handle = (HANDLE)arg;

    // Re-direct loop:
    char packet[MAX_PACKET];
    UINT packet_len;
    DIVERT_ADDRESS addr;
    while (true)
    {
        // Process a packet:
        if (!DivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
        {
            warning("failed to redirect packet; divert failed");
            continue;
        }

        SetLastError(0);

        PDIVERT_IPHDR iphdr = NULL;
        PDIVERT_TCPHDR tcphdr = NULL;
        PDIVERT_UDPHDR udphdr = NULL;
        PVOID data = NULL;
        UINT data_len;
        DivertHelperParsePacket(packet, packet_len, &iphdr, NULL, NULL,
            NULL, &tcphdr, &udphdr, &data, &data_len);

        if (iphdr != NULL && udphdr != NULL)
        {
            if (ntohs(udphdr->DstPort) != 53 || data == NULL || data_len == 0)
            {
                // DROP non DNS UDP traffic.
                continue;
            }

            // HANDLE DNS request.
            dns_handle_query(handle, &addr, iphdr, udphdr, data, data_len);
            continue;
        }

        if (iphdr == NULL || tcphdr == NULL)
        {
            // DROP non TCP/IP traffic.
            continue;
        }

        if (addr.Direction == DIVERT_DIRECTION_INBOUND)
        {
            // DROP all in-bound traffic.
            continue;
        }

        if (ntohs(tcphdr->DstPort) == 80)
        {
            // REDIRECT out-bound HTTP traffic to Privoxy:
            uint32_t dst_addr = iphdr->DstAddr;
            iphdr->DstAddr = iphdr->SrcAddr;
            iphdr->SrcAddr = dst_addr;
            tcphdr->DstPort = htons(PROXY);
            addr.Direction = DIVERT_DIRECTION_INBOUND;
        }
        else if (ntohs(tcphdr->SrcPort) == PROXY)
        {
            // REDIRECT out-bound PROXY traffic to HTTP:
            uint32_t dst_addr = iphdr->DstAddr;
            iphdr->DstAddr = iphdr->SrcAddr;
            iphdr->SrcAddr = dst_addr;
            tcphdr->SrcPort = htons(80);
            addr.Direction = DIVERT_DIRECTION_INBOUND;
        }
        else
        {
            // DROP non-HTTP, non-PROXY traffic:
            continue;
        }

        // Re-inject the packet:
        DivertHelperCalcChecksums(packet, packet_len, 0);
        if (!DivertSend(handle, packet, packet_len, &addr, NULL))
            warning("failed to redirect packet; injection failed");
    }
}

/*
 * Send a fake DNS reply for every DNS request.  We can use a fake reply
 * because the domain will be forwarded through SOCKSv5 via Tor, so the
 * value returned is irrelevant.
 */
static void dns_handle_query(HANDLE handle, PDIVERT_ADDRESS addr,
    PDIVERT_IPHDR iphdr, PDIVERT_UDPHDR udphdr, char *data, size_t data_len)
{
    if (data_len <= sizeof(struct dnshdr_s))
        return;
    if (data_len >= 512)
        return;

    dnshdr_t dnshdr = (dnshdr_t)data;
    data += sizeof(struct dnshdr_s);
    data_len -= sizeof(struct dnshdr_s);

    // Check request:
    if (ntohs(dnshdr->option) != 0x0100)
        return;
    if (ntohs(dnshdr->qdcount) != 1)
        return;
    if (ntohs(dnshdr->ancount) != 0)
        return;
    if (ntohs(dnshdr->nscount) != 0)
        return;
    if (ntohs(dnshdr->arcount) != 0)
        return;
    size_t i = 0;
    while (i < data_len && data[i] != 0)
    {
        size_t len = data[i];
        i += len + 1;
    }
    i++;
    if (i >= data_len)
        return;
    if (data_len - i != sizeof(struct dnsq_s))
        return;
    dnsq_t dnsq = (dnsq_t)(data + i);
    if (ntohs(dnsq->type) != 0x0001)
    {
        warning("ignoring DNS type=(0x%.4X) request", ntohs(dnsq->type));
        return;
    }
    if (ntohs(dnsq->class) != 0x0001)
    {
        warning("ignoring DNS class=(0x%.4X) request", ntohs(dnsq->class));
        return;
    }

    // Construct response:
    char buf[1024];
    PDIVERT_IPHDR r_iphdr = (PDIVERT_IPHDR)buf;
    PDIVERT_UDPHDR r_udphdr = (PDIVERT_UDPHDR)(r_iphdr + 1);
    dnshdr_t r_dnshdr = (dnshdr_t)(r_udphdr + 1);
    void *r_data = (void *)(r_dnshdr + 1);

    memset(r_iphdr, 0, sizeof(DIVERT_IPHDR));
    r_iphdr->Version   = 4;
    r_iphdr->HdrLength = sizeof(DIVERT_IPHDR) / sizeof(uint32_t);
    r_iphdr->Id        = (UINT16)rand();
    DIVERT_IPHDR_SET_DF(r_iphdr, 1);
    r_iphdr->TTL       = 32;
    r_iphdr->Protocol  = 17;                // IP_PROTO_UDP
    memcpy(&r_iphdr->SrcAddr, &iphdr->DstAddr, sizeof(r_iphdr->SrcAddr));
    memcpy(&r_iphdr->DstAddr, &iphdr->SrcAddr, sizeof(r_iphdr->DstAddr));

    r_udphdr->SrcPort = htons(53);          // DNS
    r_udphdr->DstPort = udphdr->SrcPort;
    
    r_dnshdr->id      = dnshdr->id;
    r_dnshdr->option  = htons(0x8180);      // Standard DNS response.
    r_dnshdr->qdcount = htons(1);
    r_dnshdr->ancount = htons(1);
    r_dnshdr->nscount = 0;
    r_dnshdr->arcount = 0;

    memcpy(r_data, data, data_len);
    dnsa_t r_dnsa = (dnsa_t)(r_data + data_len);
    r_dnsa->name   = htons(0xC00C);
    r_dnsa->type   = htons(0x0001);         // (A)
    r_dnsa->class  = htons(0x0001);         // (IN)
    r_dnsa->ttl    = htonl(3);              // 3 seconds
    r_dnsa->length = htons(4);

    // Generate a dummy IP address 10.x.x.x
    uint32_t res = 0x0A000000 | ((uint32_t)rand() << 8) | ((uint32_t)rand());
    uint32_t *r_dnsa_res = (uint32_t *)(r_dnsa + 1);
    *r_dnsa_res = htonl(res);

    size_t len = sizeof(DIVERT_IPHDR) + sizeof(DIVERT_UDPHDR) +
        sizeof(struct dnshdr_s) + data_len + sizeof(struct dnsa_s) +
        sizeof(uint32_t);
    r_iphdr->Length = htons((uint16_t)len);
    r_udphdr->Length = htons((uint16_t)len - sizeof(DIVERT_IPHDR));

    // Send response:
    DivertHelperCalcChecksums(buf, len, 0);
    addr->Direction = DIVERT_DIRECTION_INBOUND;
    if (!DivertSend(handle, buf, len, addr, NULL))
        warning("failed to send DNS response; injection failed");
}

/*
 * Clean-up and exit.
 */
static void cleanup(int sig)
{
    printf("Stopping Privoxy...\n");
    if (privoxy != INVALID_HANDLE_VALUE)
        TerminateProcess(privoxy, 0);

    printf("Stopping Tor...\n");
    if (tor != INVALID_HANDLE_VALUE)
        TerminateProcess(tor, 0);

    printf("Finished!\n");
    Sleep(1500);
    exit(EXIT_SUCCESS);
}

