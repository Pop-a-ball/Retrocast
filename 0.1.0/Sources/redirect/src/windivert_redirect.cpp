// WinDivert redirect to localhost:8080
// Redirects all outbound HTTP(S) traffic (ports 80, 443) to mitmproxy on 127.0.0.1:8080
// Requires: WinDivert.dll in System32 or same directory, admin rights
// Usage: WinDivert_redirect.exe

#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <unordered_set>
#include <string>
#include <cctype>
#include <algorithm>


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// WinDivert types and constants
typedef void* HANDLE;
#pragma pack(push, 1)
typedef struct WINDIVERT_ADDRESS {
    UINT32 IfIdx;
    UINT32 SubIfIdx;
    UINT8 Direction;
    UINT8 Impostor;
    UINT8 PseudoIPChecksum;
    UINT8 PseudoTcpChecksum;
} WINDIVERT_ADDRESS;
#pragma pack(pop)
#define WINDIVERT_LAYER_NETWORK 0
#define WINDIVERT_LAYER_NETWORK_FORWARD 1

typedef HANDLE(__stdcall *PWinDivertOpen)(const char *filter, int layer, short priority, UINT64 flags);
typedef BOOL(__stdcall *PWinDivertRecv)(HANDLE handle, void *pPacket, UINT packetLen, UINT *readLen, void *pAddr);
typedef BOOL(__stdcall *PWinDivertSend)(HANDLE handle, void *pPacket, UINT packetLen, UINT *writeLen, void *pAddr);
typedef BOOL(__stdcall *PWinDivertClose)(HANDLE handle);
typedef BOOL(__stdcall *PWinDivertHelperCalcChecksums)(void *pPacket, UINT packetLen, void *pAddr, UINT flags);

// IPv4 header
struct IPHDR {
    UINT8 HdrLen:4, Version:4;
    UINT8 TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff:13, Flags:3;
    UINT8 TTL;
    UINT8 Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
};

// TCP header
struct TCPHDR {
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT32 SeqNum;
    UINT32 AckNum;
    UINT8 Reserved:4, HdrLen:4;
    UINT8 Flags;
    UINT16 Window;
    UINT16 Checksum;
    UINT16 Urgent;
};

static PWinDivertOpen WinDivertOpen = nullptr;
static PWinDivertRecv WinDivertRecv = nullptr;
static PWinDivertSend WinDivertSend = nullptr;
static PWinDivertClose WinDivertClose = nullptr;
static PWinDivertHelperCalcChecksums WinDivertHelperCalcChecksums = nullptr;

// Exclusion set: local (addr,port) tuples owned by mitmproxy process(es)
static CRITICAL_SECTION g_excl_cs;
static std::unordered_set<uint64_t> g_excluded_local; // key = (uint64_t)addr<<16 | port
static volatile BOOL g_refresh_thread_running = TRUE;
static std::vector<std::string> g_excluded_proc_names;
static std::unordered_set<uint16_t> g_excluded_local_ports;

static std::vector<DWORD> get_pids_by_name(const char *name) {
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            // compare case-insensitive
            if (_stricmp(pe.szExeFile, name) == 0) {
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}

static void load_exclusions_from_file() {
    const char *cfg = "prototype/config/proxy_exclusions.txt";
    FILE *f = fopen(cfg, "r");
    if (!f) return;
    char line[512];
    std::vector<std::string> proc_names;
    std::unordered_set<uint16_t> ports;
    while (fgets(line, sizeof(line), f)) {
        // trim
        char *s = line;
        while (*s && isspace((unsigned char)*s)) s++;
        if (*s == '\0' || *s == '#' || *s == ';') continue;
        // strip newline
        char *e = s + strlen(s) - 1;
        while (e >= s && (e[0] == '\n' || e[0] == '\r' || isspace((unsigned char)e[0]))) { *e = '\0'; e--; }
        if (strncmp(s, "process=", 8) == 0) {
            char *p = s + 8;
            if (*p) proc_names.emplace_back(p);
        } else if (strncmp(s, "port=", 5) == 0) {
            char *p = s + 5;
            int v = atoi(p);
            if (v > 0 && v <= 65535) ports.insert((uint16_t)v);
        } else {
            // allow bare process names
            proc_names.emplace_back(s);
        }
    }
    fclose(f);

    // Swap into globals
    EnterCriticalSection(&g_excl_cs);
    g_excluded_proc_names.swap(proc_names);
    g_excluded_local_ports.swap(ports);
    LeaveCriticalSection(&g_excl_cs);
}

static void refresh_excluded_sockets_once() {
    // Collect PIDs for configured process names
    std::vector<DWORD> pids;
    EnterCriticalSection(&g_excl_cs);
    std::vector<std::string> proc_names = g_excluded_proc_names;
    LeaveCriticalSection(&g_excl_cs);
    for (const auto &name : proc_names) {
        std::vector<DWORD> found = get_pids_by_name(name.c_str());
        pids.insert(pids.end(), found.begin(), found.end());
    }

    // Build a set of PIDs for quick lookup
    std::unordered_set<DWORD> pidset;
    for (DWORD pid : pids) pidset.insert(pid);

    // Query TCP table
    PMIB_TCPTABLE_OWNER_PID table = NULL;
    DWORD size = 0;
    DWORD rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER) return;
    table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return;
    rc = GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != NO_ERROR) {
        free(table);
        return;
    }

    // Rebuild excluded set
    std::unordered_set<uint64_t> newset;
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID row = table->table[i];
        if (pidset.find(row.dwOwningPid) != pidset.end()) {
            uint32_t addr = row.dwLocalAddr; // network order
            uint16_t port = ntohs((u_short)row.dwLocalPort);
            uint64_t key = ((uint64_t)addr << 16) | (uint64_t)port;
            newset.insert(key);
        }
    }
    free(table);

    // Swap in atomically
    EnterCriticalSection(&g_excl_cs);
    g_excluded_local.swap(newset);
    LeaveCriticalSection(&g_excl_cs);
}

static DWORD WINAPI refresh_thread(LPVOID param) {
    (void)param;
    while (g_refresh_thread_running) {
        refresh_excluded_sockets_once();
        Sleep(2000);
    }
    return 0;
}

static bool is_excluded_local(uint32_t addr_netorder, uint16_t port_hostorder) {
    uint64_t key = ((uint64_t)addr_netorder << 16) | (uint64_t)port_hostorder;
    bool found = false;
    EnterCriticalSection(&g_excl_cs);
    found = (g_excluded_local.find(key) != g_excluded_local.end());
    if (!found && g_excluded_local_ports.find(port_hostorder) != g_excluded_local_ports.end()) found = true;
    LeaveCriticalSection(&g_excl_cs);
    return found;
}

// Global state for packet redirect logic
struct RedirectContext {
    HANDLE divert_handle;
    const char *layer_name;
    volatile LONG packet_count;
};

// Worker thread function for processing packets from a single handle
DWORD WINAPI packet_worker_thread(LPVOID param) {
    RedirectContext *ctx = (RedirectContext *)param;
    
    UINT8 packet[65535];
    UINT readLen = 0;
    unsigned char addr_buf[128];
    void *addr = addr_buf;
    
    printf("[%s Layer] Worker thread started.\n", ctx->layer_name);
    
    while (TRUE) {
        memset(addr_buf, 0, sizeof(addr_buf));
        
        if (WinDivertRecv(ctx->divert_handle, packet, sizeof(packet), &readLen, addr)) {
            // Parse packet
            IPHDR *ip_hdr = (IPHDR *)packet;
            
            // Check if it's IPv4 and TCP
            if (ip_hdr->Version == 4 && ip_hdr->Protocol == IPPROTO_TCP) {
                TCPHDR *tcp_hdr = (TCPHDR *)((UINT8 *)ip_hdr + (ip_hdr->HdrLen * 4));
                UINT16 dst_port = ntohs(tcp_hdr->DstPort);

                // Check if destination port is 80 or 443
                if (dst_port == 80 || dst_port == 443) {
                    // If this packet originates from a local socket owned by mitmproxy, skip redirect
                    uint32_t src_addr = ip_hdr->SrcAddr; // network order
                    uint16_t src_port_host = ntohs(tcp_hdr->SrcPort);
                    if (is_excluded_local(src_addr, src_port_host)) {
                        // pass-through unchanged
                        UINT writeLen = 0;
                        if (!WinDivertSend(ctx->divert_handle, packet, readLen, &writeLen, addr)) {
                            DWORD err = GetLastError();
                            printf("[%s] ERROR: WinDivertSend pass-through failed (error: %lu)\n", ctx->layer_name, err);
                        }
                        continue;
                    }

                    UINT32 old_dst = ip_hdr->DstAddr;
                    UINT16 old_port = tcp_hdr->DstPort;

                    // Log a small snippet of the TCP payload (useful for SNI/ClientHello inspection)
                    UINT ip_hdr_len = (ip_hdr->HdrLen * 4);
                    UINT tcp_hdr_len = ((tcp_hdr->HdrLen) * 4);
                    UINT payload_offset = ip_hdr_len + tcp_hdr_len;
                    UINT payload_len = (readLen > payload_offset) ? (readLen - payload_offset) : 0;
                    if (payload_len > 0) {
                        UINT snip = payload_len > 512 ? 512 : payload_len;
                        unsigned char *payload_ptr = packet + payload_offset;

                        // Build a printable snippet and a lowercase text buffer for simple OCSP/CRL detection
                        char printable[520];
                        char lower[520];
                        int bi = 0;
                        for (UINT i = 0; i < snip && bi < (int)sizeof(printable)-4; i++) {
                            unsigned char c = payload_ptr[i];
                            // printable representation
                            if (c >= 32 && c <= 126) {
                                printable[bi] = c;
                            } else if (c == '\n' || c == '\r' || c == '\t') {
                                printable[bi] = ' ';
                            } else {
                                printable[bi] = '.';
                            }
                            // lowercase copy for simple substring search
                            if (c >= 'A' && c <= 'Z') lower[bi] = (char)(c - 'A' + 'a'); else lower[bi] = (char)c;
                            bi++;
                        }
                        printable[bi] = '\0';
                        lower[bi] = '\0';

                        printf("[%s] Payload snippet (len=%u): %s\n", ctx->layer_name, payload_len, printable);

                        // Simple detection: if payload contains 'ocsp' or '.crl', treat as revocation traffic and do not redirect
                        if (strstr(lower, "ocsp") != NULL || strstr(lower, ".crl") != NULL) {
                            // pass-through unchanged
                            UINT writeLen = 0;
                            if (!WinDivertSend(ctx->divert_handle, packet, readLen, &writeLen, addr)) {
                                DWORD err = GetLastError();
                                printf("[%s] ERROR: WinDivertSend pass-through failed for revocation packet (error: %lu)\n", ctx->layer_name, err);
                            }
                            continue;
                        }
                    }

                    // Redirect to localhost:8080
                    ip_hdr->DstAddr = htonl(0x7F000001);  // 127.0.0.1
                    tcp_hdr->DstPort = htons(8080);

                    // Recalculate checksums
                    ip_hdr->Checksum = 0;
                    tcp_hdr->Checksum = 0;
                    if (WinDivertHelperCalcChecksums) {
                        WinDivertHelperCalcChecksums(packet, readLen, addr, 0);
                    }

                    // Send modified packet
                    UINT writeLen = 0;
                    if (WinDivertSend(ctx->divert_handle, packet, readLen, &writeLen, addr)) {
                        InterlockedIncrement(&ctx->packet_count);
                        if (ctx->packet_count % 20 == 0) {
                            printf("[%s] [%ld] Redirected: %u.%u.%u.%u:%u -> 127.0.0.1:8080\n",
                                   ctx->layer_name,
                                   ctx->packet_count,
                                   (old_dst >> 0) & 0xFF,
                                   (old_dst >> 8) & 0xFF,
                                   (old_dst >> 16) & 0xFF,
                                   (old_dst >> 24) & 0xFF,
                                   ntohs(old_port));
                        }
                    } else {
                        DWORD err = GetLastError();
                        printf("[%s] ERROR: WinDivertSend failed (error: %lu). Packet dropped.\n", ctx->layer_name, err);
                    }
                } else {
                    // Not port 80/443, pass through
                    UINT writeLen = 0;
                    if (!WinDivertSend(ctx->divert_handle, packet, readLen, &writeLen, addr)) {
                        DWORD err = GetLastError();
                        printf("[%s] ERROR: WinDivertSend failed for pass-through packet (port %u) (error: %lu)\n", 
                               ctx->layer_name, dst_port, err);
                    }
                }
            } else {
                // Not IPv4 TCP, pass through
                UINT writeLen = 0;
                if (!WinDivertSend(ctx->divert_handle, packet, readLen, &writeLen, addr)) {
                    DWORD err = GetLastError();
                    printf("[%s] ERROR: WinDivertSend failed for non-IPv4-TCP packet (error: %lu)\n", ctx->layer_name, err);
                }
            }
        }
    }
    
    return 0;
}

static BOOL load_windivert_dll() {
    HMODULE h = LoadLibraryA("WinDivert.dll");
    if (!h) {
        printf("ERROR: WinDivert.dll not found. Make sure WinDivert is installed or the DLL is in System32.\n");
        return FALSE;
    }

    WinDivertOpen = (PWinDivertOpen)GetProcAddress(h, "WinDivertOpen");
    WinDivertRecv = (PWinDivertRecv)GetProcAddress(h, "WinDivertRecv");
    WinDivertSend = (PWinDivertSend)GetProcAddress(h, "WinDivertSend");
    WinDivertClose = (PWinDivertClose)GetProcAddress(h, "WinDivertClose");
    WinDivertHelperCalcChecksums = (PWinDivertHelperCalcChecksums)GetProcAddress(h, "WinDivertHelperCalcChecksums");

    if (!WinDivertOpen || !WinDivertRecv || !WinDivertSend || !WinDivertClose) {
        printf("ERROR: WinDivert.dll missing required exports.\n");
        return FALSE;
    }

    printf("WinDivert.dll loaded successfully.\n");
    return TRUE;
}

int main() {
    printf("WinDivert Redirect to mitmproxy (localhost:8080)\n");
    printf("================================================\n");

    if (!load_windivert_dll()) {
        return 1;
    }

    // Filter: outbound TCP traffic to ports 80 and 443 (HTTP and HTTPS)
    const char *filter = "(outbound && tcp.DstPort == 80) || (outbound && tcp.DstPort == 443)";
    
    // Open NETWORK layer handle (local traffic)
    printf("Opening WinDivert NETWORK layer with filter: %s\n", filter);
    HANDLE handle_network = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (!handle_network || handle_network == INVALID_HANDLE_VALUE) {
        printf("ERROR: WinDivertOpen (NETWORK) failed. Make sure you're running as admin.\n");
        return 1;
    }
    printf("NETWORK layer handle opened successfully.\n");

    // Try to open NETWORK_FORWARD layer handle (hotspot/forwarded traffic)
    // This is optional - if it fails, we continue with just NETWORK layer
    printf("Attempting to open WinDivert NETWORK_FORWARD layer...\n");
    HANDLE handle_forward = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK_FORWARD, 0, 0);
    BOOL has_forward = FALSE;
    if (handle_forward && handle_forward != INVALID_HANDLE_VALUE) {
        printf("NETWORK_FORWARD layer handle opened successfully.\n");
        has_forward = TRUE;
    } else {
        DWORD err = GetLastError();
        printf("NOTE: NETWORK_FORWARD layer unavailable (error: %lu). Continuing with NETWORK layer only.\n", err);
        printf("      (This is normal on some WinDivert versions or configurations)\n");
    }
    printf("\n");

    printf("Starting redirect loop%s...\n", has_forward ? "s" : "");
    printf("All HTTP(S) traffic will be redirected to 127.0.0.1:8080\n");
    printf("Press Ctrl+C to stop.\n\n");

    // Initialize exclusion data
    InitializeCriticalSection(&g_excl_cs);
    // Load configured exclusions if present
    load_exclusions_from_file();
    HANDLE hrefresh = CreateThread(NULL, 0, refresh_thread, NULL, 0, NULL);
    if (!hrefresh) {
        printf("WARNING: failed to start refresh thread for excluded sockets.\n");
    }

    // Create worker thread for NETWORK layer
    RedirectContext ctx_network = { handle_network, "NETWORK", 0 };
    HANDLE thread_network = CreateThread(
        NULL, 0, packet_worker_thread, &ctx_network, 0, NULL
    );

    if (!thread_network) {
        printf("ERROR: Failed to create NETWORK worker thread.\n");
        WinDivertClose(handle_network);
        if (has_forward) WinDivertClose(handle_forward);
        return 1;
    }

    // Create worker thread for NETWORK_FORWARD layer if available
    HANDLE thread_forward = NULL;
    RedirectContext ctx_forward = { NULL, "", 0 };
    if (has_forward) {
        ctx_forward.divert_handle = handle_forward;
        ctx_forward.layer_name = "FORWARD";
        thread_forward = CreateThread(
            NULL, 0, packet_worker_thread, &ctx_forward, 0, NULL
        );

        if (!thread_forward) {
            printf("ERROR: Failed to create FORWARD worker thread.\n");
            WinDivertClose(handle_network);
            WinDivertClose(handle_forward);
            return 1;
        }
    }

    // Wait for threads (they run indefinitely until Ctrl+C)
    WaitForSingleObject(thread_network, INFINITE);
    if (thread_forward) {
        WaitForSingleObject(thread_forward, INFINITE);
    }

    WinDivertClose(handle_network);
    if (has_forward) WinDivertClose(handle_forward);
    printf("WinDivert closed.\n");
    return 0;
}
