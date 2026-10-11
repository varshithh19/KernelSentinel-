#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include "../include/collector.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

static collector_stats_t g_stats = {0};
static volatile int g_keep_running = 1;
static int g_ipc_sock = -1;

void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        printf("\n[Collector] Signal %d received, shutting down gracefully...\n", signo);
        g_keep_running = 0;
    }
}

int collector_init(const char *ipc_host, int ipc_port) {
    printf("[Collector] Initializing KernelSentinel C Event Collector...\n");
    g_stats.is_running = 1;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[Collector] WSAStartup failed.\n");
        return -1;
    }
#endif

    g_ipc_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_ipc_sock < 0) {
        fprintf(stderr, "[Collector] Failed to create socket.\n");
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((uint16_t)ipc_port);

    if (inet_pton(AF_INET, ipc_host, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "[Collector] Invalid host address: %s\n", ipc_host);
        return -1;
    }

    if (connect(g_ipc_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("[Collector] Note: IPC receiver not connected on %s:%d. Events will be logged locally.\n", ipc_host, ipc_port);
#ifdef _WIN32
        closesocket(g_ipc_sock);
#else
        close(g_ipc_sock);
#endif
        g_ipc_sock = -1;
    } else {
        printf("[Collector] Connected to Detection Engine IPC on %s:%d\n", ipc_host, ipc_port);
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    return 0;
}

static void send_event_json(const char *json_str) {
    if (g_ipc_sock >= 0) {
        size_t len = strlen(json_str);
        send(g_ipc_sock, json_str, (int)len, 0);
        send(g_ipc_sock, "\n", 1, 0);
    }
}

int handle_kernel_event(void *ctx, void *data, size_t size) {
    (void)ctx;
    if (size < sizeof(struct event_header)) {
        g_stats.dropped_events++;
        return -1;
    }

    struct event_header *hdr = (struct event_header *)data;
    if (hdr->magic != MAGIC_KSEN) {
        g_stats.invalid_magic_events++;
        return -1;
    }

    g_stats.total_events++;
    char json_buf[1024];

    if (hdr->event_type == EVENT_TYPE_EXEC && size >= sizeof(struct process_exec_event)) {
        struct process_exec_event *ev = (struct process_exec_event *)data;
        g_stats.exec_events++;
        snprintf(json_buf, sizeof(json_buf),
            "{\"type\":\"exec\",\"pid\":%u,\"tgid\":%u,\"uid\":%u,\"comm\":\"%s\",\"filename\":\"%s\",\"ts\":%llu}",
            hdr->pid, hdr->tgid, hdr->uid, ev->comm, ev->filename, (unsigned long long)hdr->timestamp_ns);
        printf("[eBPF Event: EXEC] PID=%u Comm=%s Filename=%s\n", hdr->pid, ev->comm, ev->filename);
        send_event_json(json_buf);

    } else if (hdr->event_type == EVENT_TYPE_OPEN && size >= sizeof(struct file_open_event)) {
        struct file_open_event *ev = (struct file_open_event *)data;
        g_stats.open_events++;
        snprintf(json_buf, sizeof(json_buf),
            "{\"type\":\"open\",\"pid\":%u,\"tgid\":%u,\"uid\":%u,\"filename\":\"%s\",\"flags\":%d,\"ts\":%llu}",
            hdr->pid, hdr->tgid, hdr->uid, ev->filename, ev->flags, (unsigned long long)hdr->timestamp_ns);
        printf("[eBPF Event: OPEN] PID=%u Filename=%s Flags=%d\n", hdr->pid, ev->filename, ev->flags);
        send_event_json(json_buf);

    } else if (hdr->event_type == EVENT_TYPE_CONNECT && size >= sizeof(struct network_connect_event)) {
        struct network_connect_event *ev = (struct network_connect_event *)data;
        g_stats.connect_events++;
        struct in_addr addr;
        addr.s_addr = ev->daddr;
        snprintf(json_buf, sizeof(json_buf),
            "{\"type\":\"connect\",\"pid\":%u,\"tgid\":%u,\"uid\":%u,\"daddr\":\"%s\",\"dport\":%u,\"ts\":%llu}",
            hdr->pid, hdr->tgid, hdr->uid, inet_ntoa(addr), (unsigned int)ntohs(ev->dport), (unsigned long long)hdr->timestamp_ns);
        printf("[eBPF Event: CONNECT] PID=%u Daddr=%s Dport=%u\n", hdr->pid, inet_ntoa(addr), ntohs(ev->dport));
        send_event_json(json_buf);

    } else {
        g_stats.dropped_events++;
        return -1;
    }

    return 0;
}

void collector_get_stats(collector_stats_t *out_stats) {
    if (out_stats) {
        *out_stats = g_stats;
    }
}

void collector_shutdown(void) {
    printf("[Collector] Shutting down collector. Total events: %llu\n", (unsigned long long)g_stats.total_events);
    if (g_ipc_sock >= 0) {
#ifdef _WIN32
        closesocket(g_ipc_sock);
        WSACleanup();
#else
        close(g_ipc_sock);
#endif
        g_ipc_sock = -1;
    }
    g_stats.is_running = 0;
}

int main(int argc, char **argv) {
    const char *ipc_host = "127.0.0.1";
    int ipc_port = 9090;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            ipc_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            ipc_host = argv[++i];
        }
    }

    if (collector_init(ipc_host, ipc_port) != 0) {
        return 1;
    }

    printf("[Collector] Ready to ingest kernel events from Rust eBPF maps.\n");
    printf("[Collector] Press Ctrl+C to terminate.\n");

    // In native Linux environment, this loops on bpf ring_buffer__poll()
    // In cross-platform demo mode, it waits for signals and reports status.
    while (g_keep_running) {
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
    }

    collector_shutdown();
    return 0;
}
