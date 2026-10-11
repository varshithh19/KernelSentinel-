#ifndef KERNELSENTINEL_COLLECTOR_H
#define KERNELSENTINEL_COLLECTOR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAGIC_KSEN 0x4B53454E // "KSEN"

#define EVENT_TYPE_EXEC    1
#define EVENT_TYPE_OPEN    2
#define EVENT_TYPE_CONNECT 3

#pragma pack(push, 1)

struct event_header {
    uint32_t magic;
    uint32_t event_type;
    uint32_t pid;
    uint32_t tgid;
    uint32_t uid;
    uint64_t timestamp_ns;
};

struct process_exec_event {
    struct event_header header;
    char comm[16];
    char filename[256];
};

struct file_open_event {
    struct event_header header;
    char filename[256];
    int32_t flags;
};

struct network_connect_event {
    struct event_header header;
    uint32_t daddr;
    uint16_t dport;
    uint16_t pad;
};

#pragma pack(pop)

typedef struct {
    uint64_t total_events;
    uint64_t exec_events;
    uint64_t open_events;
    uint64_t connect_events;
    uint64_t dropped_events;
    uint64_t invalid_magic_events;
    int is_running;
} collector_stats_t;

int collector_init(const char *ipc_host, int ipc_port);
int handle_kernel_event(void *ctx, void *data, size_t size);
void collector_get_stats(collector_stats_t *out_stats);
void collector_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif // KERNELSENTINEL_COLLECTOR_H
