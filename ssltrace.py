#!/usr/bin/env python3

import os
import argparse
import ctypes
from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack
import subprocess
import fnmatch

# Suppress LLVM and BCC warnings
os.environ['BCC_LOGLEVEL'] = 'off'
os.environ['CLANG_LOGLEVEL'] = 'off'



# BPF program with SSL_read + SSL_write and connect
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/in.h>

#define MAX_DATA_SIZE 1024

struct pid_fd_t {
    u32 pid;
    u64 fd;
};

struct endpoint_t {
    u32 ip;
    u16 port;
};

struct event_t {
    u32 pid;
    u64 fd;
    u32 ip;
    u16 port;
    int size;
    int buf_filled;
    char direction; // 'r' for read, 'w' for write
    char data[MAX_DATA_SIZE];
};

#define BASE_EVENT_SIZE ((size_t)(&((struct event_t*)0)->data))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))

BPF_HASH(getpeername_args, u32, struct sockaddr*);
BPF_HASH(ssl_to_fd, u64, struct pid_fd_t);
BPF_HASH(fd_to_endpoint, struct pid_fd_t, struct endpoint_t);
BPF_PERCPU_ARRAY(event_buffer, struct event_t, 1);
BPF_PERF_OUTPUT(events);

__attribute__((always_inline))
static inline u32 bpf_min(u32 a, u32 b) {
    return (a < b) ? a : b;
}

// Accept return: capture only (pid, fd)
int trace_accept_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    int new_fd = PT_REGS_RC(ctx);
    if (new_fd < 0) return 0;

    struct pid_fd_t pidfd = {};
    pidfd.pid = pid;
    pidfd.fd = new_fd;

    // No IP at this point, will be resolved later via getpeername
    struct endpoint_t empty = {};
    fd_to_endpoint.update(&pidfd, &empty);
    return 0;
}

// getpeername: resolve IP/port for a (pid, fd)
int trace_getpeername_entry(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, int *addrlen) {
    u32 pid = bpf_get_current_pid_tgid();
    getpeername_args.update(&pid, &addr);
    return 0;
}

int trace_getpeername_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct sockaddr **addrp = getpeername_args.lookup(&pid);
    if (!addrp) return 0;

    struct sockaddr *addr = *addrp;
    getpeername_args.delete(&pid);
    if (!addr) return 0;

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &addr->sa_family);
    if (family != AF_INET) return 0;

    struct pid_fd_t pidfd = {};
    pidfd.pid = pid;
    pidfd.fd = PT_REGS_PARM1(ctx);  // original sockfd

    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    struct endpoint_t info = {};
    bpf_probe_read(&info.ip, sizeof(info.ip), &addr_in->sin_addr.s_addr);
    bpf_probe_read(&info.port, sizeof(info.port), &addr_in->sin_port);
    fd_to_endpoint.update(&pidfd, &info);
    return 0;
}

// SSL context -> (pid, fd)
int trace_ssl_set_fd(struct pt_regs *ctx, void *ssl, int fd) {
    u64 ssl_ptr = (u64)ssl;
    struct pid_fd_t pidfd = {};
    pidfd.pid = bpf_get_current_pid_tgid() >> 32;
    pidfd.fd = fd;
    ssl_to_fd.update(&ssl_ptr, &pidfd);
    return 0;
}

// Outgoing connect
int trace_connect(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, int addrlen) {
    if (addr == NULL) return 0;
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &addr->sa_family);
    if (family != AF_INET) return 0;

    struct pid_fd_t pidfd = {};
    pidfd.pid = bpf_get_current_pid_tgid() >> 32;
    pidfd.fd = sockfd;

    struct endpoint_t info = {};
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    bpf_probe_read(&info.ip, sizeof(info.ip), &addr_in->sin_addr.s_addr);
    bpf_probe_read(&info.port, sizeof(info.port), &addr_in->sin_port);
    fd_to_endpoint.update(&pidfd, &info);
    return 0;
}

// Emit SSL event
static int emit_ssl_event(struct pt_regs *ctx, void *ssl, const void *buf, int num, char direction) {
    if (buf == 0 || num <= 0) return 0;

    u64 ssl_ptr = (u64)ssl;
    struct pid_fd_t *pidfd = ssl_to_fd.lookup(&ssl_ptr);
    if (!pidfd) return 0;

    struct endpoint_t default_ep = {};
    struct endpoint_t *ep = &default_ep;
    struct endpoint_t *found_ep = fd_to_endpoint.lookup(pidfd);
    if (found_ep)
        ep = found_ep;

    int index = 0;
    struct event_t *evt = event_buffer.lookup(&index);
    if (!evt) return 0;

    evt->pid = pidfd->pid;
    evt->fd = pidfd->fd;
    evt->ip = ep->ip;
    evt->port = ep->port;
    evt->size = (u32)num;
    evt->buf_filled = 0;
    evt->direction = direction;

    u32 buf_copy_size = bpf_min(MAX_DATA_SIZE, num);
    int ret = bpf_probe_read_user(&evt->data, buf_copy_size, buf);

    if (!ret)
        evt->buf_filled = 1;
    else
        buf_copy_size = 0;

    events.perf_submit(ctx, evt, EVENT_SIZE(buf_copy_size));
    return 0;
}

int trace_ssl_write(struct pt_regs *ctx, void *ssl, const void *buf, int num) {
    return emit_ssl_event(ctx, ssl, buf, num, 'w');
}

"""

# Load BPF with suppressed warnings
b = BPF(text=bpf_source, cflags=["-Wno-duplicate-decl-specifier", "-Wno-address-of-packed-member"])

def get_container_pid(name):
    try:
        output = subprocess.check_output(["docker", "inspect", "--format", "{{.State.Pid}}", name])
        return int(output.decode().strip())
    except Exception as e:
        print(f"[!] Failed to get PID for container '{name}': {e}")
        return None

# Utility: find a file under /proc/[pid]/root matching pattern
def find_library_under_proc_root(pid, pattern):
    root_path = f"/proc/{pid}/root"
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            if fnmatch.fnmatch(filename, pattern):
                full_path = os.path.join(dirpath, filename)
                if os.path.isfile(full_path):
                    return full_path
    return None

target_names = ["python_client", "tls_server"]
targets = []
for name in target_names:
    pid = get_container_pid(name)
    libc_path = find_library_under_proc_root(pid, "libc.so.6")
    libssl_path = find_library_under_proc_root(pid, "libssl.so*")
    if not libc_path or not libssl_path:
        print(f"[!] Skipping PID {pid} (missing libc or libssl)")
        continue
    targets.append((pid, libssl_path, libc_path))

if not targets:
    print("[-] No valid processes found. Exiting.")
    exit(1)

print("Resolved library paths for:")
for pid, libssl_path, libc_path in targets:
    print(f"  PID={pid} libssl={libssl_path} libc={libc_path}")


b = BPF(text=bpf_source, cflags=["-Wno-duplicate-decl-specifier", "-Wno-address-of-packed-member"])

# Attach for each container
for pid, libssl, libc in targets:
    try:
        b.attach_uprobe(name=libssl, sym="SSL_set_fd", fn_name="trace_ssl_set_fd", pid=pid)
        b.attach_uprobe(name=libssl, sym="SSL_write", fn_name="trace_ssl_write", pid=pid)
        b.attach_uprobe(name=libc, sym="connect", fn_name="trace_connect", pid=pid)
        b.attach_uretprobe(name=libc_path, sym="accept", fn_name="trace_accept_return", pid=pid)
        # b.attach_uprobe(name=libc_path, sym="getpeername", fn_name="trace_getpeername_entry", pid=pid)
        # b.attach_uretprobe(name=libc_path, sym="getpeername", fn_name="trace_getpeername_return", pid=pid)
    except Exception as e:
        print(f"[!] Failed to attach to PID {pid}: {e}")



# Define perf buffer event
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("fd", ctypes.c_ulonglong),
        ("ip", ctypes.c_uint),
        ("port", ctypes.c_ushort),
        ("size", ctypes.c_int),
        ("buf_filled", ctypes.c_int),
        ("direction", ctypes.c_char),
        ("data", ctypes.c_char * 1024),
    ]


def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents


    ip_str = inet_ntop(AF_INET, pack("I", event.ip))
    direction = {
        b"r": "READ ",
        b"w": "WRITE"
    }.get(event.direction, "UNKWN")

    print("=" * 60)
    print(f"[PID={event.pid} FD={event.fd}] {direction} {ip_str}:{event.port} ({event.size}/1024 bytes)")

    if event.direction in (b"r", b"w"):
        raw_data = bytes(event.data[:event.size])
        print("  Raw:", raw_data)
        try:
            printable = raw_data.decode("utf-8", errors="replace")
        except Exception:
            printable = raw_data.hex()
        print("  Text:", printable)

print("Tracing SSL_read/write and connect calls... Ctrl-C to stop.\n")
b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("Exiting.")