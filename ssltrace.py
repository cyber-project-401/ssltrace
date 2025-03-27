#!/usr/bin/env python3

import os
import argparse
import ctypes
from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack

# Suppress LLVM and BCC warnings
os.environ['BCC_LOGLEVEL'] = 'off'
os.environ['CLANG_LOGLEVEL'] = 'off'

# Args
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", type=int, help="Trace specific PID only")
parser.add_argument("--libssl", type=str, required=True, help="Path to libssl.so used by target")
parser.add_argument("--libc", type=str, required=True, help="Path to libc.so.6 used by target")
parser.add_argument("-n", "--name", help="Trace processes with matching name")
args = parser.parse_args()

# BPF program with SSL_read + SSL_write and connect
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/in.h>

#define MAX_DATA_SIZE 1024

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
    char direction; // 'r' for read, 'w' for write
    char data[MAX_DATA_SIZE];
};

BPF_HASH(ssl_to_fd, u64, u64);
BPF_HASH(fd_to_endpoint, u64, struct endpoint_t);
BPF_PERCPU_ARRAY(event_buffer, struct event_t, 1);
BPF_PERF_OUTPUT(events);

int trace_ssl_set_fd(struct pt_regs *ctx, void *ssl, int fd) {
    u64 ssl_ptr = (u64)ssl;
    u64 fd_u64 = fd;
    ssl_to_fd.update(&ssl_ptr, &fd_u64);
    return 0;
}

int trace_connect(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, int addrlen) {
    if (addr == NULL) return 0;
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &addr->sa_family);
    if (family != AF_INET) return 0;

    u64 fd = sockfd;
    struct endpoint_t info = {};
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    bpf_probe_read(&info.ip, sizeof(info.ip), &addr_in->sin_addr.s_addr);
    bpf_probe_read(&info.port, sizeof(info.port), &addr_in->sin_port);
    fd_to_endpoint.update(&fd, &info);
    return 0;
}

static int emit_ssl_event(struct pt_regs *ctx, void *ssl, const void *buf, int num, char direction) {
    if (buf == 0 || num <= 0) return 0;

    u64 ssl_ptr = (u64)ssl;
    u64 *fdp = ssl_to_fd.lookup(&ssl_ptr);
    if (!fdp) return 0;

    u64 fd = *fdp;
    struct endpoint_t *ep = fd_to_endpoint.lookup(&fd);
    if (!ep) return 0;

    int index = 0;
    struct event_t *evt = event_buffer.lookup(&index);
    if (!evt) return 0;

    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->fd = fd;
    evt->ip = ep->ip;
    evt->port = ep->port;

    u32 size = (u32)num;
    evt->size = size < MAX_DATA_SIZE ? size : MAX_DATA_SIZE;
    evt->direction = direction;
    bpf_probe_read_user(&evt->data, evt->size, buf);

    events.perf_submit(ctx, evt, sizeof(*evt));
    return 0;
}

int trace_ssl_write(struct pt_regs *ctx, void *ssl, const void *buf, int num) {
    return emit_ssl_event(ctx, ssl, buf, num, 'w');
}

int trace_ssl_read(struct pt_regs *ctx, void *ssl, const void *buf, int num) {
    return emit_ssl_event(ctx, ssl, buf, num, 'r');
}
"""

# Load BPF with suppressed warnings
b = BPF(text=bpf_source, cflags=["-Wno-duplicate-decl-specifier", "-Wno-address-of-packed-member"])

# Path resolving
def get_lib_path(pid, lib_path):
    return f"/proc/{pid}/root" + lib_path

target_pid = args.pid
libssl_path = get_lib_path(target_pid, args.libssl)
libc_path = get_lib_path(target_pid, args.libc)
print(f"SELECTED LIBSSL PATH: {libssl_path}")
print(f"SELECTED LIBC PATH: {libc_path}")

# Attach uprobes to libssl and libc
b.attach_uprobe(name=libssl_path, sym="SSL_set_fd", fn_name="trace_ssl_set_fd", pid=target_pid)
b.attach_uprobe(name=libssl_path, sym="SSL_write", fn_name="trace_ssl_write", pid=target_pid)
b.attach_uprobe(name=libssl_path, sym="SSL_read", fn_name="trace_ssl_read", pid=target_pid)
b.attach_uprobe(name=libc_path, sym="connect", fn_name="trace_connect", pid=target_pid)

# Define perf buffer event
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("fd", ctypes.c_ulonglong),
        ("ip", ctypes.c_uint),
        ("port", ctypes.c_ushort),
        ("size", ctypes.c_int),
        ("direction", ctypes.c_char),
        ("data", ctypes.c_char * 1024),
    ]

target_name = args.name

def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    if target_pid and event.pid != target_pid:
        return

    if target_name:
        try:
            pname = open(f"/proc/{event.pid}/comm").read().strip()
            if target_name not in pname:
                return
        except:
            return

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
#!/usr/bin/env python3

import os
import argparse
import ctypes
from bcc import BPF
from socket import inet_ntop, AF_INET
from struct import pack

# Suppress LLVM and BCC warnings
os.environ['BCC_LOGLEVEL'] = 'off'
os.environ['CLANG_LOGLEVEL'] = 'off'

# Args
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", type=int, help="Trace specific PID only")
parser.add_argument("--libssl", type=str, required=True, help="Path to libssl.so used by target")
parser.add_argument("--libc", type=str, required=True, help="Path to libc.so.6 used by target")
parser.add_argument("-n", "--name", help="Trace processes with matching name")
args = parser.parse_args()

# BPF program with SSL_read + SSL_write and connect
bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/in.h>

#define MAX_DATA_SIZE 1024

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
    char direction; // 'r' for read, 'w' for write
    char data[MAX_DATA_SIZE];
};

BPF_HASH(ssl_to_fd, u64, u64);
BPF_HASH(fd_to_endpoint, u64, struct endpoint_t);
BPF_PERCPU_ARRAY(event_buffer, struct event_t, 1);
BPF_PERF_OUTPUT(events);

int trace_ssl_set_fd(struct pt_regs *ctx, void *ssl, int fd) {
    u64 ssl_ptr = (u64)ssl;
    u64 fd_u64 = fd;
    ssl_to_fd.update(&ssl_ptr, &fd_u64);
    return 0;
}

int trace_connect(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, int addrlen) {
    if (addr == NULL) return 0;
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &addr->sa_family);
    if (family != AF_INET) return 0;

    u64 fd = sockfd;
    struct endpoint_t info = {};
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    bpf_probe_read(&info.ip, sizeof(info.ip), &addr_in->sin_addr.s_addr);
    bpf_probe_read(&info.port, sizeof(info.port), &addr_in->sin_port);
    fd_to_endpoint.update(&fd, &info);
    return 0;
}

static int emit_ssl_event(struct pt_regs *ctx, void *ssl, const void *buf, int num, char direction) {
    if (buf == 0 || num <= 0) return 0;

    u64 ssl_ptr = (u64)ssl;
    u64 *fdp = ssl_to_fd.lookup(&ssl_ptr);
    if (!fdp) return 0;

    u64 fd = *fdp;
    struct endpoint_t *ep = fd_to_endpoint.lookup(&fd);
    if (!ep) return 0;

    int index = 0;
    struct event_t *evt = event_buffer.lookup(&index);
    if (!evt) return 0;

    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->fd = fd;
    evt->ip = ep->ip;
    evt->port = ep->port;

    u32 size = (u32)num;
    evt->size = size < MAX_DATA_SIZE ? size : MAX_DATA_SIZE;
    evt->direction = direction;
    bpf_probe_read_user(&evt->data, evt->size, buf);

    events.perf_submit(ctx, evt, sizeof(*evt));
    return 0;
}

int trace_ssl_write(struct pt_regs *ctx, void *ssl, const void *buf, int num) {
    return emit_ssl_event(ctx, ssl, buf, num, 'w');
}

int trace_ssl_read(struct pt_regs *ctx, void *ssl, const void *buf, int num) {
    return emit_ssl_event(ctx, ssl, buf, num, 'r');
}
"""

# Load BPF with suppressed warnings
b = BPF(text=bpf_source, cflags=["-Wno-duplicate-decl-specifier", "-Wno-address-of-packed-member"])

# Path resolving
def get_lib_path(pid, lib_path):
    return f"/proc/{pid}/root" + lib_path

target_pid = args.pid
libssl_path = get_lib_path(target_pid, args.libssl)
libc_path = get_lib_path(target_pid, args.libc)
print(f"SELECTED LIBSSL PATH: {libssl_path}")
print(f"SELECTED LIBC PATH: {libc_path}")

# Attach uprobes to libssl and libc
b.attach_uprobe(name=libssl_path, sym="SSL_set_fd", fn_name="trace_ssl_set_fd", pid=target_pid)
b.attach_uprobe(name=libssl_path, sym="SSL_write", fn_name="trace_ssl_write", pid=target_pid)
b.attach_uprobe(name=libssl_path, sym="SSL_read", fn_name="trace_ssl_read", pid=target_pid)
b.attach_uprobe(name=libc_path, sym="connect", fn_name="trace_connect", pid=target_pid)

# Define perf buffer event
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("fd", ctypes.c_ulonglong),
        ("ip", ctypes.c_uint),
        ("port", ctypes.c_ushort),
        ("size", ctypes.c_int),
        ("direction", ctypes.c_char),
        ("data", ctypes.c_char * 1024),
    ]

target_name = args.name

def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    if target_pid and event.pid != target_pid:
        return

    if target_name:
        try:
            pname = open(f"/proc/{event.pid}/comm").read().strip()
            if target_name not in pname:
                return
        except:
            return

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

