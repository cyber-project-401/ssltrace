from dataclasses import dataclass
import queue
import threading
from time import time
from typing import Optional
from bcc import BPF
from psutil import Process

bpf_code = """
#include <linux/sched.h>

struct exec_exit_event_t {
    u32 pid;
};

BPF_PERF_OUTPUT(execve_events);
BPF_PERF_OUTPUT(exit_events);
BPF_PERF_OUTPUT(dlopen_events);

int trace_execve(struct pt_regs *ctx) {
    struct exec_exit_event_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;

    execve_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_exit(struct pt_regs *ctx) {
    struct exec_exit_event_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;

    exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

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

@dataclass
class TrackedProc:
    libc: Optional[str] = None
    libssl: Optional[str] = None
    ready: bool = False

class Tracer:
    def __init__(self):
        self.b = BPF(text=bpf_code)
        self.b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")
        self.b.attach_kprobe(event="__x64_sys_exit_group", fn_name="trace_exit")
        self.b.attach_kprobe(event="__x64_sys_exit", fn_name="trace_exit")
        self.proc_map = {}
        self.proc_map_lock = threading.Lock()
        self.wait_queue = queue.Queue()
        self.b["execve_events"].open_perf_buffer(self.event_execve)
        self.b["exit_events"].open_perf_buffer(self.event_exit)
        self.b["events"].open_perf_buffer(self.handle_event)
        self.wait_thread = threading.Thread(target=self.hold_thread)
        self.wait_thread.start()
        

    def event_exit(self, cpu, data, size):
        exit_data = self.b["exit_events"].event(data)
        pid = exit_data.pid
        try:
            with self.proc_map_lock:
                if pid in self.proc_map:
                    self.proc_map.pop(pid)
            self.b.detach_uprobe(pid=pid)
        except:
            pass

    def event_execve(self, cpu, data, size):
        execve_data = self.b["execve_events"].event(data)
        self.push_new_pid(execve_data.pid)
        
    def push_new_pid(self, pid):
        try:
            process = Process(pid)
            tracked_proc = TrackedProc()
            tracked_proc.libc = get_loaded_path(process, "libc.so")
            if tracked_proc.libc is not None:
                tracked_proc.libssl = get_loaded_path(process, "libssl.so")
                if tracked_proc.libssl is not None:
                    self.final_attach(pid, tracked_proc)
                else:
                    with self.proc_map_lock:
                        if pid in self.proc_map:
                            return
                    self.wait_queue.put(process)
        except Exception as e:
            pass

    def hold_thread(self):
        tracked_list: list[Process] = []
        while True:
            try:
                while True:
                    tracked_list.append(self.wait_queue.get_nowait())
            except:
                remove_list = []
                for proc in tracked_list:
                    start_time = proc.create_time()
                    elapsed_time = time() - start_time
                    if elapsed_time > 5 or proc.is_running() == False:
                        remove_list.append(proc)
                    else:
                        try:
                            libssl = get_loaded_path(proc, "libssl.so")
                            if libssl is not None:
                                tracked_proc = None
                                with self.proc_map_lock:
                                    if proc.pid in self.proc_map:
                                        tracked_proc = self.proc_map.pop(proc.pid)
                                if tracked_proc is not None:
                                    tracked_proc.libssl = libssl
                                    self.final_attach(proc.pid, tracked_proc)
                                remove_list.append(proc)
                        except:
                            remove_list.append(proc)
                tracked_list = [item for item in tracked_list if item not in remove_list]

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

    def final_attach(self, pid: int, libpaths: TrackedProc):
        print("FINAL ATTACH ")
        libssl = libpaths.libssl
        libc = libpaths.libc
        try:
            self.b.attach_uprobe(name=libssl, sym="SSL_set_fd", fn_name="trace_ssl_set_fd", pid=pid)
            self.b.attach_uprobe(name=libssl, sym="SSL_write", fn_name="trace_ssl_write", pid=pid)
            self.b.attach_uprobe(name=libc, sym="connect", fn_name="trace_connect", pid=pid)
            self.b.attach_uretprobe(name=libc, sym="accept", fn_name="trace_accept_return", pid=pid)
        except Exception as e:
            print(f"[!] Failed to attach to PID {pid}: {e}")

    def poll(self):
        self.b.perf_buffer_poll()


def get_loaded_path(process, library_name) -> Optional[str]:
    for mmap in process.memory_maps():
        if library_name in mmap.path:
            return f"/proc/{process.pid}/root" + mmap.path
    return None


tracer = Tracer()

while True:
    tracer.poll()