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

    def final_attach(self, pid: int, libpaths: TrackedProc):
        print("win")

    def poll(self):
        self.b.perf_buffer_poll()


def get_loaded_path(process, library_name) -> Optional[str]:
    for mmap in process.memory_maps():
        if library_name in mmap.path:
            return f"/proc/{process.pid}/root" + mmap.path
    return None