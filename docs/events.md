# eBPF-Sourced Events

Elastic Endpoint leverages BPF to source a variety of security-related events
on Linux. It does this by hooking into a variety of kprobes/tracepoints and
ftrace hooks with BPF programs.

This is currently only supported for newer kernels (5.11+) due to the
difficulties stemming from a lack of BPF-features on older kernels. Endpoint
sources events on older kernels from tracefs instead.

## Local usage

All the kernelspace BPF event sourcing code is located at `GPL/Events`. BPF
code pertaining to different classes of events (e.g. Process/File/Network) are
found under subdirectories of a respective name in that directory.

The BPF probes pass up generated events by way of a [BPF
ringbuffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html) to
userspace where they can be processed. A userspace library is provided at
`non-GPL/Events/Lib` to wrap all the ringbuffer logic and easily consume events
from userspace.

For quick debugging, a simple CLI wrapper around the userspace library is
provided at `non-GPL/Events/EventsTrace`. This tool will load the event probes,
source specified events from them and print them to standard output as
newline-delimited JSON. For example, process exec events can be monitored from
the command line with:

```
$ sudo ./EventsTrace --process-exec
{"event_type":"PROCESS_EXEC","pids":{"tid":20115,"tgid":20115,"ppid":2393,"pgid":20115,"sid":2393,"start_time_ns":4070455677498},"creds":{"ruid":1000,"rgid":1000,"euid":1000,"egid":1000,"suid":1000,"sgid":1000},"ctty":{"major":136,"minor":1},"filename":"/usr/bin/ls","cwd":"/home/vagrant/endpoint-dev/Kernel/Ebpf","pids_ss_cgroup_path":"/user.slice/user-1000.slice/session-5.scope","argv":"ls --color=auto"}
```

For better human-reading, the output can be cleaned up by piping it to `jq`.
You will need to pass the `--unbuffer-stdout` flag to `EventsTrace` to ensure
that data goes to `jq` in real time (and not just when standard output is
flushed):

```
$ sudo ./EventsTrace --unbuffer-stdout --process-exec | jq
{
  "event_type": "PROCESS_EXEC",
  "pids": {
    "tid": 20265,
    "tgid": 20265,
    "ppid": 2393,
    "pgid": 20265,
    "sid": 2393,
    "start_time_ns": 4230949664975
  },
  "creds": {
    "ruid": 1000,
    "rgid": 1000,
    "euid": 1000,
    "egid": 1000,
    "suid": 1000,
    "sgid": 1000
  },
  "ctty": {
    "major": 136,
    "minor": 1
  },
  "filename": "/usr/bin/ls",
  "cwd": "/home/vagrant/ebpf",
  "pids_ss_cgroup_path": "/user.slice/user-1000.slice/session-5.scope",
  "argv": "ls --color=auto"
}
```
