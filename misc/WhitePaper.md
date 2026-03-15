# NetPanic: The Attack Surface You Can't Syscall

### Fuzzing the Forgotten Remote Attack Surface of the Linux Kernel Network Stack

**Authors:** [Author Name(s)]
**Affiliation:** [Organization]
**Supplementary Material — Black Hat USA Briefing**

---

## Executive Summary

The Linux kernel network stack processes every inbound packet at the highest privilege level, yet its remote attack surface — reachable by anyone with network connectivity — has received almost no systematic security auditing. The kernel security community has spent over a decade focused on local privilege escalation via system call fuzzing, while the remote side remained a blind spot. Tools like Google's Syzkaller, despite years of continuous operation and massive compute budgets, have discovered zero remotely triggerable vulnerabilities in the network stack — not because it is secure, but because they are architecturally incapable of reaching this code.

We built **NetPanic**, the first fuzzer purpose-built for this problem. Its novel **Fuzzer-in-the-Middle (FitM)** architecture positions the fuzzer between two real kernel network stack instances, letting the kernel itself generate valid packets while the fuzzer intercepts and mutates them in flight. This eliminates the need for protocol grammars or manual packet templates and naturally synchronizes the system call and network input channels that the kernel requires.

In a single evaluation campaign against Linux kernel 6.14, NetPanic discovered **15 remotely triggerable vulnerabilities** — including use-after-free, null-pointer dereference, and memory drain bugs across TCP, SMB, NFS, and SUNRPC — with **5 CVEs assigned** and patches merged. It achieves over **100x the packet injection throughput** and approximately **400% more code coverage** than Syzkaller on the same hardware. NetPanic will be released as open source.

---

## 1. Introduction

Every server, cloud VM, container host, and embedded device running Linux exposes a vast attack surface to the network: the kernel's protocol stack. From Ethernet framing through IP routing, TCP state machines, and application-layer protocols like NFS and SMB, every byte of an inbound packet is parsed and processed at ring 0. A single exploitable bug in this path gives a remote attacker — who needs nothing more than network connectivity — the ability to crash a system, leak kernel memory, or achieve code execution.

Despite this severity, the kernel security community's tooling has a critical blind spot. The dominant fuzzing paradigm, pioneered by Syzkaller and operationalized at scale by Google's Syzbot, models the kernel's attack surface as a set of system calls. This paradigm has been enormously productive for local privilege escalation bugs, but it is fundamentally unable to model the remote attacker's perspective: crafting malicious packets from across the network, with no local code execution on the target.

The result is a dangerous asymmetry. Organizations observe years of intensive Syzbot fuzzing with no remote vulnerabilities reported and conclude the network stack is hardened. Our work shows this conclusion is wrong — the vulnerabilities were simply invisible to the tools.

This white paper provides the technical depth behind our Black Hat USA briefing. We explain why existing tools fail, describe the Fuzzer-in-the-Middle architecture that makes remote kernel fuzzing practical, and present our findings: 15 new remotely triggerable vulnerabilities in a single campaign, including bug classes (remote UAF, remote kernel panic) that have immediate offensive relevance.

---

## 2. The Problem: A Critical Blind Spot in Kernel Security

### 2.1 Two Attack Surfaces, Only One Being Tested

The kernel exposes two fundamentally different attack surfaces:

- **Local (system call) surface**: The attacker has code execution on the target and interacts with the kernel via system calls. Bugs here enable privilege escalation. This surface has been systematically fuzzed for over a decade.
- **Remote (network packet) surface**: The attacker has only network connectivity. Interaction is limited to sending and receiving packets. Bugs here enable denial of service, information disclosure, or remote code execution — with zero prior access required.

The remote surface is strictly more dangerous from a threat-modeling perspective, yet it has received a fraction of the attention.

### 2.2 The Evidence Gap

Google's Syzbot has been running Syzkaller continuously against the Linux kernel with massive compute resources for years. During the same period in which NetPanic discovered 15 remotely triggerable vulnerabilities, Syzbot reported **zero**. This is not a resource problem — it is a structural one. The absence of reported remote vulnerabilities has created a false sense of security across the industry.

### 2.3 Two Barriers That Block Existing Tools

We identified two fundamental technical barriers that prevent existing fuzzers from reaching this attack surface.

**Barrier 1: Extreme Input Complexity.** The kernel network stack does not process flat byte sequences. It expects fully encapsulated, multi-layered packets where each layer wraps the next:

```
┌────────────────────────────────────────────────────┐
│ Ethernet Header                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │ IP Header (v4/v6)                            │  │
│  │  ┌────────────────────────────────────────┐  │  │
│  │  │ TCP/UDP Header                         │  │  │
│  │  │  ┌──────────────────────────────────┐  │  │  │
│  │  │  │ Application Payload (NFS, SMB..) │  │  │  │
│  │  │  └──────────────────────────────────┘  │  │  │
│  │  └────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

A fuzzer must generate packets structurally valid enough to pass initial sanity checks (correct checksums, valid header lengths, proper encapsulation) while also being malformed enough to trigger bugs in deep protocol logic. Too conservative and it exercises only happy paths; too aggressive and the kernel drops packets at the front door.

**Barrier 2: Dual-Channel Input Coordination.** Unlike most kernel subsystems that accept a single input (system calls), the network stack requires tight coordination between **two** coupled channels:

1. **Network packets** arriving from the network interface.
2. **System calls** from user-space applications (`socket()`, `bind()`, `listen()`, `accept()`).

These channels are interdependent. The kernel will silently drop an incoming TCP SYN unless a process has already called `listen()` on the appropriate socket. An NFS request is discarded unless the NFS server daemon is running and registered. A fuzzer cannot simply inject packets — it must ensure the correct system calls have been made, in the correct order, at the correct time.

### 2.4 Why Specific Tool Classes Fail

**Kernel fuzzers (Syzkaller/Syzbot)** generate system call sequences and are highly effective for local privilege escalation. But their description language (Syzlang) was designed for system call arguments and cannot model deeply nested, multi-layer network packets from a remote attacker's perspective. In our evaluation, a dedicated Syzkaller instance tuned exclusively for network operations **failed to complete a single TCP handshake** over 24 hours.

**Protocol fuzzers (AFLNet, StateAFL)** target user-space protocol implementations and are fundamentally incompatible with kernel-level testing. They cannot collect kernel code coverage, detect kernel crashes, or drive the kernel's network stack directly.

---

## 3. Background: The Linux Kernel Network Stack

### 3.1 Packet Processing Pipeline

The Linux kernel implements the full network protocol stack — Layer 2 (Ethernet) through Layer 7 (application protocols like NFS and SMB). When a packet arrives at an interface, it enters kernel space and traverses protocol handlers in sequence: Ethernet framing, IP routing, TCP/UDP transport, and application-layer logic. Every step executes at kernel privilege.

A malformed packet that reaches deep enough into this pipeline can corrupt kernel memory, trigger null-pointer dereferences, cause use-after-free conditions, or exhaust system resources — all from a remote position with zero prior access.

### 3.2 Threat Model

NetPanic's threat model is deliberately direct: a remote, on-path adversary who can observe and modify network traffic between two legitimate endpoints. The attacker has:

- Network connectivity to the target.
- No local access, no shell, no user account.
- The ability to intercept, modify, drop, or delay packets in transit.

This encompasses both unauthenticated attackers (targeting protocols like raw TCP) and authenticated attackers (e.g., with NFS credentials, targeting post-authentication logic).

---

## 4. The Solution: NetPanic and the Fuzzer-in-the-Middle Architecture

### 4.1 Core Insight

NetPanic's key architectural insight draws from a well-known network attack: the Man-in-the-Middle. Instead of constructing packets from scratch, we position the fuzzer **between two real kernel network stack instances** communicating via real user-space programs. The kernel itself becomes the expert packet generator.

```
┌────────────────────── Host ──────────────────────┐
│               Fuzzing Manager                     │
│   ┌──────────┐  ┌────────┐  ┌──────────────┐     │
│   │Scheduler │  │Feedback│  │   Mutator    │     │
│   └──────────┘  └────────┘  └──────────────┘     │
└─────────────────────┬────────────────────────────┘
                      │ Seeds / Observations
┌─────────────────────┴────────────────────────────┐
│                VM  (Agent)                        │
│   ┌──────────┐             ┌──────────┐          │
│   │ Network  │  ← FitM →   │ Network  │          │
│   │ Stack A  │  intercept   │ Stack B  │          │
│   │ (Server) │  & mutate    │ (Client) │          │
│   └──────────┘             └──────────┘          │
└──────────────────────────────────────────────────┘
```

### 4.2 How FitM Solves Both Barriers

**Solving Extreme Input Complexity.** Two real kernel network stacks communicate normally, generating perfectly valid, multi-layered packets. The fuzzer does not need a grammar or protocol specification — it intercepts well-formed packets in flight and applies targeted mutations. The fuzzer inherits the kernel's own expertise in packet construction for free.

**Solving Dual-Channel Coordination.** User-space client and server programs naturally invoke the correct system calls in the correct order. A TCP server calls `listen()` before the client calls `connect()`; an NFS server registers its RPC programs before the client mounts. Synchronization between packets and system calls emerges as a free property of the architecture.

### 4.3 Manager-Agent Architecture

NetPanic uses a split design:

- **Fuzzing Manager** (host side): All fuzzing intelligence — mutator, coverage feedback engine, seed scheduler, crash detection. Runs on the host.
- **Fuzzing Agent** (VM side): A lightweight, disposable execution engine inside a QEMU virtual machine. Executes sessions, intercepts packets, returns observations.

When a mutated packet triggers a kernel panic inside the VM, the agent is simply restarted from a snapshot without losing fuzzing state.

### 4.4 Network Stack Isolation

Inside the VM, the agent uses Linux kernel **namespaces** to create two completely isolated network stack instances, each connected to a **TAP virtual device** as its gateway. TAP devices operate at Layer 2, providing full read/write access to raw Ethernet frames — complete interception and injection at the packet level.

A critical detail: packets written to a TAP device are processed **synchronously** by the kernel. This bypasses deferred processing and allows coverage to be precisely attributed to each injected packet via KCOV.

### 4.5 Seeds and Session Drivers

A seed in NetPanic is defined as:

```
Seed = (D, M)
```

where `D` is a pair of **Session Drivers** (user-space programs that establish a valid communication session) and `M` is a set of **Packet Modifiers** (deterministic mutation instructions).

When executed, the Session Drivers produce a clean session — an ordered sequence of packets `[P1, P2, ..., Pk]`. The Packet Modifiers are then applied to specific packets. Each modifier is a declarative instruction `⟨idx, op, meta⟩` targeting a specific packet with a mutation operator.

Session Drivers serve dual roles: packet generators and system call coordinators. To fuzz NFS, the Session Drivers are simply an NFS server and client performing standard file operations. The kernels generate all NFS/SUNRPC/TCP/IP packets; the programs ensure correct system calls in correct sequence.

This design is **protocol-agnostic**: adding support for a new protocol requires only writing a pair of client/server programs — no protocol grammar, no packet templates, no state machine specification.

### 4.6 Packet Interception and Dissection

Every packet passing between the two stacks is intercepted via the TAP devices and **dissected** using Wireshark's protocol analysis engine. A recent Wireshark commit enables parsing single packets from stdin with minimal overhead, providing a structured, protocol-aware view of every field.

This enables structure-aware mutations: the mutator can target specific protocol fields (e.g., "TCP Window Size" or "NFS File Handle") rather than operating on raw bytes.

### 4.7 Structure-Aware Mutation Strategy

NetPanic's mutations operate at three hierarchical levels — a departure from byte-level havoc mutation. Every mutation targets a semantically meaningful unit.

**Session-Level Operators** manipulate the sequence and timing of packets without altering content:

| Operator | Effect |
|---|---|
| `DropPacket` | Removes the packet from the session |
| `DelayPacket` | Holds the packet for a specified duration before forwarding |

**Packet-Level Operators** modify the protocol composition of a single packet:

| Operator | Effect |
|---|---|
| `ReplaceProtocol` | Replaces one protocol layer with another |
| `AddProtocol` | Inserts an additional protocol layer |
| `RMProtocol` | Removes a protocol layer |

**Field-Level Operators** target specific fields within protocol headers, informed by Wireshark dissection:

| Operator | Effect |
|---|---|
| `SetToExtremeL` / `SetToExtremeS` | Sets the field to its minimum/maximum boundary value |
| `SetToRandom` | Assigns a random value |
| `ArithmeticPlus` / `ArithmeticMinus` | Increments/decrements by a small delta |
| `AddOptionalHeader` / `RMOptionalHeader` | Adds/removes optional headers (TCP options, IPv6 extensions) |

Two heuristics guide mutation selection:

- **Sparsity**: The modifier list is kept small per seed. Network sessions are fragile — aggressive malformation in a single packet can prematurely terminate the session, blocking the fuzzer from reaching deep protocol states.
- **Exclusivity**: Higher-level operators preclude lower-level ones in the same pass. A packet-level mutation (e.g., replacing a layer) invalidates field-level mutations targeting the original structure.

### 4.8 Feedback and Scheduling

After each session, the agent returns an observation `⟨C, S, L, T⟩` — code coverage (KCOV basic blocks), full session trace, kernel/user-space logs, and execution time.

A seed is **interesting** and added to the corpus if it increases coverage, produces a new non-fatal log message, or generates a session with a previously unseen packet count.

The **scheduler** prioritizes seeds by derivation depth (deeper = probes more corner cases) and de-prioritizes consistently slow or timing-out seeds. Crash detection examines kernel logs for panic signatures and monitors execution time for hang conditions.

The evolutionary process mutates only the Packet Modifier set — Session Drivers remain fixed. Over iterations, modifiers evolve toward mutations that reach increasingly deep and complex code paths.

---

## 5. Results

### 5.1 Evaluation Setup

All experiments: Intel Core i7-14700K, 32GB RAM, Linux kernel 6.14 with KCOV and KASAN enabled. Single-threaded, 24-hour runs, repeated 3 times. Syzkaller was tuned exclusively for network stack testing as the baseline.

### 5.2 Vulnerability Discovery

NetPanic discovered **15 remotely triggerable vulnerabilities** across TCP, SMB (v2/v3), NFS (v3/v4), and SUNRPC. These include 10 kernel panics, 3 system hangs, 1 server hang, and 1 performance degradation. Five have CVEs assigned and patches merged; the rest are under responsible disclosure.

The same Syzkaller baseline, run for a **3-month campaign**, discovered **zero** novel remotely triggerable vulnerabilities and **failed to reproduce any** of NetPanic's findings.

### 5.3 Coverage and Throughput

| Metric | NetPanic | Syzkaller |
|---|---|---|
| Avg. code coverage improvement | — | ~400% less than NetPanic |
| TCP handshake completion | Consistent | Failed over 24 hours |
| Packet injection rate | >100x Syzkaller's peak | Collapses to near-zero |
| Packet reply rate | High and consistent | Zero across all experiments |
| NFS coverage | Substantial | Zero |

### 5.4 Ablation Study

A controlled ablation on Eth-IPv4-TCP isolates each component's contribution:

| Configuration | Result |
|---|---|
| **Full NetPanic** | Highest coverage across IPv4 and TCP |
| **Valid-only traffic** (no mutations) | Respectable baseline, significantly lower than full |
| **No syscall coordination** (no `listen()`/`accept()`) | Moderate IPv4; virtually zero TCP coverage |
| **Random byte-level mutation** (AFL-style havoc) | Near-zero coverage in both IPv4 and TCP |

Syscall coordination is essential — without it, the kernel drops packets before TCP processing begins. Structure-aware mutation matters — random havoc destroys packet structure. Targeted mutation adds significant value over clean traffic alone.

---

## 6. Discovered Vulnerabilities

NetPanic discovered 15 remotely triggerable vulnerabilities in Linux kernel 6.14, each confirmed with a stable reproducer.

| # | Impact | Bug Class | Protocol | Kernel Function | Status |
|---|---|---|---|---|---|
| 1 | Server Hang | — | SMB | `ksmbd_kthread_fn` | Patched, CVE assigned |
| 2 | Kernel Panic | Null-Pointer Deref | SUNRPC | `nfsd` | Patched, CVE assigned |
| 3 | Kernel Panic | Use-After-Free | SUNRPC | `cache_clean` | Patched, CVE assigned |
| 4 | Kernel Panic | Memory Drain | NFSv4 | `sunrpc_cache_lookup_rcu` | Patched, CVE assigning |
| 5 | Kernel Panic | Use-After-Free | SMBv3 | `fib_get_table` | Patched, CVE assigning |
| 6 | Kernel Panic | Null-Pointer Deref | SMBv3 | `smb3_get_tree` | Under disclosure |
| 7 | Kernel Panic | General Protection Fault | SMBv3 | `cifs_smb3_do_mount` | Under disclosure |
| 8 | Kernel Panic | Use-After-Free | SMBv3 | `svc_process_common` | Under disclosure |
| 9 | Kernel Panic | Use-After-Free | NFSv3 | `nfs_localio_disable_client` | Under disclosure |
| 10 | System Hang | — | SUNRPC | — | Under disclosure |
| 11 | Perf Degradation | — | SMBv2 | — | Under disclosure |
| 12 | Kernel Panic | Use-After-Free | SMBv2 | — | Under disclosure |
| 13 | System Hang | — | SMBv2 | — | Under disclosure |
| 14 | Kernel Panic | Use-After-Free | SMBv2 | `smb_grant_oplock` | Under disclosure |
| 15 | System Hang | — | TCP | `inet_frag_rbtree_purge` | Under disclosure |

**Assigned CVEs**: CVE-2025-38089, CVE-2025-38501, CVE-2025-40210, CVE-2025-40212, CVE-2026-23220

### 6.1 Breakdown by Impact

- **Kernel Panic** (immediate system crash): 10
- **System Hang** (requires hard reboot): 3
- **Server Hang** (service thread unresponsive): 1
- **Performance Degradation** (sustained slowdown): 1

### 6.2 Breakdown by Bug Class

- **Use-After-Free**: 6 — the most prevalent class, indicating systemic issues with object lifetime management in protocol handlers
- **Null-Pointer Dereference**: 2
- **General Protection Fault**: 1
- **Memory Drain**: 1
- **No memory corruption** (hang/degradation): 5

### 6.3 Breakdown by Protocol

- **SMB/SMBv2/SMBv3**: 8 — the most affected protocol family
- **SUNRPC**: 3
- **NFS/NFSv3/NFSv4**: 2
- **TCP**: 1

### 6.4 Implications

The prevalence of use-after-free vulnerabilities is particularly concerning. UAF bugs in kernel context are often exploitable for code execution, not merely denial of service. Combined with the remote trigger, these represent some of the highest-severity primitives possible. The TCP vulnerability (#15) is notable because it affects the most fundamental and widely deployed protocol, impacting virtually every Linux system regardless of which services it runs.

---

## 7. Future Work and Upcoming Developments

### Cross-Platform Portability

NetPanic's FitM architecture is OS-agnostic. We have begun porting to:

- **Windows kernel**: Using Windows network compartments and TAP drivers for packet interception.
- **ChromeOS**: Leveraging its Linux-based kernel with platform-specific adaptations.

These ports will be discussed for the first time at our Black Hat briefing.

### Expanding the Mutation Space

Currently, NetPanic mutates only network packets while keeping system call sequences fixed. A natural extension is co-mutating system call parameters (socket options, buffer sizes, timeout values) alongside packets, exploring interactions the current design holds constant.

### Exploitability Analysis

Our briefing will include new analysis on exploitability of the discovered vulnerabilities, including a live demonstration of a remotely triggered kernel crash — bridging the gap between vulnerability discovery and real-world offensive impact.

---

## 8. Conclusion

The remote attack surface of the Linux kernel network stack has been critically under-examined. Despite years of intensive fuzzing by Syzkaller and massive compute investments by Google Syzbot, zero remotely triggerable vulnerabilities were discovered — not because the kernel is secure, but because existing tools cannot reach this code.

NetPanic addresses this gap with the Fuzzer-in-the-Middle architecture, which turns the kernel itself into the packet generator and leverages natural client-server interactions for system call synchronization. The result is a protocol-agnostic fuzzer that exceeds the state of the art by over 100x in throughput and approximately 400% in code coverage.

The 15 remotely triggerable vulnerabilities discovered in a single campaign — including use-after-free, null-pointer dereference, and memory drain bugs in TCP, SMB, NFS, and SUNRPC — demonstrate that this attack surface is actively dangerous and demands the community's attention. NetPanic will be released as open source, giving the security community its first practical tool for systematically auditing the kernel network stack from the attacker's true vantage point: the network.

---

## References

1. Google. Syzkaller: An unsupervised coverage-guided kernel fuzzer. https://github.com/google/syzkaller
2. Google. Syzbot: Continuous kernel fuzzing dashboard. https://syzkaller.appspot.com
3. AFLplusplus. LibAFL: Advanced fuzzing library. https://github.com/AFLplusplus/LibAFL
4. Wireshark Foundation. Wireshark: Network protocol analyzer. https://www.wireshark.org
5. Linux kernel documentation. KCOV: Code coverage for fuzzing. https://www.kernel.org/doc/html/latest/dev-tools/kcov.html
6. Linux kernel documentation. KASAN: Kernel Address Sanitizer. https://www.kernel.org/doc/html/latest/dev-tools/kasan.html
7. Natella, R., et al. AFLNet: A greybox fuzzer for network protocols. IEEE ICST, 2020.
8. Natella, R., et al. StateAFL: Greybox fuzzing for stateful network servers. Empirical Software Engineering, 2022.
