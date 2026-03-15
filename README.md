# NetPanic

**The Attack Surface You Can't Syscall**

NetPanic is a novel fuzzer for systematically auditing the **remote attack surface** of the Linux kernel network stack. It discovers remotely triggerable vulnerabilities — bugs that can be exploited by sending crafted packets over the network, with no prior local access required.

NetPanic has discovered **15 remotely triggerable vulnerabilities** in the latest Linux kernel, none of which could be found or reproduced by the state-of-the-art kernel fuzzer Syzkaller. In direct comparison, NetPanic achieves over **100x execution throughput** and over **400% code coverage improvement**.

## Motivation

Kernel security research has historically focused on the local attack surface (e.g., privilege escalation via crafted syscalls). The remote attack surface — where an adversary needs only network connectivity — has been dangerously overlooked. NetPanic addresses this gap by providing the first systematic, fuzzing-based audit of this attack surface.

## Key Challenges Addressed

1. **Extreme Input Complexity**: The kernel network stack processes complete, multi-layered packets (Ethernet/IP/TCP/application). A fuzzer must construct fully encapsulated packets and mutate them intelligently — too aggressive breaks basic checks, too conservative misses corner cases.

2. **Dual-Channel Input Coordination**: The network stack requires tight synchronization between incoming packets and user-space system calls (e.g., `listen()` must be called before a TCP SYN is processed). Existing fuzzers cannot coordinate these two input channels.

## Design

NetPanic is built on a **Fuzzer-in-the-Middle (FitM)** architecture:

- **Two kernel network stacks** communicate via real user-space programs (Session Drivers), with the fuzzer intercepting packets in-flight.
- The kernel itself acts as an expert packet generator, solving the construction problem and inherently coordinating syscalls with packet flow.
- An **execution-guided, structure-aware mutation strategy** applies targeted malformations at three levels — session (drop/delay packets), packet (replace/add/remove protocol layers), and field (boundary values, arithmetic, optional headers) — while preserving enough structural validity to bypass sanity checks.

### Architecture

```
┌─────────────────── Host ───────────────────┐
│              Fuzzing Manager                │
│  ┌──────────┐ ┌────────┐ ┌──────────────┐  │
│  │Scheduler │ │Feedback│ │   Mutator    │  │
│  └──────────┘ └────────┘ └──────────────┘  │
└────────────────────┬───────────────────────┘
                     │ Seeds / Observations
┌────────────────────┴───────────────────────┐
│               VM  (Agent)                  │
│  ┌──────────┐            ┌──────────┐      │
│  │ Network  │  ← FitM →  │ Network  │      │
│  │ Stack A  │  intercept  │ Stack B  │      │
│  │ (Server) │  & mutate   │ (Client) │      │
│  └──────────┘            └──────────┘      │
└────────────────────────────────────────────┘
```

## Implementation

- Written in **Rust** (~14,000 LoC) and **C** (~5,100 LoC)
- Manager runs on the host; agent executes inside a QEMU VM
- Built on the [LibAFL](https://github.com/AFLplusplus/LibAFL) framework
- Uses Linux kernel **namespaces** for network stack isolation and **TAP devices** for packet interception
- Leverages **Wireshark** for in-flight packet dissection
- Coverage via **KCOV**; memory error detection via **KASAN**

## Vulnerabilities Discovered

NetPanic has discovered 15 remotely triggerable vulnerabilities across TCP, SMB, NFS, and SUNRPC protocols. All are considered high-risk per kernel security guidelines.

| # | Attack Result | Memory Corruption | Protocol |
|---|---|---|---|
| 1 | Server Hang | N/A | SMB |
| 2 | Kernel Panic | Null-Pointer Deref | SUNRPC |
| 3 | Kernel Panic | Use-After-Free | SUNRPC |
| 4 | Kernel Panic | Memory Drain | NFSv4 |
| 5 | Kernel Panic | Use-After-Free | SMBv3 |
| 6 | Kernel Panic | Null-Pointer Deref | SMBv3 |
| 7 | Kernel Panic | General Protection Fault | SMBv3 |
| 8 | Kernel Panic | Use-After-Free | SMBv3 |
| 9 | Kernel Panic | Use-After-Free | NFSv3 |
| 10 | System Hang | N/A | SUNRPC |
| 11 | Perf Degradation | N/A | SMBv2 |
| 12 | Kernel Panic | Use-After-Free | SMBv2 |
| 13 | System Hang | N/A | SMBv2 |
| 14 | Kernel Panic | Use-After-Free | SMBv2 |
| 15 | System Hang | N/A | TCP |

All vulnerabilities have been responsibly disclosed to the Linux kernel security team.

## Getting Started

*Coming soon* — source code and build instructions will be added to this repository.

## Citation

If you use NetPanic in your research, please cite our paper:

```bibtex
@inproceedings{netpanic,
  title     = {NetPanic: The Attack Surface You Can't Syscall},
  year      = {2026},
}
```

## License

*License information will be added upon release.*
