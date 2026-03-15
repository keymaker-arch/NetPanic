# Vulnerabilities Discovered by NetPanic

## List
- cve-2025-38089
- cve-2025-38501
- cve-2025-40210
- cve-2025-40212
- cve-2026-23220

## Details

---

### CVE-2025-38089 — SUNRPC: NULL Pointer Dereference via SVC_GARBAGE in svc_authenticate

**Component:** Linux kernel — `net/sunrpc` (SUNRPC server authentication)
**Protocol:** SUNRPC (affects NFS server daemon `nfsd`)
**Type:** NULL Pointer Dereference (CWE-476)
**Impact:** Remote kernel crash (denial of service); potential memory corruption ("memory scribble") on subsequent requests
**CVSS v3.1:** 5.5 MEDIUM (NIST) — `AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`
**Affected Versions:** Linux 6.3.4 through 6.15.3 (multiple stable branches)

**Root Cause:**
When a specially crafted RPC packet is sent to a kernel RPC server (e.g., `nfsd`), the authentication processing functions `svc_authenticate()` or `pg_authenticate()` can return `SVC_GARBAGE` without initializing the `rq_accept_statp` pointer. The server-side reply path subsequently dereferences this pointer. On a thread's first RPC processing, the pointer is NULL, resulting in an immediate kernel crash. On subsequent requests (where the pointer retains a stale value from a previous call), dereferencing it causes a memory corruption ("memory scribble") — writing reply status data to an arbitrary or freed memory location.

**Fix:**
The patch treats `SVC_GARBAGE` as an `AUTH_ERROR` with reason `AUTH_BADCRED` (per RFC 5531), which routes the reply through a code path that does not touch `rq_accept_statp` at all. This sidesteps the uninitialized pointer problem entirely.

**Patch Commits:**
- [`353e75b55e58`](https://git.kernel.org/stable/c/353e75b55e583635bf71cde6abcec274dba05edd)
- [`599c489eea79`](https://git.kernel.org/stable/c/599c489eea793821232a2f69a00fa57d82b0ac98)
- [`94d10a4dba0b`](https://git.kernel.org/stable/c/94d10a4dba0bc482f2b01e39f06d5513d0f75742)
- [`c90459cd58bb`](https://git.kernel.org/stable/c/c90459cd58bb421d275337093d8e901e0ba748dd)

**Public Exploit:** [NFSundown](https://github.com/keymaker-arch/NFSundown)
**Disclosure:** [oss-security (2025-07-02)](https://www.openwall.com/lists/oss-security/2025/07/02/2)

---

### CVE-2025-38501 — ksmbd: Connection Exhaustion via Repeated Same-IP Connections

**Component:** Linux kernel — `ksmbd` (in-kernel SMB server)
**Protocol:** SMB
**Type:** Uncontrolled Resource Consumption (CWE-400)
**Impact:** Remote denial of service — legitimate clients blocked from connecting
**CVSS v3.1:** 7.5 HIGH (CISA-ADP) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
**Affected Versions:** Linux 5.15 through 6.16.0 (multiple stable branches)

**Root Cause:**
The ksmbd in-kernel SMB server enforces a global maximum connection limit but does not restrict the number of connections from a single IP address. An attacker can repeatedly open SMB connections from the same source IP, rapidly saturating the server's connection pool. Once the maximum is reached, all subsequent connection attempts — including those from legitimate clients — are rejected.

This is a classic resource exhaustion vulnerability. The attack requires no authentication: simply initiating TCP connections and sending SMB negotiate requests is sufficient to consume all available connection slots.

**Fix:**
The patch introduces per-IP connection limiting in ksmbd, preventing a single source address from monopolizing the server's connection capacity.

**Patch Commits:**
- [`6073afe64510`](https://git.kernel.org/stable/c/6073afe64510c302b7a0683a01e32c012eff715d)
- [`7e5d91d3e6c6`](https://git.kernel.org/stable/c/7e5d91d3e6c62a9755b36f29c35288f06c3cd86b)
- [`cb092fc3a629`](https://git.kernel.org/stable/c/cb092fc3a62972a4aa47c9fe356c2c6a01cd840b)
- [`e6bb91939740`](https://git.kernel.org/stable/c/e6bb9193974059ddbb0ce7763fa3882bd60d4dc3)
- [`f1ce9258bcbc`](https://git.kernel.org/stable/c/f1ce9258bcbce2491f9f71f7882b6eed0b33ec65)
- [`fa1c47af4ff6`](https://git.kernel.org/stable/c/fa1c47af4ff641cf9197ecdb1f8240cbb30389c1)

**Public Exploit:** [KSMBDrain](https://github.com/keymaker-arch/KSMBDrain)
**Disclosure:** [oss-security (2025-09-15)](http://www.openwall.com/lists/oss-security/2025/09/15/2)
**Downstream Advisory:** [Debian LTS (2025-10)](https://lists.debian.org/debian-lts-announce/2025/10/msg00008.html)

---

### CVE-2025-40210 — NFSD: Unbounded Memory Allocation via NFSv4 COMPOUND Op Count

**Component:** Linux kernel — `fs/nfsd` (NFS server daemon, NFSv4 COMPOUND processing)
**Protocol:** NFSv4
**Type:** Uncontrolled Resource Consumption / Memory Drain
**Impact:** Remote denial of service — kernel attempts ~1.2 TB vmalloc allocation, causing system-wide memory pressure and crash
**CVSS:** Awaiting NVD analysis
**Affected Versions:** Kernels containing commit `48aab1606fa8` (which removed the op-per-COMPOUND cap)

**Root Cause:**
A prior kernel commit (`48aab1606fa8` — "NFSD: Remove the cap on number of operations per NFSv4 COMPOUND") removed the limit on the number of operations that a client could request in a single NFSv4 COMPOUND request. This allowed an attacker to craft a COMPOUND request with an arbitrarily large operation count in the header. During XDR decoding, NFSD allocates an array proportional to this count. An attacker specifying a sufficiently large value triggers an allocation attempt on the order of ~1.2 TB via `vmalloc`, which causes the kernel to emit:

```
vmalloc error: size 1209533382144, exceeds total pages
```

This results in immediate denial of service. Additionally, the removed cap caused the pynfs COMP6 test to leave connections and leases in a broken state, hanging subsequent operations.

**Fix:**
The patch restores a per-COMPOUND operation limit, defined as `NFSD_MAX_OPS_PER_COMPOUND = 200`. The client's requested op count is preserved in `client_opcnt` for diagnostics, while the actual `opcnt` used for allocation is clamped via `min_t()`. The limit is also enforced during NFSv4.1+ session forechannel attribute negotiation.

**Patch Author:** Chuck Lever (Oracle)
**Patch Commits:**
- [`3e7f011c2555`](https://git.kernel.org/stable/c/3e7f011c255582d7c914133785bbba1990441713) (upstream)
- [`b3ee7ce43228`](https://git.kernel.org/stable/c/b3ee7ce432289deac87b9d14e01f2fe6958f7f0b) (stable backport)

**Files Changed:** `fs/nfsd/nfsd.h`, `fs/nfsd/xdr4.h`, `fs/nfsd/nfs4xdr.c`, `fs/nfsd/nfs4proc.c`, `fs/nfsd/nfs4state.c`

---

### CVE-2025-40212 — NFSD: Use-After-Free via Refcount Leak in nfsd_set_fh_dentry()

**Component:** Linux kernel — `fs/nfsd/nfsfh.c` (`nfsd_set_fh_dentry()`)
**Protocol:** NFSv2 / NFSv3
**Type:** Use-After-Free / Double-Free (refcount imbalance)
**Impact:** Remote kernel crash (denial of service); potential for further exploitation via use-after-free
**CVSS:** Awaiting NVD analysis
**Affected Versions:** Kernels containing commit `ef7f6c4904d0` ("nfsd: move V4ROOT version check to nfsd_set_fh_dentry()")

**Root Cause:**
NFSv4 uses a "pseudo root filesystem" for export discovery via LOOKUP operations. NFSv2/v3 clients are not supposed to access this pseudo root. However, `nfsd_set_fh_dentry()` contained a refcount management bug on the error path: when a v3/v2 client presented a filehandle belonging to the pseudo root filesystem, the function would:

1. Store the export reference in `fhp->fh_export` and dentry in `fhp->fh_dentry`.
2. Enter an error path that calls `exp_put()` to release the export reference.
3. Return an error.

Later, `fh_put()` would be called to clean up the `svc_fh` structure, which sees the non-NULL `fh_export` and calls `exp_put()` again — a classic double-put. This drops the reference count below zero, leading to use-after-free on the export object and potential kernel crash.

Triggering this requires a client to synthesize an incorrect filehandle — normal NFS operations do not produce pseudo-root filehandles for v3 clients.

**Fix:**
The two assignments (`fhp->fh_dentry = dentry` and `fhp->fh_export = exp`) are moved from before the error-checking `switch` block to after all error paths, immediately before the `return 0` success path. This ensures the struct is only populated when no error will trigger the conflicting `exp_put()`.

**Patch Author:** NeilBrown
**Patch Commits:**
- [`8a7348a9ed70`](https://git.kernel.org/stable/c/8a7348a9ed70bda1c1f51d3f1815bcbdf9f3b38c) (upstream)
- [`b6bc86ce3944`](https://git.kernel.org/stable/c/b6bc86ce3944b10b9fc181fc00c1a520a20ed965)
- [`c83d7365cec5`](https://git.kernel.org/stable/c/c83d7365cec5eb5ebeeee2a72e29b4ca58a7e4c2) (stable backport)

**Files Changed:** `fs/nfsd/nfsfh.c` (3 insertions, 3 deletions)

---

### CVE-2026-23220 — ksmbd: Infinite Loop on SMB2 Signature Verification Failure

**Component:** Linux kernel — `ksmbd` (in-kernel SMB server, compound request handling)
**Protocol:** SMB2/SMB3 (signed compound requests)
**Type:** Infinite Loop / Uncontrolled Resource Consumption
**Impact:** Remote denial of service — kernel thread enters infinite loop with 100% CPU usage and log flooding
**CVSS:** Awaiting NVD analysis
**Affected Versions:** Multiple stable branches (patches applied across 6 branch lines)

**Root Cause:**
When ksmbd processes a signed SMB2 compound (chained) request and signature verification fails for one of the chained messages, the following sequence occurs:

1. `check_sign_req()` returns an error for the current chained message.
2. `set_smb2_rsp_status()` is called to set an error response, which **resets `work->next_smb2_rcv_hdr_off` to zero** as a side effect.
3. The processing loop calls `is_chained_smb2_message()` to advance to the next chained message. However, because the offset was reset to zero, the function points back to the **first** request header.
4. If that first header's `NextCommand` field is non-zero (indicating more chained messages), the loop processes the same message again — hitting the same signature failure, resetting the offset to zero again, and repeating indefinitely.

The result is an infinite loop in kernel context. The kernel log is flooded with "bad smb2 signature" messages and the affected CPU core is pinned at 100% utilization. The system becomes unresponsive and requires a hard reboot.

**Fix:**
The patch changes the return value from `SERVER_HANDLER_CONTINUE` to `SERVER_HANDLER_ABORT` when a signature check fails. This ensures the compound request processing loop terminates immediately rather than attempting to continue from the invalidated offset.

**Patch Commits:**
- [`010eb01ce23b`](https://git.kernel.org/stable/c/010eb01ce23b34b50531448b0da391c7f05a72af)
- [`5accdc5b7f28`](https://git.kernel.org/stable/c/5accdc5b7f28a81bbc5880ac0b8886e60c86e8c8)
- [`71b5e7c52831`](https://git.kernel.org/stable/c/71b5e7c528315ca360a1825a4ad2f8ae48c5dc16)
- [`9135e791ec27`](https://git.kernel.org/stable/c/9135e791ec2709bcf0cda0335535c74762489498)
- [`f7b1c2f5642b`](https://git.kernel.org/stable/c/f7b1c2f5642bbd60b1beef1f3298cbac81eb232c)
- [`fb3b66bd72de`](https://git.kernel.org/stable/c/fb3b66bd72deb5543addaefa67963b34fb163a7b)