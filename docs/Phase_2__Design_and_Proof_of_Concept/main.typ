// -----------------------------------------------------------------
// Document settings
// -----------------------------------------------------------------
#set page(
  paper: "a4",
  margin: (top: 24mm, bottom: 24mm, left: 28mm, right: 28mm),
  footer: context {
    if counter(page).get() != (1,) {
      align(center)[#counter(page).display()]
    }
  },
)

#set text(
  font: "Libertinus Serif",
  size: 11pt,
)

#set par(
  leading: 1.35em,
  justify: true,
)

#set heading(numbering: "1.")

#show heading: it => [
  #v(0.8em)
  #align(center)[#strong(it.body)]
  #v(0.35em)
]

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------
#let hrule() = rule(width: 100%, stroke: 0.6pt)
#let sigline(lable) = [
  #strong(label) #h(0.8em) #rule(width: 65mm, stroke: 0.8pt)
  #v(0.7em)
]


// -----------------------------------------------------------------
// SECTION: cover page
// -----------------------------------------------------------------
#align(center)[
  #v(40mm)

  #text(size: 20pt, weight: "bold")[Linux Sandboxing II]

  #v(10mm)

  #emph[by]

  #v(4mm)

  #text(size: 12pt, weight: "bold")[Diya Mahato (2023ebcs550)]
  #v(1.5mm)
  #text(size: 12pt, weight: "bold")[Julian Cazzola (2023ebcs575)]
  #v(1.5mm)
  #text(size: 12pt, weight: "bold")[K.Harshavardhan Reddy (2023ebcs447)]
  #v(1.5mm)
  #text(size: 12pt, weight: "bold")[Saurabh Singh (2023ebcs591)]

  #v(12mm)

  #emph[supervised by]

  #v(4mm)

  #text(size: 12pt, weight: "bold")[Prof. Sarathi Subramani]
]

#align(right + bottom)[
  #text(size: 9pt)[
    BCS ZC241T Study Project (Group 153) \
    Phase II --- Design and Proof of Concept \
    Dept. of Computer Science, BITS Pilani
  ]
]

// -----------------------------------------------------------------
// SECTION: table of contents
// -----------------------------------------------------------------
#pagebreak()

#outline()

// -----------------------------------------------------------------
// SECTION: intro
// -----------------------------------------------------------------
#pagebreak()

= Introduction <intro>

== Purpose of Phase 2 <intro-purpose>

Phase 2 converts the Phase 1 problem definition ("desktop Linux applications typically execute with the user's full authority") into a concrete design and a validated feasibility slice. Academic work on Linux desktop sandboxing highlights that many desktop apps run within a single user context such that compromise of one program can expose a broad set of user data and processes, and that there is no single, widely adopted, user-friendly sandboxing approach on Linux desktops today @brodschelm-2022. Phase 2 therefore focuses on:

#v(1em)

- translating the Phase 1 goals into an implementable architecture grounded in Linux isolation primitives (namespaces and related mechanisms used to implement containers),
- defining requirements that the system must satisfy to be usable and secure,
- demonstrating feasibility with a Proof of Concept (PoC) that proves the core launch-and-isolate mechanism works end-to-end using real kernel interfaces.

#v(1.5em)

== Scope of Phase 2 <intro-scope>

- a system design and architecture on which the PoC's control flow and kernel interactions are based,
- detailed functional and non-functional requirements (including those validated by the PoC vs. deferred),
- high-level data flow and configuration storage design (database is treated as a local profile store, since the target is a desktop tool),
- a working demonstrable PoC proving rootless sandbox launch of commands using user and network namespaces on Linux.

// -----------------------------------------------------------------
// SECTION: overview
// -----------------------------------------------------------------
#pagebreak()

= System overview <overview>

== Product perspective <overview-perspective>

In Phase 2, the system is a standalone sandbox launcher (CLI-driven) that can be integrated later into a broader desktop UX (GUI launcher, per-app profiles, notifications). The isolation boundary is implemented by the Linux kernel namespace API: namespaces wrap global system resources so processes perceive an isolated instance of that resource, a foundation commonly used for containers @namespaces-linux-manual-page-no-date.

#v(1em)

The PoC specifically demonstrates:

#v(0.5em)

- creating a user namespace (isolating UIDs/GIDs and capabilities) and
- creating a network namespace (isolating network devices, stacks, routing tables, ports/sockets, etc.)

#v(1em)

The deployment environment for Phase 2 is:

#v(0.5em)

- Linux only (explicitly enforced by the PoC) and
- local execution (no daemon required in the PoC), suitable for desktop use where a user launches an app through the sandbox tool.

#v(1.5em)

== Major system functions <overview-functions>

The Phase 2 PoC supports these major functions:

#v(0.5em)

- launching an arbitrary command under a sandboxed execution context created via namespaces,
- mapping host UID/GID into the new user namespace via `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map`, including safe handling of `/proc/<pid>/setgroups`,
- isolating networking by moving the target process into a new network namespace,
- producing diagnostic logging of identity and namespace-related `/proc` state to validate the sandbox boundary (Phase 2 validation instrumentation).

#v(1.5em)

== User classes and characteristics <overview-characteristics>

#v(0.5em)

- End users (future phases): non-expert desktop users who need "safe-by-default" sandbox profiles and permission toggles. This aligns with findings that usability characteristics are key to adoption of desktop security features.
- Power users / developers (Phase 2 primary): run the CLI PoC, supply a config, interpret logs, and manually test isolation.
- Administrators (optional, future): may set organization defaults (e.g., baseline profiles) but Phase 2 does not require system-wide policy.

// -----------------------------------------------------------------
// SECTION: requirements
// -----------------------------------------------------------------
#pagebreak()

= Requirements <requirements>

== Functional Requirements <requirements-functional>

The following functional requirements reflect (a) what the PoC already demonstrates and (b) what Phase 2 design commits to for later phases:

#v(0.5em)

*FR1 --- Config-driven launch*\
The system shall accept a sandbox configuration specifying the command (`argv`) to execute, and shall launch the command under sandbox controls (PoC: config #sym.arrow `execvp`).

#v(0.5em)

*FR2 --- User namespace creation (rootless)*\
The system shall create a new user namespace for the launched process using `unshare(CLONE_NEWUSER)`, enabling per-sandbox UID/GID virtualization. User namespaces are specifically designed to isolate security identifiers like UIDs/GIDs and capabilities @namespaces-linux-manual-page-no-date.

#v(0.5em)

*FR3 --- UID/GID mapping via procfs*\
The system shall establish a UID and GID mapping for the sandbox such that namespace UID 0 maps to the invoking user's host UID (and similarly for GID), by writing (once) to `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map`.

#v(0.5em)

*FR4 --- Safe `setgroups` handling for gid_map*\
The system shall write "`deny`" to `/proc/<pid>/setgroups` when required before writing `gid_map`, to comply with kernel restrictions and avoid unsafe group transitions @namespaces-linux-manual-page-no-date.

#v(0.5em)

*FR5 --- Network isolation baseline*\
The system shall isolate the target command's network view by creating a new network namespace with `unshare(CLONE_NEWNET)`, such that networking resources (devices/stacks/ports, etc.) are isolated from the host.

#v(0.5em)

*FR6 --- Deterministic parent/child handshake*\
The system shall coordinate namespace creation and UID/GID mapping deterministically (PoC: child signals "`ready`"; parent writes maps; parent ACKs; child proceeds). This is required because a new user namespace begins with no mappings and mappings are written through procfs under specific rules @namespaces-linux-manual-page-no-date.

#v(0.5em)

*FR7 --- Observable verification hooks (Phase 2)*\
The system shall provide diagnostic output sufficient to validate the sandbox boundary (e.g., show UID/GID status, mapping files, and namespace-related proc metadata). This supports Phase 2 feasibility validation (not a permanent end-user requirement).

#v(0.5em)

*Deferred functional requirements (Phase 1 #sym.arrow Capstone)*\
The Phase 2 PoC does not yet implement filesystem isolation (mount namespaces), syscall filtering (seccomp), capability bounding, or GUI integration. These remain in-scope for Capstone because they are core to a full desktop sandbox, but they are not required to prove the Phase 2 feasibility slice (rootless namespace-mediated isolation path). Namespaces beyond user/network exist specifically for mount points, PIDs, etc., and are expected to be layered later.

#v(1.5em)

== Non-functional Requirements <requirements-non-functional>

=== Performance Requirements <requirements-non-functional-performance>

Namespace creation is designed as a lightweight kernel primitive (commonly used as the isolation basis for containers) @namespaces-linux-manual-page-no-date. Phase 2 performance expectations are:

#v(1em)

- sandbox launch overhead should be close to a normal `fork`/`exec` plus namespace setup,
- startup should remain interactive for desktop workloads (Capstone will quantify with timing/benchmarks).

#v(1.5em)

=== Security Requirements <requirements-non-functional-security>

- User namespaces isolate security identifiers and capabilities; a process moved into a new user namespace obtains a full set of capabilities in that namespace @namespaces-linux-manual-page-no-date.
- For non-user namespaces, the kernel records the creating process's user namespace as the "owner" for capability checks, meaning user namespaces govern permission checks for actions in associated namespaces.
- The PoC's design intentionally avoids requiring root: since Linux 3.8, no privilege is required to create a user namespace (subject to system configuration), enabling rootless sandboxing @unshare-linux-manual-page-no-date.

#v(1.5em)

=== Usability Requirements <requirements-non-functional-usability>

Phase 2 UX is developer-oriented, but the product direction is an "Android-like" permission model. Research on Linux desktop sandboxing emphasizes usability as a prerequisite for adoption of security features. Phase 2 therefore constrains future design choices:

- permissions must be expressed as high-level toggles (e.g., "Network: Allow/Deny"),
- secure defaults should be provided via profiles.

#v(1.5em)

=== Scalability and maintainability  <requirements-non-functional-scalability>

- The system should remain modular: launcher/frontend, sandbox runtime, and profile store should be separable components.
- Maintainability requires precise, testable boundaries around "trusted code" that manipulates namespaces. Kernel APIs such as namespaces and seccomp are well documented and stable, supporting an incremental hardening path @namespaces-linux-manual-page-no-date.

// -----------------------------------------------------------------
// SECTION: architecture
// -----------------------------------------------------------------
#pagebreak()

= System Architecture and Design <architecture>

The Phase 2 architecture is best described as a two-process launcher plus kernel isolation boundary, mirroring how namespace setup must be staged:

#v(1.5em)

== Architecture Diagram (Phase 2 PoC) <architecture-diagram>

User (CLI)

#sym.arrow Sandbox launcher (parent process, host namespaces)

#sym.arrow forks child process

#sym.arrow child calls `unshare(CLONE_NEWUSER | CLONE_NEWNET)`

#sym.arrow.l.r parent writes `/proc/<child>/uid_map`, `/proc/<child>/gid_map`, `/proc/<child>/setgroups`

#sym.arrow child sets `uid=0`,`gid=0` inside namespace

#sym.arrow child `execvp(target command)`

#sym.arrow kernel enforces: user namespace + network namespace isolation boundary @namespaces-linux-manual-page-no-date

=== Why user+net namespaces in one call

`unshare(2)` documents that creating most namespaces requires `CAP_SYS_ADMIN`, but when a user namespace is created, it confers capabilities, so creating a user namespace along with other namespaces in the same `unshare()` call does not require `CAP_SYS_ADMIN` in the original namespace @unshare-linux-manual-page-no-date. This is the key to the PoC's rootless `CLONE_NEWUSER | CLONE_NEWNET` approach.

#v(1.5em)

== Module-wise Design (PoC) <architecture-module>

=== CLI entry module (`main`)

- Responsibility: parse arguments, configure logging, enforce constraint (e.g., Linux-only), call the sandbox parent routine.
- Inputs: `argv`, config path/object.
- Outputs: process exit code; logs.

#v(0.5em)

=== Parent module (`parent`)

- Responsibility: create two unidirectional pipes, fork a child, wait for readiness signal, write UID/GID mappings to procfs, ACK child, wait for completion, return exit code.
- Key interaction: procfs writes to `/proc/<pid>/uid_map`, `/proc/<pid>/gid_map`, `/proc/<pid>/setgroups` follow kernel rules for mapping establishment @namespaces-linux-manual-page-no-date.

#v(0.5em)

=== Child module (`child`)

- Responsibility: (best-effort) drop supplementary groups before mapping, unshare into new namespaces, synchronize with parent for mappings, switch to namespace-root IDs, exec target command.
- Constraints: `unshare(CLONE_NEWUSER)` requires the calling process be single-threaded @namespaces-linux-manual-page-no-date. The PoC's `fork()`-then-`unshare()` structure is consistent with this requirement.

#v(0.5em)

=== Diagnostics module (`diag`)

- Responsibility: read and log `/proc/self/uid_map`, `/proc/self/gid_map`, and selected `/proc/self/status` keys to make namespace/mapping effects observable.
- Design intent: Phase 2 validation instrumentation, enabling manual confirmation that mappings and identities are as expected.

#v(1.5em)

== Data flow design <architecture-data-flow>

Phase 2 data flow is intentionally small and deterministic:

1. User config input (`command`, `argv`) enters the launcher.
2. Parent creates IPC primitives (pipes) and forks.
3. Child unshares namespaces and emits "`ready`".
4. Parent writes identity mappings via procfs.
5. Child becomes namespace-root via `setresuid(0)`/`setresgid(0)`.
6. Child execs the target command, after which the kernel enforces runtime isolation boundaries (user + network namespaces).
7. Exit status propagates to the parent.

== Database (profile store) design

A traditional database is not necessary for Phase 2 PoC, but a local profile store is required for the full desktop product (Phase 1 intent). Research on Linux desktop sandboxing PoCs commonly includes sandbox profiles as a usability feature, supporting repeatable permission sets @brodschelm-2022.

#v(1em)

Proposed minimal schema (for Capstone; not implemented in PoC):

- `Profile`
  - `profile_id` (string/uuid)
  - `display_name`
  - `executable_path`
  - `argv_template`
  - `permissions`:
    - `network`: `allow`/`deny`
    - `filesystem`: list of allowed read/write paths (later, mount namespace bindings)
    - `devices`: allowlist (later)
    - `seccomp_policy`: reference (later)
  - `created_at` / `updated_at`

- `AuditEvent` (optional, only needed if audit framework is implemented)
  - `timestamp`
  - `profile_id`
  - `decision` (`allowed`/`denied`)
  - `resource` type (net/fs)
  - `detail` (for debugging)

#v(1em)

Storage format: a human-readable file format (e.g., TOML/JSON), consistent with a desktop tool's portability goals.

// -----------------------------------------------------------------
// SECTION: techstack
// -----------------------------------------------------------------
#pagebreak()

= Technology stack and justification <techstack>

== Phase 2 PoC stack (implemented) <techstack-poc>

- Language/runtime: Python (rapid iteration; direct access to `os.unshare`, `os.fork`, `os.execvp`, and procfs file operations). Python exposes `os.unshare(flags)` on Linux (added in Python 3.12; Linux availability ≥ 2.6.16 for the syscall wrapper) @os-python-documentation-no-date.
- Kernel isolation primitives:
  - Linux namespaces via `unshare(2)` (user namespace since Linux 3.8; network namespace supported when kernel is configured with `CONFIG_NET_NS`) @network_namespaces-linux-manual-page-no-date.
  - procfs interface for namespace mapping (`/proc/<pid>/uid_map`, `/proc/<pid>/gid_map`, `/proc/<pid>/setgroups`).
- IPC: anonymous pipes for a minimal parent/child synchronization protocol (`READY`/`ACK`).

#v(1em)

== Capstone-direction stack (design intent) <techstack-capstone>

- Sandbox runtime in a systems language (planned in Phase 1): A memory-safe systems language (e.g., Rust) is an appropriate target for the hardened sandbox runtime because it reduces memory-corruption classes in trusted isolation code (Phase 1 rationale); Phase 2 uses Python strictly as a feasibility and design extraction vehicle.
- Hardening layers to add: seccomp filtering (`seccomp(2)` / `SECCOMP_MODE_FILTER`) and capability bounding.
- Resource governance (optional): cgroups can limit and monitor per-sandbox resource usage @cgroups-linux-manual-page-no-date.

#v(1em)

// -----------------------------------------------------------------
// SECTION: poc
// -----------------------------------------------------------------
#pagebreak()

= Proof of Concept and Validation <poc>

== PoC description <poc-description>

The current Phase 2 PoC implements the core sandbox launch pipeline:

- fork-based parent/child staging,
- child creates a new user + network namespace using one `unshare()` call,
- parent writes UID/GID maps (and handles `/proc/<pid>/setgroups`),
- child becomes root inside the namespace (UID/GID 0) and executes the target command.

#v(1em)

The PoC proves:

- Rootless setup is viable: Linux's namespace API supports unprivileged creation of user namespaces since Linux 3.8; this is the key that makes desktop-friendly sandboxing possible without requiring a system daemon or root privileges (subject to system configuration).
- Network isolation is feasible as a default-deny: network namespaces isolate network resources such as protocol stacks, routing tables, and ports/sockets, providing a clean foundation for profiles without network access by default.
- Correct mapping mechanics are implementable: PID-scoped procfs mapping files (`uid_map`, `gid_map`, `setgroups`) provide a stable interface to establish identity mappings under documented constraints (write-once; `setgroups` restrictions) @namespaces-linux-manual-page-no-date.

#v(1.5em)

== PoC demonstration details <poc-demonstration>

Phase 2 manual testing validates:

#v(1em)

*1. Identity transformation*

Inside the sandbox, the process can adopt UID/GID 0 within the new user namespace after mappings are applied (expected because the caller gains capabilities in the new user namespace).

#image("poc-demo-1-identity.png")

The output demonstrates a successful user namespace isolation with correct UID/GID remapping:

1. On the host, before running the sandbox, the `id` command indicates that both UID and GID are 1000 (normal user).
2. Inside the sandbox, the `id` command reports that both UID and GID are 0 (root). This indicates that the process successfully becomes root inside the namespace (this is not equivalent to real root privileges) and that the user namespace UID/GID mapping is working.
3. After creating the file inside the sandbox as root, we check the file ownership on the host. We notice that the file is owned by user (UID 1000). This further confirms that UID/GID mapping is working properly.

#v(1em)

*2. Mapping correctness*

`/proc/self/uid_map` and `/proc/self/gid_map` reflect the intended 1-entry mapping rules (a single line mapping namespace IDs to host IDs).

#image("poc-demo-2-mapping.png")

The mapping shows:

```
         0       1000          1
```

This indicates that namespace UID/GID 0 is mapped to host UID/GID 1000 for a range of 1 ID. As a result, root inside the namespace corresponds to the invoking unprivileged user on the host. This confirms that the UID/GID mapping is correctly configured and that namespace root does not map to host root, preserving isolation.

#v(1em)

*3. Network isolation*

Workloads run in a private network namespace (isolated network stack and related resources), aligning with the documented isolation semantics.

#image("poc-demo-3-network.png")

When executing `nslookup google.com` inside the sandbox, DNS resolution fails with "network unreachable." This demonstrates that the process does not have access to the host network stack or external network interfaces.

The new network namespace does not inherit the host's network configuration (interfaces, routes, or DNS reachability). As a result, outbound connectivity is unavailable unless explicitly allowed and configured.

This confirms that network isolation is correctly enforced and that sandboxed workloads cannot access external network resources by default.

#v(1.5em)

== Current limitations <poc-limitations>

- No filesystem sandbox (mount namespace / bind mounts) despite mount namespaces being a primary mechanism for filesystem view isolation.
- No seccomp syscall filtering, which is a standard hardening layer for restricting kernel attack surface.
- No capability dropping/bounding (the process obtains broad capabilities inside the new user namespace by default).
- No GUI integration; Phase 1 already recognizes GUI isolation complexities (especially under X11).
- Validation relies on manual testing and debug logs; automated tests are planned for Capstone.

#v(1.5em)

== Testing and validation <poc-testing>

In Phase 2, only manual testing was performed. This is appropriate for Phase 2 because the primary goal is feasibility of kernel interactions and correctness of mapping + namespace staging, which can be directly observed through procfs and behavior checks.

#v(1em)

Capstone testing plan:

- Unit tests: pure logic (config parsing, profile resolution, command templating, allowlist resolution) with hermetic tests.
- Integration tests (Linux-only):
  - verify namespace membership via `/proc/<pid>/ns/*` handles (namespaces API exposes per-process namespace handles),
  - verify `uid_map`/`gid_map` semantics and enforcement (write-once behavior; expected failure modes),
  - verify network behavior inside `CLONE_NEWNET` (no host interfaces unless explicitly bridged; bridging via veth is possible when designed).
- Security regression tests: ensure no unintended host filesystem write paths, validate seccomp deny rules once introduced.

// -----------------------------------------------------------------
// SECTION: risks
// -----------------------------------------------------------------
#pagebreak()

= Risk, challenges, and mitigation <risk>

*Risk:* user namespaces disabled or restricted on target systems. While user namespaces are unprivileged in the general API design, real deployments may restrict them via system configuration; failure modes appear as `unshare()` errors @unshare-linux-manual-page-no-date.

*Mitigation:* detect at startup (probe `unshare(CLONE_NEWUSER)`), provide clear diagnostics, and document required kernel/sysctl settings.

#v(1em)

*Risk:* incomplete isolation if only user+net are used. The PoC shows feasibility but does not yet enforce filesystem least privilege; many real attacks target sensitive files in the home directory. Desktop sandboxing literature emphasizes the blast radius of a single compromised process within a user account @brodschelm-2022.

*Mitigation:* Capstone must add mount namespaces, explicit bind-mount allowlists, and ideally portals/mediated access patterns.

#v(1em)

*Risk:* capability overreach inside user namespace. A process gains a full set of capabilities in the new user namespace by default @unshare-linux-manual-page-no-date.

*Mitigation:* Capstone should drop/limit capabilities where possible and add seccomp filters to reduce the kernel attack surface.

#v(1em)

*Risk:* GUI isolation (X11). X11 lacks strong GUI-level isolation; a malicious client can potentially observe inputs/other client behavior, undermining the overall desktop security boundary @roukala-2014.

*Mitigation:* prioritize Wayland-native paths and explicitly document degraded guarantees under X11/XWayland; restrict GUI support scope if required.

// -----------------------------------------------------------------
// SECTION: outcomes
// -----------------------------------------------------------------
#pagebreak()

= Phase 2 outcomes and readiness for Phase 3 and Capstone <outcomes>

== Completed in Phase 2 <outcomes-completed>

- A working PoC demonstrates the critical feasibility path: rootless creation of user and network namespaces, correct UID/GID mapping via procfs (including `setgroups` handling), and reliable `exec()` of an arbitrary target command within the sandbox boundary.
- A concrete, code-derived architecture and data flow have been established, removing major uncertainty about namespace/mapping orchestration.

#v(1em)

== Readiness for Phase 3 (presentation) <outcomes-readiness>

- Phase 3 can present a live demo showing: (1) identity mapping + namespace-root inside sandbox, (2) network isolation effects, and (3) procfs evidence (`uid_map`/`gid_map`) alongside logs.
- Phase 3 deliverables will include: architecture diagram (from this report), demo script, and a short threat model statement derived from Phase 1 assumptions and the PoC's proven guarantees.

#v(1em)

== Capstone plan <outcomes-capstone-plan>

- Implement mount namespace isolation and filesystem allowlists (turn Phase 1 permissions into enforced binds), leveraging the general namespace model,
- add seccomp filtering (baseline syscall denylist/allowlist),
- add capability bounding and resource controls (`cgroups`) for defense-in-depth,
- build a profile store and a user-facing permission UI (Phase 1 usability goal; research indicates usability is key for adoption @brodschelm-2022),
- expand testing from manual checks to automated integration tests keyed on `/proc` and namespace handles.

// -----------------------------------------------------------------
// SECTION: references
// -----------------------------------------------------------------
#pagebreak()

#bibliography("refs.bib", style: "apa") <references>
