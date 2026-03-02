#import "@preview/fletcher:0.5.8" as fletcher: diagram, edge, node

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

  #text(size: 20pt, weight: "bold")[Linux Sandboxing III]

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
    Phase III --- Implementation Readiness and Validation \
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

== Project Context <intro-context>

#v(0.5em)

- This phase is carefully scoped. The Proof-of-Concept (PoC) demonstrates that the chosen approach is implementation-ready, based on real kernel interfaces and a working CLI pipeline.

- The broader desktop sandbox vision (filesystem isolation, GUI handling, seccomp hardening, profile store, etc.) remains explicitly deferred to the capstone phase.

#v(1.5em)

== Purpose of Phase 3 <intro-purpose>

#v(0.5em)

=== Demonstrate implementation readiness

- Confirm that a practical, rootless sandbox launch flow is implementable with stable Linux primitives (namespaces + UID/GID mapping rules + deterministic parent/child staging).

=== Validate design choices through PoC implementation

- Validate the core design choice from Phase II: a two-process (parent/child) launcher that:
  - unshares into a user namespace (optionally network namespace),
  - applies UID/GID mappings,
  - switches to root identity inside namespace and execs the target command,
  - and uses procfs evidence to validate the boundary.

=== Assess reliability, limitations, and future potential

- Explicitly document what is and is not guaranteed by a user+net namespace only PoC, since filesystem least-privilege and syscall filtering are not yet present.

// -----------------------------------------------------------------
// SECTION: work
// -----------------------------------------------------------------
#pagebreak()

= Work Completed in Phases I and II <work>

#v(0.5em)

== Key outcomes from Phase I (problem definition & planning)

- *Problem statement and motivation*
  - Established that desktop Linux applications typically inherit broad user-level privileges; compromise of one app can expose a wide set of user secrets and mutable files.
  - Motivated a desktop-friendly sandbox concept aligned with usability requirements emphasized in existing research @brodschelm-2022.
- *Objective framing*
  - Defined the capstone target as an Android-like permission model backed by Linux isolation primitives (namespaces, seccomp, etc.), with emphasis on rootless operation for usability reasons.
- *Planning artifacts*
  - Captured risks and mitigations early (technical complexity, user namespace availability restrictions, integration challenges, and the need to stage a minimal workable core early before hardening).

== Key outcomes from Phase II (design & proof of concept)

- *Architecture and control flow*
  - Produced a concrete design: parent process orchestrates, child process unshares, parent writes mappings, child becomes namespace-root and execs.
- *Feasibility validation*
  - Demonstrated feasibility of:
    - rootless user namespaces,
    - network namespace isolation effects,
    - and verification using `/proc/*` mapping files and diagnostics.
- *Deferred scope (capstone)*
  - Phase II explicitly deferred: mount namespace filesystem isolation, seccomp filtering, capability bounding, GUI mediation, and automated testing (to capstone).

// -----------------------------------------------------------------
// SECTION: implementation
// -----------------------------------------------------------------
#pagebreak()

= Implementation Overview <implementation>

#v(0.5em)

== Implementation status

- *Fully implemented*
  - CLI-driven sandbox launcher that executes an arbitrary command under:
    - user namespace isolation, and
    - optional network namespace isolation (internet on/off mode).
  - Deterministic orchestration via parent/child handshake (pipe-based readiness + `ACK`), aligning with kernel rules around mapping establishment.
  - UID/GID mapping via the `newuidmap`/`newgidmap` helper tools, using `/etc/subuid` and `/etc/subgid` delegation.
  - Diagnostics to log process identity and relevant procfs state for manual validation (maps + selected `/proc/self/status` keys).\
- *Partially Implemented*
  - Production packaging and hermetic runtime: the repository provides basic Bazel rules and scripts for packaging.
- *Planned but not implemented (deferred to capstone)*
  - Filesystem isolation (mount namespaces, bind-mount allowlists).
  - Syscall filtering (seccomp), capability bounding/dropping, cgroups controls.
  - GUI isolation and controlled desktop integration (Wayland-leaning direction, X11 caveats).
  - Automated tests (unit + integration) and CI pipelines.

== Implemented features

- *Core application functionality*
  - Launch a target command in a sandboxed context by:
    - `fork()` in the parent,
    - `unshare(CLONE_NEWUSER | optional CLONE_NEWNET)` in the child,
    - write UID/GID maps in parent,
    - set `uid=0`,`gid=0` inside the namespace,
    - finally `execvp()` the target.
  - Key design validation: using `CLONE_NEWUSER` together with other `CLONE_NEW*` flags in `unshare()` syscall.
- *Data handling and persistence*
  - No persistent profile store is implemented in Phase III.
  - Configuration is passed transiently via CLI arguments (a deliberate PoC simplification).
- *User interaction flows*
  - CLI usage supports:
    - selecting network policy (`host` vs `none`),
    - specifying command argv to execute.
- *Integration with external services/tools*
  - Integrates with OS-provided UID/GID mapping helpers:
    - `newuidmap` writes `/proc/[pid]/uid_map` after validating allowed subuid ranges,
    - `newgidmap` writes `/proc/[pid]/gid_map` after validating allowed subgid ranges.
  - Implements required `setgroups deny` handling when relevant to gid mapping safety constraints.

#v(1.5em)

_(See #link(<implementation-architecture>)[next page].)_

#pagebreak()

== Visual PoC architecture <implementation-architecture>

#v(1.5em)

#diagram(
  node-stroke: 1pt,
  node-corner-radius: 2pt,

  node((0, 0), [User (CLI)]),
  edge("-|>", [config]),
  node((0, 1), [Parent process (host namespace)]),
  edge("-|>"),
  node((0, 2), [
    create pipes\
    `fork()`
  ]),
  edge((0, 2), (1, 2), (1, 3), "-|>", [config]),
  edge("-|>", [wait for "`READY`" from child]),
  node((0, 3), [
    Parent writes idmaps\
    signal "`ACK`" to child
  ]),
  edge((0.1, 3), (0.1, 5), (1, 5), "-|>", [`ACK`], dash: "dashed"),
  edge((-0.1, 3), (-0.1, 6), "-|>", [wait for child to finish]),
  node((0, 6), [exit with child's exit code]),

  node((1, 3), [Child process]),
  edge("-|>", [unshare flags]),
  node((1, 4), [
    `unshare()`\
    signal "`READY`" to parent
  ]),
  edge((1, 4), (0.2, 4), (0.2, 3), "-|>", [`READY`], dash: "dashed"),
  edge("-|>", [wait for "`ACK`" from parent]),
  node((1, 5), [Child sets uid/gid = 0 in namespace]),
  edge("-|>"),
  node((1, 6), [`execvp(target command)`]),
  edge((1, 6), (0, 6), "-|>", [`EXIT_CODE`], dash: "dashed"),
)

#pagebreak()

_(Continued @implementation.)_

== Bazel build and packaging overview

- *Why Bazel is used*
  - Supports reproducible builds and packaging across environments; Phase I anticipated build tooling as a mitigation against "works on my machine" integration risk.
- *Developer build/run flow*
  - Run the CLI demo directly via:
    - `bazel run //sandbox:demo -- <args>`
- *Production build flow*
  - The repository includes:
    - `prod-build.sh` invoking `bazel build --build_python_zip=true ...`
    - a packaging target `//pkg:study_project_dist` that bundles the zipapp output.

// -----------------------------------------------------------------
// SECTION: testing
// -----------------------------------------------------------------
#pagebreak()

= System Validation and Testing <testing>

== Testing strategy

- *Primary method: manual testing*
  - Rationale: feasibility and correctness of namespace/mapping mechanics can be validated directly through procfs mapping files, id output, and behavioral network tests.
- *Unit tests/integration tests*
  - Not implemented in this phase (explicitly deferred to capstone).
  - This matches the PoC goal: validate kernel interactions and orchestration rather than hardening edge cases.

== Representative test cases and results

- *Identity remapping: host user #sym.arrow namespace-root*
  - Feature tested: user namespace creation + post-map `setresuid(0)`/`setresgid(0)`
  - Expected behavior:
    - outside sandbox: id reports normal user UID/GID (e.g., `1000`),
    - inside sandbox: id reports `uid=0`,`gid=0` (namespace-root),
    - but this must not imply host-root privileges.
  - Observed result: matches expected (see #link(<testing-demos-identity>)[screenshot below]).
  - Status: *Pass*

- *Mapping evidence: procfs `uid_map`/`gid_map` validation*
  - Feature tested: UID/GID mapping correctness (procfs mapping files provided by kernel)
  - Expected behavior:
    - `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map` show the mapping lines applied to the sandboxed process.
  - Observed result: mapping file inspection matches expected mapping semantics (see #link(<testing-demos-mapping>)[screenshot below]).
  - Status: *Pass*

- *Network "deny" mode: no external DNS reachability*
  - Feature tested: network namespace isolation with `CLONE_NEWNET`
  - Expected behavior:
    - in a new network namespace with no additional setup, there are no usable external interfaces; connectivity and DNS resolution should fail unless explicitly configured.
  - Observed result: `nslookup` fails inside sandbox with "network unreachable," while host `nslookup` succeeds (see #link(<testing-demos-network>)[screenshot below]).
  - Status: *Pass*

- *Staging correctness: parent/child handshake*
  - Feature tested: deterministic "`READY` #sym.arrow parent writes maps #sym.arrow `ACK`" staging
  - Expected behavior:
    - child blocks until mappings are applied, since user namespace begins with no mappings and mapping setup has ordering constraints.
  - Observed result: logs show child "ready" then continues after `ACK`, consistent with staged design (see #link(<testing-demos-logs>)[screenshot below]).
  - Status: *Pass*

#v(1.5em)

_(See #link(<testing-demos>)[next page].)_

#pagebreak()

== Visual evidence from PoC demonstrations <testing-demos>

=== Identity transformation and execution inside sandbox <testing-demos-identity>

#image("poc-demo-1-identity.png")

*Observation:* The UID/GID are 1000 (user) on the host but appear as 0 (root) inside the sandbox. The `id` comamnd executes successfully inside the sandbox.

#pagebreak()

=== File ownership correspondance <testing-demos-fileown>

#image("poc-demo-2-fileown.png")

*Observation:* The file appears to be owned by UID/GID 0 (root) inside the sandbox, but it is actually owned by UID/GID 1000 (user) on the host.

#pagebreak()

=== Procfs mapping inspection <testing-demos-mapping>

#image("poc-demo-3-mapping.png")

*Observation:* The sandbox UID/GID 0 (root) correctly maps to host UID/GID 1000 (user).

#pagebreak()

=== Network isolation `nslookup` failure in deny mode <testing-demos-network>

#image("poc-demo-4-network.png")

*Observation:* The `nslookup` command succeeds on both the host and inside the sandbox when using "host" network mode, but it fails inside the sandbox when using "none" network mode.

#pagebreak()

=== Verbose logging <testing-demos-logs>

#image("poc-demo-5-logs.png")

*Observation:* The child process correctly sends "`READY`" to the parent when it is time to perform UID/GID mapping, then it waits for the parent complete the mapping. The parent sends "`ACK`" once the UID/GID mapping is done, after which the child proceeds correctly.

#pagebreak()

== Validation summary against defined requirements

- *Meets (PoC scope)*
  - User namespace creation and semantics (root inside namespace, unprivileged outside).
  - Network namespace isolation toggle (host vs none).
  - Deterministic staging for mapping setup.
  - Observable diagnostics via `/proc` state.
- *Deferred to capstone*
  - Filesystem sandbox; the tool does not yet enforce least privilege over `$HOME` or other user data.
  - Seccomp filtering, capability bounding, or other defense-in-depth layers.

// -----------------------------------------------------------------
// SECTION: performance
// -----------------------------------------------------------------
#pagebreak()

= Performance and Reliability Analysis <performance>

== Responsiveness

- The runtime flow is essentially: `fork()` + `unshare()` + small amount of procfs/utility work + `execvp()`.
- Namespace creation is a standard kernel mechanism commonly used as a container isolation basis.
- The Python API used (`os.unshare`) exists specifically to expose the underlying kernel mechanism in a direct way and is available starting Python 3.12+.

== Stability

- The staging design reduces race conditions:
  - child signals readiness only after namespace creation,
  - parent applies UID/GID mappings,
  - child proceeds only after `ACK`.
- The design aligns with the documented requirement that `CLONE_NEWUSER` operations must be performed by a non-threaded process @unshare-linux-manual-page-no-date; using a `fork()`-then-`unshare()` structure is consistent with this constraint.

== Resource usage

- *CPU/memory overhead (qualitative)*
  - The PoC does not allocate significant in-memory state and does not process large datasets.
  - The only expected incremental cost in a production distribution is zipapp bootstrapping when packaged as a self-executable zipapp. (No benchmark data is provided in Phase III; performance measurement is not a core Phase III goal.)
- *Network-mode "none" behavior*
  - The "no internet" behavior comes from the kernel-default state of new network namespaces: they start with loopback only and require explicit setup for connectivity; without setup, "network unreachable" errors are expected and observed.

== Reliability

- *Dependency brittleness*
  - `newuidmap`/`newgidmap` must be present and correctly configured; they validate allowed ranges using `/etc/subuid` and `/etc/subgid`. Missing entries or missing tools will break sandbox startup.
- *System policy brittleness*
  - Some systems restrict or disable user namespaces via sysctls/limits; `unshare(CLONE_NEWUSER)` will fail in those cases.

// -----------------------------------------------------------------
// SECTION: risks
// -----------------------------------------------------------------
#pagebreak()

= Risk Analysis and Mitigation Review <risks>

== Identified risks

- *User namespaces disabled/restricted*
  - kernel/distribution policies can disable or limit unprivileged user namespaces; this is a known deployment friction for rootless tooling.
- *Dependency on external helpers*
  - Relying on `newuidmap`/`newgidmap` introduces system misconfiguration risk (installation, permissions, delegated subid configuration).
- *Incomplete isolation with user+net only*
  - Without mount namespaces/seccomp, the sandbox boundary is not a full desktop sandbox; the tool demonstrates feasibility, not complete containment.
- *GUI isolation risk (capstone)*
  - X11's trust model makes strong GUI isolation difficult; process sandboxing does not automatically prevent cross-client snooping if the X socket is accessible.

== Mitigation effectiveness

- *Successfully mitigated in Phase III*
  - Namespace orchestration risk reduced via deterministic staging and diagnostic evidence hooks.
  - Network isolation validated behaviorally and aligns with documented semantics of network namespaces.
  - Mapping correctness through mature tooling (`newuidmap`/`newgidmap`) that explicitly enforces allowed delegation ranges.
- *Risks to be addressed in capstone*
  - Full filesystem least-privilege and syscall-reduction (seccomp) risks remain open, as they are capstone scope.
  - Automated regression testing is not present, so behavior relies on manual validation; this is acceptable for PoC but not for production hardening.

// -----------------------------------------------------------------
// SECTION: limitations
// -----------------------------------------------------------------
#pagebreak()

= Limitations, Constraints, and Future Enhancements <limitations>

== Current limitations (Phase III PoC)

=== Security limitations

- No filesystem sandboxing: the sandboxed process still sees the host filesystem view (no mount namespace), so sensitive file exposure is not addressed yet.
- No seccomp syscall filtering or capability bounding/dropping: defense-in-depth is not yet implemented.

=== Product limitations
- CLI-only; no desktop integration, no profile persistence, no user-facing permission UI.

=== Operational constraints

- Linux-only (namespaces and `unshare()` are Linux primitives).
- Requires:
  - kernel support for user and network namespaces,
  - user namespace enablement/limits not set to restrictive values,
  - `newuidmap`/`newgidmap` + delegated `/etc/subuid` and `/etc/subgid` ranges configured.

== Assumptions made in development

- Target systems are Linux distributions where unprivileged user namespaces are permitted (or can be enabled by policy).
- Subuid/subgid delegation exists for the executing user if multi-ID mapping is desired.
- Phase III is a feasibility slice rather than a hardened, end-user product.

== Future enhancements and scope extension (capstone)

- *Filesystem isolation*
  - Add mount namespace support (bind-mount allowlists/denylists) as the primary mechanism to reduce file access blast radius.
- *Kernel attack-surface reduction*
  - Add seccomp deny/allow policies for syscall reduction.
  - Add capability bounding/dropping to reduce what namespace-root can do.
- *Network policy hardening*
  - Extend "`none`/`host`" into multi-profile network policies (e.g., allow DNS only, allow local LAN only, or veth-based controlled egress). Network namespaces support such designs via veth pairs and explicit routing/firewall configuration.
- *Testing and reproducibility*
  - Add unit tests for config parsing and mapping plan generation.
  - Add integration tests to assert expected namespace membership and procfs mappings under controlled conditions.
- *GUI integration (capstone)*
  - When GUI is introduced, prioritize Wayland-based approaches; document degraded guarantees under X11 due to its permissive trust model.

// -----------------------------------------------------------------
// SECTION: outcomes
// -----------------------------------------------------------------
#pagebreak()

= Learning Outcomes, Final Deliverables, and Conclusion <outcomes>

== Learning outcomes and reflections

- *Kernel-interface literacy*
  - Gained practical understanding of Linux kernel APIs (especially namespaces).
- *Rootless identity mapping mechanics*
  - Learned how UID/GID mapping is established and validated, including delegated subid ranges and the role of helper utilities that write procfs mapping files.
- *Correct orchestration patterns*
  - Validated the necessity of two-process staging and deterministic synchronization for correct mapping establishment and predictable behavior.
- *Build and packaging systems*
  - Applied Bazel-based Python builds with precompilation and packaging rules to create reproducible dev/prod build paths.

== Final deliverables

- Phase III report (this document): https://drive.google.com/file/d/1SvL2lV2tAIeZPUtfnADApHoK-Z-eAehH/view?usp=drive_link

- GitHub repository snapshot: https://drive.google.com/file/d/1Ws_VJLfbjk2fDZaxiQ_PVdd04CgmfXco/view?usp=drive_link

- Demo binary package (python zipapp): https://drive.google.com/file/d/17s6YLtpP4LKTe80CkkWgj32Ojc5dtoV7/view?usp=drive_link

== Conclusion

- Phase III successfully demonstrates implementation readiness for the selected approach:
  - rootless namespace setup using documented kernel mechanisms,
  - deterministic mapping orchestration,
  - and observable validation via procfs and behavioral tests.

- The PoC is ready for evaluation as a feasibility slice, with clearly-scoped limitations:
  - it proves the correctness of the launch-and-isolate pipeline for user+network namespaces,
  - while leaving full desktop sandbox guarantees (filesystem least privilege, syscall filtering, GUI security) to the capstone extension.

// -----------------------------------------------------------------
// SECTION: references
// -----------------------------------------------------------------
#pagebreak()

#bibliography("refs.bib", style: "apa") <references>
