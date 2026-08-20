Abstract



Traditional Linux desktop environments lack a default, rootless security model capable of isolating individual applications without significant administrative overhead or performance degradation. While server-oriented containerization tools like Docker offer strong process isolation, they require complex configurations and daemon management that make them impractical for everyday command-line interface (CLI) and headless workflows. Conversely, existing desktop sandboxing tools often suffer from over-privileged default permissions, reliance on specific Linux Security Modules (LSMs), or expanded attack surfaces due to setuid-root binaries.



To address this security gap, this project introduces a lightweight, rootless application sandboxing runtime designed specifically for Linux CLI and headless applications. Operating entirely in user space without elevated root privileges or background daemons, the framework leverages core Linux kernel primitives—including user namespaces, network namespaces, mount namespaces, and Secure Computing Mode (seccomp) filters—to enforce strict process confinement. The system architecture employs a dual-process parent-child model synchronized over inter-process communication pipes to manage UID/GID mappings, isolate filesystem views via bind-mount allowlists, drop capabilities, and execute target binaries securely. Written primarily in Go and orchestrated using the Bazel build system, the runtime provides a simple, declarative CLI configuration interface that allows users to define per-execution security policies on demand. Programmatic testing suites continuously verify namespace membership, procfs mappings, and seccomp enforcement. By offering a distribution-agnostic, zero-trust execution environment, this project delivers a practical mechanism to mitigate malware, protect user privacy, and reduce the attack surface of untrusted binaries on modern Linux systems.



Problem context



On traditional Linux desktops, applications run within a single user context, inheriting full read and modify privileges across all personal files, system resources, and user data. Unlike mobile operating systems that enforce strict per-application sandboxing by default, desktop Linux lacks an accessible, widespread mechanism for on-demand application confinement.



While server-oriented container platforms provide robust isolation through kernel primitives, they rely on complex configurations, heavy filesystem overhead, and background daemons that are impractical for everyday desktop and command-line interface (CLI) workflows. On the other hand, existing desktop sandboxing tools introduce notable drawbacks:



\- Over-Privilege \& Store Lock-In: Solutions like Flatpak often grant broad permission overrides to maintain application compatibility, while remaining tied to specific package management ecosystems.

\- Distribution Dependencies: Frameworks like Snap rely heavily on AppArmor profiles, rendering core sandboxing capabilities unavailable on distributions using alternative security modules like SELinux.

\- Expanded Attack Surface \& Usability Barriers: Utilities like Firejail rely on large setuid-root binaries that introduce privilege escalation risks. Low-level tools like Bubblewrap require users to manually construct complex CLI flags for individual directory mounts, making daily interactive use tedious.



As third-party software risks and supply-chain threats grow, there is a distinct need for a lightweight, distribution-agnostic tool that allows regular users to isolate command-line binaries on demand using a simple, declarative policy model—without requiring superuser privileges or setuid binaries.





Solution implemented



To address the security and usability gaps of existing process isolation tools, a lightweight, rootless application sandboxing runtime was developed specifically for command-line and headless applications. The solution operates entirely in user space without requiring root privileges, setuid binaries, or background system daemons, utilizing native Linux kernel primitives to achieve secure process confinement.



The framework implements the following core engineering features and runtime mechanics:



\- Dual-Process Synchronization Architecture: Process orchestration uses a parent-child execution model linked via unidirectional inter-process communication pipes. The parent process coordinates host-side setups and configures kernel identity mappings within /proc/<pid>/uid\_map and /proc/<pid>/gid\_map. The child process executes the target binary via execvp after establishing its unprivileged namespace boundaries.

\- Kernel Namespace Disassociation: Confinement is established by unsharing kernel namespaces, including user namespaces for unprivileged UID/GID identity virtualization, network namespaces for network access control, and mount namespaces.

\- Filesystem View Isolation: Mount namespaces are configured to restrict the sandboxed application's file system visibility. The engine constructs restricted chroot or pivot\_root directory trees and applies bind-mount allowlists defined by user policies.

\- Capability Reduction \& System Call Filtering: POSIX capabilities are explicitly dropped from the bounding set prior to process execution. Additionally, Secure Computing Mode filters are applied to block dangerous or unnecessary system calls, reducing the available kernel attack surface.

\- Declarative CLI \& Profile Management: Application policies are managed through simple, human-readable static configuration profiles passed directly through a streamlined CLI entry point. This allows users to declare filesystem allowlists and network rules on a per-execution basis.

\- Automated Diagnostics \& Verification: A dedicated verification module inspects /proc/self/status and mapping endpoints within the container to programmatically validate active namespace boundaries, UID/GID assignments, and active seccomp filters during runtime execution.



Technologies used



The project leverages a modern, low-level system software stack and a hermetic build automation framework to deliver secure, rootless application sandboxing on Linux.

* Go (Golang): Serves as the primary implementation language, chosen for its low-level system call interfaces, strong concurrency primitives, memory safety, and static compilation model that avoids CGO overhead.
* Linux Kernel Confinement Primitives: Utilizes native kernel isolation mechanisms, including user namespaces, network namespaces, mount namespaces, POSIX capability bounding sets, and Secure Computing Mode filters.
* Bazel: Acts as the primary build automation and dependency management system, utilizing BUILD.bazel configurations alongside go\_library and go\_test rules to ensure hermetic, reproducible compilation and testing workflows.
* Starlark: Used as the embedded configuration language (10.3% of the codebase) to define Bazel build targets, isolated execution rules, and package dependencies deterministically.
* Python \& Shell Scripting: Python is retained for validation benchmarking and test fixtures, while Shell scripts handle test orchestration, environment bootstrapping, and /proc verification workflows.
* Go Extended System Libraries: Incorporates golang.org/x/sys/unix for Unix kernel parameter manipulation and golang.org/x/sys/execabs to prevent executable path spoofing vulnerabilities during process invocation.



outcomes and results



The development of the rootless application sandboxing runtime yielded several key technical outcomes, successfully addressing the isolation gaps inherent in traditional Linux desktop environments:



* Successful Rootless Execution: Delivered a fully functional, user-space sandboxing engine capable of isolating command-line and headless applications using CLONE\_NEWUSER and unprivileged Linux kernel primitives, eliminating the need for elevated root privileges, background system daemons, or setuid-root binaries.
* Effective Multi-Domain Isolation: Successfully established isolated runtime environments with customized network access rules, restricted filesystem views via configurable bind-mount allowlists, reduced capability sets, and active seccomp system call filtering.
* Robust Dual-Process Orchestration: Implemented a stable parent-child synchronization model over unidirectional IPC pipes, reliably executing target binaries via execvp while safely writing UID/GID mappings in /proc/<pid>/uid\_map and /proc/<pid>/gid\_map.
* Distribution-Agnostic Portability: Achieved a portable security solution that operates across Linux distributions with unprivileged user namespaces enabled, functioning independently of specific Linux Security Modules like AppArmor or SELinux.
* Hermetic Build and Automated Verification: Integrated the codebase into a Bazel build system utilizing Go rules. Verified sandbox integrity through programmatic diagnostic testing suites that continuously monitor namespace membership, /proc mappings, and seccomp filter enforcement.





CHAPTER 1



Overview of the Project



This project introduces a lightweight, rootless application sandboxing runtime designed specifically for command-line and headless Linux applications. Implemented primarily in Go (83.0%) and built using the Bazel build system, the framework operates entirely in user space without requiring elevated root privileges, background daemons, or setuid-root binaries. The engine utilizes a dual-process parent-child architecture synchronized over inter-process communication pipes to manage Linux kernel isolation primitives—specifically user namespaces, network namespaces, mount namespaces, capability reductions, and Secure Computing Mode filters. Configuration is driven by simple, static policy files passed directly through a command-line interface, providing on-demand, fine-grained process confinement.



Problem Statement and Motivation



Traditional Linux desktop environments follow a single-user security model where applications inherit the full read and write permissions of the executing user account. Consequently, a compromised binary or malicious package gains unrestricted access to personal files, sensitive data, and host resources. While mobile operating systems enforce strict per-application sandboxing by default, traditional Linux desktops lack a widely adopted, default security architecture offering equivalent application confinement.



Existing isolation tools present significant trade-offs:

* Server Containers: Designed for DevOps and microservices, these tools introduce heavy daemon setups, complex workflows, image builds, and high filesystem overhead that make them impractical for everyday CLI tasks.
* Desktop Packaging Frameworks: Flatpak applications frequently override sandbox restrictions or request broad permissions. Snap relies heavily on AppArmor profiles, which limits its sandboxing functionality on non-AppArmor distributions like Fedora. Furthermore, both platforms are tied to specific app stores and package formats.
* Low-Level Utilities: Firejail uses large setuid-root binaries that increase the privilege-escalation attack surface. Bubblewrap is secure and rootless, but requires users to manually assemble complex, low-level CLI flags for directory mounts during daily interactive use.



As supply-chain threats and third-party software risks grow, there is a clear motivation for a lightweight, distribution-agnostic tool that enables terminal users to isolate local CLI binaries on demand using declarative static configuration files without needing superuser privileges.



Objectives of the Capstone



Primary Objectives:

* Secure, Rootless Sandbox Runtime: Develop a core sandbox engine that isolates CLI applications using kernel primitives without superuser privileges or background daemons.
* Simple CLI Configuration Interface: Build a streamlined CLI enabling users to launch and configure sandboxed applications via straightforward flags and declarative configuration profiles.
* CLI \& Headless Application Reliability: Ensure sandboxed command-line utilities and headless applications run reliably within the constrained environment without unexpected breakage.



Secondary Objectives:

* Provide network policy toggles beyond simple on/off switches.
* Implement automated programmatic verification suites to test namespace membership, /proc mappings, and seccomp enforcement.



Scope of Implementation



* Application Focus: Exclusively command-line and headless applications.
* Target Platform: Modern Linux desktop/server environments with unprivileged user namespaces enabled.
* Core Isolation Capabilities: User namespace creation and UID/GID identity virtualization; network isolation; filesystem view isolation via mount namespaces and bind-mount allowlists; and system call filtering via seccomp and POSIX capability reduction.
* Configuration Management: Lightweight, human-readable static configuration profiles passed directly through the CLI.
* System Boundaries: Operates entirely in user space without requiring root privileges, setuid binaries, or specific Linux Security Modules like AppArmor or SELinux.  



Organization of the Report



The report is organized into structured sections covering the design, implementation, and evaluation of the sandboxing framework:

* Introduction \& Problem Context: Establishes the background of Linux desktop security, details the gaps in existing tools, and outlines the objectives and scope.
* System Architecture \& Design: Explains the dual-process parent-child model, IPC synchronization pipes, and kernel mapping mechanics.
* Modular Implementation: Details the design and responsibilities of core system modules .
* Technical Stack \& Build Automation: Summarizes the progamming language distribution, external libraries, and the Bazel build system.
* Verification \& Outcomes: Presents evaluation results, programmatic testing verification, and comparative advantages over existing solutions. 



CHAPTER 2



2.1 System architecture and design



2.2 Technology stack



Programming Languages



* Go (83.0%): Serves as the primary implementation language, selected for its low-level Unix system call interfaces, efficient concurrency model, memory safety, and static compilation without CGO overhead.
* Starlark (10.3%): Embedded configuration language used to define Bazel build targets, execution rules, and security profiles deterministically.
* Python (6.6%): Used for proof-of-concept validation, performance benchmarking, and test fixtures.
* Shell (0.1%): Utility scripts for automated integration testing, setup bootstrapping, and /proc filesystem verification.



Frameworks \& Libraries



* Go Standard Library: Core runtime modules used for system call execution, process management, file I/O, and test orchestration.
* golang.org/x/sys/unix: Low-level Go interface providing access to Unix system calls, kernel namespace parameters, and sandboxing primitives.
* golang.org/x/sys/execabs: Security library used to resolve executable binary paths explicitly, preventing path spoofing vulnerabilities during execution.



Tools \& Platforms



* Bazel (BUILD.bazel): Primary build automation system using rules like go\_library and go\_test for reproducible, hermetic compilation and testing workflows.
* Linux Kernel Primitives: Native OS isolation tools, including user, network, mount, PID, UTS, and IPC namespaces, chroot/pivot\_root, POSIX capability bounding sets, and seccomp filters.
* Git \& Linux OS: Git for version control and source management; modern Linux distributions with unprivileged user namespaces enabled as the target execution platform.



2.3 System modules



Module-Wise Description



* CLI Entry \& Argument Parsing Module: Serves as the primary interface for user interaction. It parses command-line flags (such as target binary paths, network toggles, and configuration file locations), validates platform dependencies (ensuring execution on Linux with unprivileged user namespaces enabled), and initializes logging and diagnostics.
* Configuration \& Profile Parser Module: Reads and parses static JSON or TOML policy profiles. It converts declarative configuration settings—such as filesystem bind-mount allowlists, network policies (host vs. none), and capability restrictions—into structured runtime parameters passed to the sandbox launcher.
* Parent Synchronization \& UID/GID Mapping Module: Manages process orchestration and kernel mapping writebacks. It forks the child process, listens for readiness signals across unidirectional IPC pipes, writes user and group mappings to /proc/<pid>/uid\_map, /proc/<pid>/gid\_map, and /proc/<pid>/setgroups, and signals the child process to proceed.
* Child Sandbox Execution Module: Prepares and enforces the isolated process environment. It invokes kernel namespace disassociation, drops supplementary group memberships, waits for parent synchronization signals, establishes namespace root identities, and executes the target application using execvp.
* Filesystem \& Mount Isolation Module: Configures mount namespaces to restrict the sandboxed process's view of the host filesystem. It handles private mount points, constructs chroot or pivot\_root directory trees, and applies bind-mount allowlists specified in the configuration profile.
* Seccomp \& Capability Bounding Module: Restricts hardware and kernel operations within the sandbox. It configures Secure Computing Mode filters to block prohibited system calls and drops POSIX capabilities from the bounding set before handing execution over to the target binary.
* Diagnostics \& Verification Module: Provides runtime verification and debugging capabilities. It inspects /proc/self/uid\_map, /proc/self/gid\_map, and /proc/self/status inside the sandboxed environment to log and verify active namespace boundaries and capability sets during execution.



Functional Flow



* Initialization \& Policy Loading: The user invokes the runtime via the cli module, passing arguments and policy profile paths. The cli module validates the platform, and the config module parses the specified policy parameters.
* Child Process Forking: The runtime forks into a parent-child process pair linked by unidirectional IPC pipes. The child process immediately disassociates its namespaces (CLONE\_NEWUSER, CLONE\_NEWNET, mount namespaces) and pauses, sending a readiness signal over IPC.
* Identity Mapping Writeback: Upon receiving the child's readiness signal, the parent module writes user and group mappings into /proc/<pid>/uid\_map and /proc/<pid>/gid\_map. Once written, the parent signals the child to continue.
* Environment Isolation: The child module resumes, establishes its virtual root identities, and hands control to the mount module to construct chroot/pivot\_root directory trees and apply bind-mount allowlists.
* Security Hardening: The security module drops POSIX bounding capabilities and compiles/attaches seccomp filters to restrict system call access.
* Diagnostic Check \& Target Execution: The diag module inspects local /proc/self/ entries to verify namespace and seccomp boundaries. Finally, the child process executes the target CLI binary via execvp, replacing itself with the sandboxed application while the parent waits to capture and report the exit code.



2.4 Key algorithms / logic



Parent-Child Process Orchestration \& Identity Mapping



Because unprivileged user namespaces initially start without identity mappings, the child process cannot map its host UID/GID to virtual root- until the parent process writes to /proc/<child\_pid>/uid\_map and /proc/<child\_pid>/gid\_map from the host side. This algorithm uses a synchronized IPC pipe handshake to prevent race conditions during initialization.



SynchronizedSandboxLaunch(Config, TargetBinary, Args)

INPUT: Config (parsed security policy), TargetBinary (path), Args (arguments)

OUTPUT: ExitCode (integer exit code of target binary)



&#x20;Create unidirectional IPC Pipes: 

&#x20;    pipe\_child\_to\_parent (read\_fd1, write\_fd1)

&#x20;    pipe\_parent\_to\_child (read\_fd2, write\_fd2)



&#x20;pid = ForkProcess()



&#x20;IF pid == 0 THEN  // CHILD PROCESS

&#x20;    Close(read\_fd1)

&#x20;    Close(write\_fd2)

&#x20;    

&#x20;    // Disassociate namespaces

&#x20;    UnshareNamespaces(CLONE\_NEWUSER | CLONE\_NEWNET | CLONE\_NEWNS | CLONE\_NEWPID)

&#x20;    

&#x20;   // Signal parent that namespaces are unshared

&#x20;   WritePipe(write\_fd1, "CHILD\_READY")

&#x20;   Close(write\_fd1)

&#x20;   

&#x20;   // Wait for parent UID/GID mapping writeback

&#x20;   WaitPipeSignal(read\_fd2, "PARENT\_MAPPED")

&#x20;   Close(read\_fd2)

&#x20;   

&#x20;   // Execute child environment isolation and execvp

&#x20;   ExecuteChildSandbox(Config, TargetBinary, Args)



&#x20;ELSE IF pid > 0 THEN  // PARENT PROCESS

&#x20;   Close(write\_fd1)

&#x20;   Close(read\_fd2)

&#x20;   

&#x20;   // Await child readiness

&#x20;   WaitPipeSignal(read\_fd1, "CHILD\_READY")

&#x20;   Close(read\_fd1)

&#x20;   

&#x20;   // Write UID/GID maps via procfs

&#x20;   HostUID = GetUID()

&#x20;   HostGID = GetGID()

&#x20;   WriteFile("/proc/" + pid + "/setgroups", "deny")

&#x20;   WriteFile("/proc/" + pid + "/uid\_map", "0 " + HostUID + " 1")

&#x20;   WriteFile("/proc/" + pid + "/gid\_map", "0 " + HostGID + " 1")

&#x20;   

&#x20;   // Signal child to resume execution

&#x20;   WritePipe(write\_fd2, "PARENT\_MAPPED")

&#x20;   Close(write\_fd2)

&#x20;   

&#x20;   // Monitor child process termination

&#x20;   ExitCode = WaitProcess(pid)

&#x20;   RETURN ExitCode

END IF



Filesystem \& Mount Namespace Construction



To isolate the file system view, the runtime constructs a private mount environment. It changes propagation to private to prevent host leakage, creates a minimal target root directory tree, bind-mounts essential system directories (e.g., /bin, /lib, /usr) along with user-specified allowlist paths, and uses pivot\_root or chroot to jail the process.



ConstructMountNamespace(Config)

INPUT: Config (contains BindMountAllowlist, IsolatedRootPath)



&#x20;// Ensure mount propagation changes do not affect host

&#x20;Mount("", "/", "", MS\_REC | MS\_PRIVATE, "")



&#x20;NewRoot = Config.IsolatedRootPath

&#x20;CreateDirectory(NewRoot)

&#x20;Mount("tmpfs", NewRoot, "tmpfs", 0, "size=10M")



&#x20;// Bind-mount allowed system \& user directories

&#x20;FOR EACH Entry IN Config.BindMountAllowlist DO

&#x20;    TargetPath = JoinPaths(NewRoot, Entry.HostPath)

&#x20;    CreateDirectoryOrFile(TargetPath)

&#x20;    Flags = MS\_BIND | MS\_REC

&#x20;   IF Entry.IsReadOnly THEN

&#x20;       Flags = Flags | MS\_RDONLY

&#x20;   END IF

&#x20;   Mount(Entry.HostPath, TargetPath, "", Flags, "")

&#x20;END FOR



&#x20;// Pivot into new isolated filesystem root

&#x20;OldRoot = JoinPaths(NewRoot, ".old\_root")

&#x20;CreateDirectory(OldRoot)

&#x20;PivotRoot(NewRoot, OldRoot)

&#x20;Chdir("/")



&#x20;// Unmount and remove old host root reference

&#x20;Unmount("/.old\_root", MNT\_DETACH)

&#x20;RemoveDirectory("/.old\_root")



Seccomp System Call Filtering \& Capability Reduction



Before executing the target binary via execvp, the child process must permanently drop privileges. It drops POSIX capabilities from its bounding set and installs Berkeley Packet Filter (BPF) programs via seccomp to restrict access to unsafe system calls (e.g., blocking key-ring operations or raw socket creation).



ApplySecurityRestrictions(Config)

INPUT: Config (contains AllowedSyscalls, CapabilityDropList)



&#x20;// Drop POSIX Capabilities from Bounding Set

&#x20;FOR EACH Cap IN Config.CapabilityDropList DO

&#x20;    CapDropBoundingSet(Cap)

&#x20;END FOR



&#x20;// Prevent process from gaining new privileges via setuid binaries

&#x20;SetPrctl(PR\_SET\_NO\_NEW\_PRIVS, 1, 0, 0, 0)



&#x20;// Compile BPF Seccomp Filter

&#x20;BPF\_Filter = InitializeBPFFilter(DEFAULT\_ACTION\_KILL)

&#x20;AddBPFRule(BPF\_Filter, ALLOW, SYS\_READ)

&#x20;AddBPFRule(BPF\_Filter, ALLOW, SYS\_WRITE)

&#x20;AddBPFRule(BPF\_Filter, ALLOW, SYS\_EXECVE)

&#x20;AddBPFRule(BPF\_Filter, ALLOW, SYS\_EXIT)



&#x20;FOR EACH Syscall IN Config.AllowedSyscalls DO

&#x20;    AddBPFRule(BPF\_Filter, ALLOW, Syscall)

&#x20;END FOR



&#x20;//: Load Seccomp BPF filter into Linux kernel

&#x20;ApplySeccompFilter(BPF\_Filter)



&#x20;// Replace process image with target CLI executable

&#x20;Execvp(Config.TargetBinary, Config.Args)



2.5 Screenshots / code snippets



CHAPTER 3

