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
  }
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

  #text(size: 20pt, weight: "bold")[Linux Sandboxing]

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
    Phase I --- Project Identification and Planning \
    Dept. of Computer Science, BITS Pilani
  ]
]

// -----------------------------------------------------------------
// SECTION: table of contents
// -----------------------------------------------------------------
#pagebreak()
#outline()

// -----------------------------------------------------------------
// SECTION: abstract
// -----------------------------------------------------------------
#pagebreak()
= Abstract

Modern operating systems have adopted sandboxing to isolate applications for security, yet Linux desktop environments lack an easy-to-use sandbox for everyday users. This project addresses the Linux desktop sandboxing problem --- the need to confine applications so that a compromised or malicious program cannot access all user data or damage the system. The motivation stems from observing that server-side solutions (Docker, Kubernetes, etc.) leverage robust kernel isolation features but are impractical for typical desktop workflows. We propose a user-friendly sandboxing tool that brings container-like isolation to Linux desktop applications. Our approach combines a simple permission-based user interface with a secure backend that leverages Linux kernel namespaces, seccomp filters, and related technologies for process isolation. By enabling per-application restrictions (e.g. file system access, network access), we aim to mitigate malware and contain vulnerabilities within apps. The expected outcome is a desktop sandbox framework that improves security for Linux users without requiring specialized expertise --- essentially bridging the gap between the strong sandbox models of mobile/ChromeOS and the flexibility of a traditional Linux desktop @brodschelm-2022. 

// -----------------------------------------------------------------
// SECTION: background
// -----------------------------------------------------------------
#pagebreak()
= Background and Motivation <background>

== Problem Statement <background-problem>

Linux desktop users today run most applications with full access to their account, meaning any exploited application can read or modify all the user's files and even interfere with other processes @brodschelm-2022. Unlike mobile operating systems (Android, iOS) where each app runs in a restricted sandbox by design @dunlap-2022, a typical Linux GUI or CLI application inherits the user's privileges and runs with isolation by default. For servers and development environments, containerization tools like Docker and Podman exist, but these are not designed for casual desktop use --- they require complex setup and target DevOps workflows. As a result, there is no widely adopted way to sandbox applications on the Linux desktop @brodschelm-2022. This gap leaves desktop Linux users exposed: any malicious or vulnerable app can potentially access personal data, spy on other applications, or encrypt files for ransom. Other desktop operating systems have attempted solutions --- Windows introduced Universal Windows Platform (UWP) apps running in AppContainer sandbox, and macOS requires App Sandbox for App Store apps --- but these platforms still allow the majority of apps to run without sandbox due to legacy software or developer resistance. On Linux, the situation is worse: applications installed via traditional package managers have no confinement at all @privacy-guides-2022. Existing Linux application sandbox projects (Flatpak, Snap, Firejail, etc.) each have limitations that prevent them from fully solving this problem (discussed in @research). In summary, the core problem is the lack of a practical, effective sandboxing mechanism on Linux desktops to protect users from an application's misbehavior or compromise.

#v(1.5em)

== Motivation <background-motivation>

This problem is worth solving due to both security and usability imperatives. Desktop Linux is increasingly used not just by developers but average users, and they face growing threats from malware, trojans, or supply-chain attacks delivered via third-party applications. Isolating applications can significantly contain the damage from such incidents --- for example, a web browser exploit would not automatically yield access to all files if the browser ran in a sandbox with limited file system permissions. Academic and industry research highlights that desktop systems are common entry points for attacks @brodschelm-2022, yet the Linux desktop's security model has not kept pace with modern threats. By bringing per-application isolation to Linux, this project aligns with societal needs for better privacy and security on personal computers. There is also a clear technical motivation: leveraging Linux kernel features (namespaces, seccomp) in novel ways for desktop security is an opportunity to apply and deepen our understanding of operating system concepts. From a personal and course perspective, this project is a chance to integrate knowledge from systems programming, OS security, and software engineering to build a real, impactful tool. The motivation is further reinforced by observing successes in other domains --- e.g. Android's app sandbox and permission model have drastically reduced malware capabilities on mobile @mayrhofer-2021 --- and the desire to bring similar security granularity to a general-purpose Linux PC without sacrificing user experience. Ultimately, the project is driven by the vision of a Linux desktop where installing or running apps doesn't imply blind trust, because each app runs in a constrained environment with only the permissions it truly needs. 

// -----------------------------------------------------------------
// SECTION: education values
// -----------------------------------------------------------------
#pagebreak()

= Educational Value and Course Alignment <education-values>

== Relevance to Course Objectives <education-values-course-objectives>

This project closely aligns with topics from a typical Computer Science curriculum, especially an operating systems or systems security course. It requires understanding of OS-level isolation mechanisms (processes, user IDs, kernel namespaces, access control) which are core OS concepts. Implementation will involve working with Linux system calls (e.g. for namespace creation and seccomp) and understanding how user-space tools can leverage kernel security features, directly reinforcing course material on OS internals. The project also relates to software engineering and architecture topics: we plan a multi-process design (separating a UI frontend from a privileged backend), use of inter-process communication (IPC), and considerations of concurrency and synchronization --- all of which are covered in systems programming courses. Additionally, the focus on a permission-based user interface connects to human-computer interaction principles and usability, showing practical application of designing secure systems that people can actually use (a theme in security courses). The need to use a memory-safe language (Rust) and a robust build system (Bazel) ties into programming language theory (safety guarantees, compile-time vs run-time checks) and software engineering practices (build automation, dependency management), respectively. By undertaking this project, we directly apply theoretical knowledge from the classroom to solve a concrete problem, thereby bridging academic learning with real-world application in OS security. 

#v(1.5em)

== Expected Learning Outcomes <education-values-learning-outcomes>

We anticipate several key learning outcomes from the project:

#v(1em)

- Technical Skills: Mastery of Linux security facilities (user namespaces, cgroups, seccomp filters, capabilities) and how to invoke them via system calls or library APIs. We will gain experience in Rust programming for systems-level tasks, including managing memory and concurrency safely. The project also builds skills in using build tools like Bazel for complex projects, and possibly working with Electron or web technologies for the UI.

- Analytical and Design Skills: The team will develop the ability to analyze security requirements and threat models for desktop applications. We must design a secure architecture that balances isolation and usability, which involves critical thinking and trade-off analysis (e.g. how restrictive to make the default sandbox vs. what users will tolerate). We will also learn to evaluate existing solutions and draw on their strengths and weaknesses to inform our design (literature review and competitive analysis).

- Tool and Framework Proficiency: By the project's end, we expect to be proficient in tools/frameworks such as Rust's tokio (for async IPC handling), Protocol Buffers (for defining RPC messages), and possibly UI frameworks like Electron or Tauri for creating desktop GUIs. We will also get hands-on experience with Bazel, learning how its hermetic build approach ensures reproducible builds and efficient dependency management @bazel-no-date.

- Problem-Solving and Documentation: Building a novel system from scratch will hone our problem-solving skills --- we will encounter and overcome challenges like sandbox escape bugs, environment setup issues, and compatibility across distributions. Finally, documenting the design and implementation (through reports and code comments) will improve our ability to communicate complex technical ideas clearly, an important professional skill. 

// -----------------------------------------------------------------
// SECTION: objectives
// -----------------------------------------------------------------
#pagebreak()

= Objectives <objectives>

== Primary Objectives <objectives-primary>

- Implement a secure sandboxing runtime: Develop the core sandbox mechanism that can confine a target application's execution. This includes creating new Linux kernel namespaces (user, mount, PID, network namespaces) for the process, applying seccomp system call filters, dropping unnecessary POSIX capabilities, and setting up isolated file system views. The runtime should be able to launch arbitrary existing applications in this confined environment without requiring superuser privileges (leveraging unprivileged user namespaces).

- Provide a simple user interface for sandbox configuration: Design and implement a frontend application through which a normal user can sandbox an application with minimal effort. The UI will allow users to select an application (executable) and configure its permissions --- for example, whether it can access the network, which directories (if any) it can read/write, whether it can access hardware devices like webcam, etc. The interface should present these in an intuitive, Android-like permission model rather than low-level technical terms.

- Achieve compatibility with common desktop workflows: Ensure that sandboxed applications remain functional for everyday tasks. This means supporting basic GUI or CLI application needs --- e.g. sandboxed apps should be able to open needed files (with user permission), connect to user-approved services, and not break completely if run in isolation. A key objective is that the sandbox is practical for real use, not only theoretically secure. This will involve providing safe pathways for common functionality.

#v(1.5em)

== Secondary Objectives <objectives-secondary>

- GUI Application Support: Extend the sandboxing solution to seamlessly handle GUI-based desktop applications (the initial prototype focuses on command-line apps). This may involve integrating with display server isolation (X11 security extensions or Wayland's sandbox-friendliness) and handling UI toolkits that expect certain privileges.

- Persistent Sandboxed Environments: Allow users to create sandbox profiles or containerized environments that persist across runs. For example, a user might install an application inside a sandbox profile that has its own file system area for persistent data, enabling isolation not just at runtime but over the application's life (similar to how Android assigns each app a separate data directory). Persistency would help in sandboxing complex apps that need to save settings or install plugins.

- Network Isolation Controls: Provide fine-grained network controls in the sandbox. Beyond a simple on/off switch for network access, we could allow rules like permitting LAN access but not internet, or limiting which hosts/ports the app can communicate with. This would enhance the security for use cases like sandboxing an untrusted browser or software that should only connect to specific services. 

#v(1em)

_(Secondary objectives are contingent on time and are intended for the later capstone phase of the project, after the initial prototype is complete.)_

// -----------------------------------------------------------------
// SECTION: research
// -----------------------------------------------------------------
#pagebreak()

= Research and Analysis <research>

== Existing Solutions <research-existing>

To design our sandbox, we examined existing tools and sandboxing frameworks, noting their strengths and limitations. Containerization technologies (Docker,Podman, LXC) are the most mature isolation solutions on Linux, but they target servers and development --- they typically require building container images and using CLI commands, which is too cumbersome for average desktop users. Moreover, they isolate entire environments (with their own filesystem and init process), whereas we need to integrate isolated apps into a user's desktop session. On the desktop side, Flatpak and Snap have emerged as popular frameworks that package applications in a sandboxed runtime. Flatpak uses a container-like sandbox approach: it relies on Bubblewrap (a user-space tool using Linux namespaces) to confine apps @dunlap-2022. In theory, a Flatpak app has no access to the host except what is explicitly allowed, and must use portals (controlled interfaces) for tasks like opening files or using the network @whittaker-2025. Snap, on the other hand, uses a kernel-level mandatory access control (AppArmor) to constrain apps @dunlap-2022. Snap defines per-app AppArmor profiles and seccomp filters. Both Flatpak and Snap integrate the sandboxing with distribution of apps (app stores), which is not our primary goal --- we want to sandbox existing applications on the system.

#v(1em)

Despite their design, Flatpak and Snap have notable limitations in practice. Many Flatpak apps end up requesting broad permissions (e.g. full home directory access, unrestricted device access), effectively punching holes in the sandbox @whittaker-2025. A recent analysis found that approximately 42% of Flatpak apps override isolation or misconfigure sandbox policies, often leading to over-privilege @whittaker-2025. This is because crafting fine-grained permissions is difficult and strict confinement can break application functionality @whittaker-2025. Snap's reliance on AppArmor means its security is strong on systems like Ubuntu where AppArmor is enabled, but on other distros (e.g. Fedora, which uses SELinux) many Snap sandbox features are unavailable @dunlap-2022. Firejail is another tool aimed at desktop sandboxing; it can sandbox arbitrary Linux applications using namespaces and seccomp. However, Firejail is implemented as a large setuid-root binary, raising concerns that any vulnerability in Firejail could lead to a root compromise @privacy-guides-2022. In fact, security experts have pointed out cases where Firejail's complexity introduced new risks rather than mitigating them @privacy-guides-2022. Bubblewrap (which Flatpak uses internally) is a minimalist sandbox tool that creates a new user namespace and mount namespace to isolate a process. It is powerful but very low-level --- using it directly requires manually specifying which parts of the filesystem to bind-mount into the sandbox, devices to allow, and so on @sloonz-2023. Setting up Bubblewrap correctly for a desktop app can be tedious (as an example, even getting a shell like `zsh` to run required binding multiple system directories and setting up `/dev` and `/proc` mounts) @sloonz-2023. This complexity makes Bubblewrap impractical as a consumer-facing solution by itself.

#v(1em)

From the above, we gained important insights: (1) Desktop sandboxing must balance security with usability. Prior solutions often end up weakened (Flatpak broad permissions) or are too technical (Bubblewrap) due to this tension. (2) A successful sandbox should not require application modifications. Mobile OSes often have apps request permissions via APIs @brodschelm-2022, but on a traditional desktop we must sandbox apps without their explicit cooperation, since they are not built with sandbox awareness. (3) Leveraging kernel features is the preferred approach over purely user-space enforcement. Namespaces, when configured correctly, can provide true isolation of filesystem and process space @dunlap-2022, and seccomp can reliably filter dangerous syscalls across all software @dunlap-2022. We will build on these concepts. (4) No persistent daemon is desired for our use-case --- unlike Docker's always-running service, a per-launch approach (similar to how Podman operates rootlessly) would be more secure (less attack surface) and align with user expectations (only active when launching an app).

#v(1em)

In summary, existing solutions inform our design: we aim to combine the strong isolation achieved by containerization technologies (namespaces, seccomp) with the user-centric design of desktop sandbox frameworks (simple permission controls, ready-to-use profiles). The novelty of our project is focusing on the normal user's workflow: sandboxing apps they install from various sources, on demand, with an easy UI --- effectively bringing the security of ChromeOS/Android to a regular Linux distro. Notably, our solution will not be tied to a specific app store or package format; it should work for user's existing applications (e.g., the web browser, an email client installed from a .deb, a game binary, etc.).

#v(1.5em)

== Functional Requirements <research-functional-requirements>

Based on the problem analysis, we have identified the following key functional requirements for our sandbox system:

#v(1em)

- Application Launch in Sandbox: The system must allow the user to launch a chosen application in an isolated environment. This includes launching via a GUI selection or a CLI command, and ensuring the target process indeed runs with restricted privileges (different namespace, etc.).

- Permission Configuration: The user should be able to configure what resources the application can access. At minimum, this covers file system access (e.g. no access to home directory by default, with options to grant access to specific folders), network access (enable/disable internet connectivity), and device access (webcam, audio, etc.). The configuration should be saved as a profile so that the user doesn't have to set permissions every time.

- Interoperability with Host: The sandboxed application should still be able to interact with the host in controlled ways necessary for usability. For instance, a sandboxed GUI app should display on the user's desktop (through X11 or Wayland, perhaps via a proxy or permission), and copy-paste or other IPC could be mediated via secure channels. Functional requirements include implementing such mediated access (e.g., using XDG Portals similar to Flatpak for file dialogs, if possible, or custom mechanisms for common tasks).

- Multiple Sandboxed Apps: Support running multiple sandboxed applications concurrently. Each sandbox instance might be separate, isolating apps from each other as well as from the host (unless the user intentionally groups some apps together). This requires the backend to manage multiple namespaces/environments possibly simultaneously and keep track of them.

- User Feedback and Logging: Provide feedback to the user, especially in cases where the sandbox blocks something. For example, if the application tried to access a file or network resource not permitted, the system could log this (and potentially notify the user or offer an option to adjust permissions). While not strictly required, this greatly aids usability and transparency, so users can understand sandbox effects.

#v(1.5em)

== Non-Functional Requirements <research-non-functional-requirements>

Several non-functional requirements are crucial for the project's success:

#v(1em)

- Usability and UX: The solution must be easy to use for non-technical users. This means the UI should be clean, avoiding technical terms like "namespace" or "seccomp". Instead, it might present toggles like "Allow Internet Connection" or "Allow access to Documents folder". Sensible defaults (secure by default with option to loosen) are needed, as users generally prefer things to "just work" out of the box @brodschelm-2022. If our sandbox requires complicated setup every time, users will likely abandon it, as happened with some prior tools.

- Security: Security is paramount --- the sandbox must genuinely confine applications under the stated threat model (an app under adversary control should not be able to affect the rest of the system) @brodschelm-2022. This implies rigorous implementation of isolation (no trivial escapes), minimal trusted code running with privileges, and defense in depth (using multiple mechanisms, e.g. namespace + seccomp + AppArmor potentially). We will consider the threat of malicious apps trying to break out and ensure our architecture minimizes that risk.

- Performance: The sandboxing mechanism should introduce minimal performance overhead. Launching an app in the sandbox should be as fast as launching it normally, within reason. Using user namespaces and seccomp is generally lightweight (especially compared to full VMs), but we should avoid unnecessary indirection. For example, communication between the sandboxed app and allowed host services (printing, file open dialog) should be efficient. The overhead in terms of CPU and memory should be low, so that even heavy applications (like a web browser or an office suite) run sandboxed without noticeable slowdown.

- Compatibility and Portability: The system should work across different Linux distributions and environments. This means avoiding assumptions tied to one distro. For instance, relying solely on AppArmor would limit use on distros that use SELinux or none; instead, we use user namespaces which are a standard kernel feature (assuming they are enabled). The UI should not be tied to specific desktop environments (hence using Electron or a neutral toolkit). We also aim for the solution to be rootless --- not requiring system-wide installation of daemons or kernel modules --- so it can be adopted by users on systems where they don't have root (e.g. enterprise or university machines, satisfying the rootless requirement R5 from research @brodschelm-2022).

- Maintainability and Extensibility: The project's codebase should be maintainable, with clear module boundaries (e.g. the UI and backend communication is via a well-defined RPC interface). By using Rust, we gain memory safety which reduces certain classes of bugs (buffer overflows, use-after-free) that plague C/C++ software @android-open-source-project-no-date. This choice not only improves security but also maintainability because memory errors are caught at compile time. In this context, extensibility refers to making it possible to add new permission types with minimal refactoring --- for instance, if in the future we want to integrate virtualization for even stronger isolation, the design should accommodate such additions.

- Scalability: In the context of this project, scalability is less about handling high load and more about handling many different application scenarios. Our sandbox should scale to sandbox any type of application a user might have --- from a simple command-line tool to a complex GUI suite. This generality is challenging but necessary for wide adoption (requirement R1 in research @brodschelm-2022). In terms of performance scalability, the design should handle multiple sandboxed apps without conflicts (e.g., ensure unique namespace IDs, handle resource limits via cgroups if needed to avoid one sandbox starving others).

#v(1.5em)

== Feasibility Analysis <research-feasibility>

Technical Feasibility: The project builds on well-tested Linux kernel mechanisms, indicating strong feasibility. Unprivileged user namespaces (since Linux 3.8) let normal users create sandboxes without root @dunlap-2022. Many mainstream distributions (e.g., Ubuntu, Debian, Fedora) enable this feature, as it is used by software like Chrome and Flatpak. Using namespaces, we can isolate the filesystem (via a new mount namespace and bind-mounting only allowed paths), the process tree (PID namespace so the app cannot see processes outside), and the network (network namespace to have an isolated network stack), etc. Seccomp filters can be applied to restrict syscalls --- this is commonly done in Chrome's sandbox and Flatpak @dunlap-2022. A practical challenge is sandboxing GUI applications, since access to display servers must be controlled: X11 lacks strong isolation guarantees by design, whereas Wayland enforces stricter client separation @roukala-2014. AppArmor/SELinux could optionally complement namespaces with additional policy enforcement (e.g., path-based controls), and implementing the system in Rust improves robustness by reducing memory-safety risk in low-level components.

#v(1em)

Time Feasibility: For the prototype, the plan is to implement a working minimal system: sandboxing for CLI apps with basic file system and network permission control, and a way to launch them (through frontend UI). User namespaces and mount namespaces are straightforward to set up using existing libraries or simple syscalls; seccomp might require more work to define a secure default filter (we could start by borrowing a known secure syscall whitelist from projects like Flatpak or Chrome). The RPC mechanism using protobuf over a Unix socket can be implemented with a small footprint (there are Rust libraries for protobuf and async IO). The UI, if using Electron, can be built using HTML/JavaScript, which accelerates development (Electron, though heavy, allows rapid UI prototyping with web technologies). By the end of prototype phase, we expect a demo where one can launch a terminal or text editor in a sandbox that, for example, cannot write outside a specific folder and cannot access the network. The capstone phase will then tackle the harder parts (GUI integration, persistent profiles, polish). Given this staged approach and focusing on core functionality first, the timeline is feasible. We have also padded in time for testing and adjusting based on what we learn in early development --- for instance, if we hit a roadblock with technology A, we have time to switch to plan B (e.g. if Electron is too heavy, we could switch to a simpler CLI-based frontend).

#v(1em)

Resource Constraints: The project primarily requires development time and standard hardware. No special hardware is needed beyond a computer to code and test on; testing can be done on any modern Linux distribution. We will use open-source libraries and tools (Rust compiler, Bazel build system, etc.). One possible constraint is the learning curve --- the team needs familiarity with kernel APIs. We have planned to allocate time for learning and using existing examples (like referencing how Flatpak or other tools do it) rather than coding everything from scratch blindly. As for external resources, we might rely on documentation and community forums for troubleshooting, but no proprietary software or data is needed. In terms of collaboration resources, using GitHub for version control is free and sufficient. Overall, resource-wise the project is low-cost and mainly demands expertise and careful engineering.

#v(1em)

Given the above, we judge the project to be feasible within the given constraints. The risks (addressed in @risks) are manageable, and the core technology needed is available and proven. By prioritizing critical features and following a disciplined schedule, we are confident in delivering a functional sandbox MVP in the prototype phase and a more complete solution in the capstone phase.

// -----------------------------------------------------------------
// SECTION: project scope
// -----------------------------------------------------------------
#pagebreak()

= Project Scope and Expected Deliverables <project-scope>

== Scope Definition <project-scope-definition>

This project will focus on creating a sandboxing tool for Linux that is tailored to desktop application use cases. The scope includes developing both the sandboxing engine (backend) and a user-facing interface (frontend) as described. We will include the ability to sandbox command-line applications in the prototype phase, and plan to extend this to GUI applications in the capstone phase. The sandbox will cover isolation of processes, file system, and network as core functionality. We assume a modern Linux kernel (with necessary features enabled) and a standard user session environment. Our design is intended to be distribution-agnostic (it should work on any standard distro with kernel support), and not dependent on a particular desktop environment or package system. We will use existing kernel security mechanisms rather than inventing new ones, which keeps the project within scope and grounded in known techniques.

#v(1em)

Out of scope (for prototype phase) are advanced features that would distract from the core goal. For example, we exclude implementing a full container image or packaging system --- unlike Docker or Flatpak, we are not distributing software, just sandboxing it. We also exclude any work on mobile platforms or non-Linux OS; the project is firmly Linux-centric. Complex hardware sandboxing like GPU isolation or 3D acceleration pass-through is out of scope, as it requires specialized approaches and could weaken security (GPU drivers are large attack surfaces). We will not attempt to confine system services or kernel modules --- the sandbox is for user applications, not for locking down system daemons (which is a separate problem). An assumption we make is that the user will voluntarily launch apps through our tool; automatically sandboxing every launch in the system is not in scope (that would require deep OS integration). Another assumption is that the underlying kernel is secure and up-to-date --- our sandbox cannot prevent all possible kernel-level attacks (no sandbox can, if the kernel itself has vulnerabilities), though by using seccomp we reduce exposure. We also assume the user has permission to use user namespaces (if a system had them disabled for unprivileged users, our tool would either not function or require the user to enable that --- which we will document but not solve universally). These constraints and assumptions will be documented to manage expectations and define a clear boundary for the project deliverables.

#v(1.5em)

== Deliverables (Prototype Phase) <project-scope-deliverables>

By the end of the prototype phase, we aim to produce the following deliverables:

#v(1em)

- Project Proposal and Design Document: A comprehensive document (this report) detailing the problem analysis, system design, and plan of execution. This includes the literature review of existing solutions, defined requirements, architecture diagrams, and the rationale behind design decisions. This document serves both as a planning artifact and as partial fulfillment of course requirements for a project proposal.

- Prototype Sandbox Implementation: A working proof-of-concept of the sandbox backend in Rust. This will be delivered as an executable that can launch a given program in a sandbox according to a simple config. This prototype will show that we can create the necessary namespaces, apply seccomp, etc., and that the confined application indeed has restricted capabilities (we will test attempting file access or network access to confirm it is blocked when it should be).

- Basic Frontend UI: We will deliver a minimal CLI to configure and launch sandboxed applications; if time permits, we will provide a basic GUI. This can be a simple script or a lightweight app that lists applications and allows adjust sandbox permissions. It will invoke the backend directly (as a subprocess) and communicate via a local IPC channel (e.g., a Unix socket).

- Documentation and Usage Guide: We will provide documentation for the prototype --- including a user manual that explains how to use the sandbox tool, what the default security model is, and how to interpret any prompts or outputs. This also covers instructions to build the project (leveraging Bazel).

- High-Level System Architecture Overview: We will create a diagram and explanation of the system's architecture (frontend-backend interaction, main modules, data flow). This might be included in the design doc and also as a standalone reference for the capstone phase development. It is essentially a blueprint of how components interact (e.g., how the launch request flows from UI to backend, how the backend sets up sandbox then execs the target app).

// -----------------------------------------------------------------
// SECTION: timeline
// -----------------------------------------------------------------
#pagebreak()

= Preliminary Project Timeline and Milestones <timeline>

Given the two-phase structure of the project, the timeline for prototype phase is outlined below:

#v(1em)

- Week 1-3: Research and Design Finalization --- In the first 2-3 weeks, we will deep dive into researching Linux namespace APIs, seccomp filters, and review how tools like Flatpak or Chrome implement them. Concurrently, we finalize the system architecture and decide on core technologies.

- Week 4-6: Backend Core Development --- During this period, focus is on implementing the sandbox runtime (the Rust backend). We will start with the ability to spawn a process in a new user namespace and mount namespace. Then add mounting logic (e.g., mounting a tempfs as `/home` inside sandbox, or binding specific directories). By week 6, we aim to have a basic tool that can sandbox a process with a default policy (e.g., no network, no home access except perhaps an isolated home).

- Week 7-8: Frontend and IPC Integration --- In these weeks, we shift to implementing the frontend and hooking it up to the backend. We'll finalize the RPC and implement a simple Unix socket server for communication. By end of week 8, the frontend should be capable of sending a request to the backend to launch an app.

- Week 9-10: Testing and Hardening --- We will spend time testing the system with various programs and refining the sandbox policies. We'll adjust the default included binds or permissions to ensure common apps don't crash in weird ways when sandboxed. We will also run security tests like attempting to open disallowed files or network connections from inside the sandbox to ensure the isolation holds. Another task in this period is to improve robustness (handle errors gracefully, make the IPC asynchronous to not block the UI, etc.).

- Week 11-12: Documentation and Buffer --- The final two weeks are for finishing the final report and presentation. We also use this as buffer time to finish any features that slipped.

// -----------------------------------------------------------------
// SECTION: team
// -----------------------------------------------------------------
#pagebreak()

= Team Structure and Collaboration <team>

Team Size and Roles: This project is being carried out by a small team of four students. For the purposes of planning, we define roles to ensure all aspects are covered:

#v(1em)

- Project Lead/Architect: Responsible for the overall design decisions and coordination. This role ensures that the system architecture meets requirements and that different components (UI and backend) integrate smoothly.

- Backend Developer (Sandbox Engine): Focuses on implementing the core sandboxing logic in Rust. This involves writing code for namespace setup, managing child process lifecycles, applying security policies, and handling RPC requests.

- Frontend Developer (UI/UX): Focuses on the CLI and GUI frontend application, creating the user interface for configuring and launching sandboxed apps. They design the layout of permission options, implement the logic for storing user preferences (which apps have what permissions), and ensure the UI properly communicates with the backend.

- DevOps/Build Manager: Handles the build and release process using Bazel. This involves writing Bazel build files for the Rust code and possibly for packaging the Electron app, ensuring that the build is reproducible and works on the targeted platforms. They will also set up version control (Git repository) and define a workflow for collaboration (feature branching, code reviews).

#v(1em)

Since this is an academic project, the team members will collaborate closely rather than in rigid roles. We will use GitHub as our primary collaboration platform --- all code will be in a Git repository to which team members commit. We will utilize issues and a project board on GitHub to track tasks, bugs, and features, ensuring transparency of progress. Regular meetings are planned to synchronize work, discuss challenges, and plan upcoming tasks. For communication, besides meetings, we will use a shared Slack channel or email thread for quick questions and updates.

#v(1em)

Collaboration Tools and Practices: We chose Bazel as our build system to manage this multi-language project (Rust backend, JS/Python frontend) --- Bazel will help keep builds consistent across different developer environments. Its support for hermetic builds and caching will save time and avoid "it works on my machine" problems, as each build will fetch the exact needed dependencies and not depend on system state @bazel-no-date. We will also employ code review practices --- any significant code change should be reviewed by at least one other team member. Documentation of code will be maintained in the repository.

// -----------------------------------------------------------------
// SECTION: risks
// -----------------------------------------------------------------
= Risk and Challenge Analysis <risks>

== Identified Risks <risks-identified>

Developing a desktop sandboxing tool involves various challenges and risks which we have identified as follows:

#v(1em)

- Technical Complexity and Unknowns: Configuring Linux namespaces and security features correctly is complex. Subtle misconfigurations could either render the sandbox insecure or non-functional. There's also complexity in handling GUI apps (e.g., X11 is not secure by design --- sandboxing an X11 app might be futile if it can sniff keystrokes from other X clients).

- Security Risks (Sandbox Escape): As we're developing security software, the primary risk is that of sandbox escape vulnerabilities. If there's a bug in our implementation (say we erroneously grant write access to a critical system directory, or our seccomp filter is too lenient), a malicious app could exploit that to break out. Moreover, user namespaces have had a history of kernel vulnerabilities in early days (increasing attack surface); while many issues have been patched and it is considered safe when properly used, we must stay vigilant.

- Time Constraints: There's a risk we might not fully implement all planned features in time. Unfamiliarity with some tools or APIs could lead to unexpected delays. Integration of components could also take more time than expected if issues arise (IPC synchronization bugs, etc.).

- Integration and Compatibility Issues: The project integrates multiple components (kernel features, a Rust program, and an Electron/Python app). There's a risk that integrating these will pose issues --- e.g., packaging the final tool so that it is easy to run on different systems might be challenging. Also, because we target various Linux setups, differences in environment (different kernels, presence/absence of AppArmor, cgroups v1 vs v2) could cause our sandbox to behave differently or fail.

#v(1.5em)

== Mitigation Strategies <risks-mitigation>

For each of the above risks, we have planned mitigation approaches:

#v(1em)

- Managing Technical Complexity: We mitigate this by leveraging existing framework and libraries whenever possible. Rather than writing namespace setup entirely from scratch, we will consult implementations from Bubblewrap and use existing Rust libraries for things like mounting filesystems or applying seccomp (for example, the seccomp Rust library can help compile filters from a high-level description, reducing error-proneness). For GUI, if X11 is too hard to secure, our mitigation might be to limit our support to Wayland (which isolates input/pointers between windows better).

- Security Assurance: To mitigate sandbox escape risk, we plan to employ a defense-in-depth strategy. Even though user namespaces give root privileges in the namespace, we will drop capabilities inside the namespace to minimize what that "root" can do (e.g., it won't have `CAP_SYS_ADMIN` in the namespace, and we'll use seccomp to disable mounting new filesystems, etc.). We'll also consider using Linux Security Modules (LSM) as an extra layer: for instance, we might ship an AppArmor profile that confines the sandboxed process, or use SELinux sandbox if available, as a secondary line of defense.

- Time Management: We have created a clear timeline with prioritized deliverables. To avoid running out of time, we will enforce a feature freeze for the prototype phase where we implement only the primary objectives. Secondary objectives (GUI app support, etc.) are deferred to capstone phase. If we find ourselves short on time, we will reduce scope accordingly --- for example, if the Electron UI integration is taking too long, we might drop it in favor of a simpler GTK app or even just a command-line driven interface for the prototype. We will use agile iteration --- get a minimal working sandbox early (by mid-project) so that we always have something functional to show, and then iteratively improve it.

- Integration Testing and Compatibility: To mitigate integration issues, we plan to test our tool on multiple Linux distributions early (e.g., Ubuntu and Fedora as two common ones) to catch any distro-specific issues (like AppArmor presence or userns restrictions). We will containerize our development environment itself --- we could use a Docker container to simulate different distros for testing our sandbox tool in a controlled way. Using Bazel will help ensure that dependencies are fetched and built in a uniform manner on any system, reducing "works on my machine" problems. We also consider providing a fallback or detection: e.g., if unprivileged user namespaces are disabled, our tool can detect that and gracefully inform the user rather than failing mysteriously.

// -----------------------------------------------------------------
// SECTION: references
// -----------------------------------------------------------------
#pagebreak()

#bibliography("refs.bib", style: "apa") <references>

