# Project Diary

## 2025-01-27
**Task**: Investigated feasibility of building ioquake3 with MSVC in 64-bit mode.
- Added new `x64` configuration in Visual Studio and copied settings from `Win32`.
- Attempted to build all targets for `x64`, resulting in major linker and preprocessor issues.
- Modified `q_platform.h` to define `ARCH_STRING` and `idx64` correctly under `_M_X64` builds.
- Verified that the preprocessor defines were working using `#pragma message` debugging.
- Linked SDL2 via `SDL2.lib` and verified the include paths — still received ~30 unresolved external symbol errors from SDL-related API calls.
- Discovered that `ftola.asm` — a critical assembly file used in the VM and physics systems — is written for x86 only and cannot be assembled for x64 under MSVC. The x64 ABI doesn't allow inline assembly, and the current ftola usage isn't portable or easily refactorable.
- Any attempts to bypass it caused architecture mismatch linker errors (`LNK1112`) or resulted in significant runtime instability.

**Problems Encountered**:
- SDL linkage completely failed despite all `.lib` files being added — suspected mix of 32/64-bit binaries, compounded by SDL's C linkage style.
- Even when `ARCH_STRING` was correctly defined, MSVC still generated x86 `.obj` files due to legacy inline asm in `ftola.asm`.
- Removing `ftola` would require rewriting a large chunk of ioquake3’s VM backend and physics precision logic — not feasible within project scope.

**Solution**:
- Decided to suspend 64-bit build attempts under MSVC for now.
- Pivoted back to developing SGX integration via a standalone enclave-aware daemon using IPC, as this allows better separation and avoids the need to modify core physics VM internals.

**Reflection**:
This process was a deep dive into legacy engine internals. The `ftola.asm` file became a blocker that revealed how brittle parts of the Quake3 engine are with respect to architecture. While 64-bit support is achievable, doing so under MSVC with SGX constraints would require refactoring beyond the current project’s scope. Developing the enclave system in a standalone daemon also enables modularity and easier testing, especially in simulation mode.

**Next Steps**:
- Focus SGX integration around IPC rather than direct linkage.
- Decide on whether to use a 32 bit MSVC build or a 64 bit Cygwin build for now.
- Build a protocol for ioquake3 <-> SGX daemon communication using tightly defined message types.
- Benchmark latency introduced by IPC and evaluate security trade-offs.

---

## 2025-01-23  
**Task**: Re-evaluated architecture after research; planning return to direct SGX integration inside ioquake3.  
- Investigated alternatives to the standalone SGX anticheat process after encountering IPC limitations in simulation mode.
- Found an official MSVC-compatible Visual Studio 2019 solution for ioquake3 under `misc/msvc142` on GitHub.
- Confirmed with ioquake3 community via Discord that this solution is viable and actively maintained.
- Determined that direct enclave integration would be more maintainable in the long term.
- Decided to move away from the standalone EXE model and plan a return to embedded SGX interaction from within the engine itself.
- Began designing a flexible enclave interface that can be called internally from within ioquake3 without relying on IPC.

**Problems Encountered**:  
- IPC development in simulation mode is becoming difficult to scale.
- Simulation constraints make it hard to test scenarios that mimic deployment on actual SGX-enabled hardware.
- External daemon architecture introduces latency and unnecessary complexity when running test cases during development.
- No secure method currently exists to guard against man-in-the-middle (MITM) interception between the daemon and engine — especially problematic when dealing with tampered clients.

**Solution**:  
- Investigated MSVC project conversion and confirmed ioquake3 can now be built with Visual Studio, solving ABI incompatibility.
- This makes it feasible to directly link the SGX runtime and load enclaves internally from within the engine.
- Will keep simulation mode for now, but design future-facing code paths for hardware enclave support.

**Reflection**:  
This architectural shift feels like a return to first principles. The standalone anticheat daemon was conceptually strong and mirrored commercial systems, but it ultimately created too many layers between the game logic and the enclave. The IPC approach was also inherently vulnerable — without shared memory sealing or TLS, any local attacker with admin access could MITM the communication. Embedding the enclave directly into the engine solves this cleanly and aligns better with SGX's design philosophy. By leveraging the MSVC project, I no longer have to fight ABI mismatch issues between MinGW and the Intel SGX SDK. Long-term, this design gives me more control, less latency, and eliminates IPC security pitfalls, which I am not all too confident about guarding against, such as interception.

**Next Steps**:  
- Clone a fresh copy of the `msvc142` ioquake3 project and open it in Visual Studio.
- Write a wrapper function for `update_health()` in an SGX-compatible enclave interface.
- Replace `G_Damage()` health logic with a secure ECALL call.
- Add conditional compile paths to toggle between simulation mode and stub logic for easier debugging.

---

## 2025-01-19  
**Task**: Set up SGX simulation and created a standalone console demo app for enclave-secured health logic.  
- Successfully built ioquake3 in CLion using Cygwin + MinGW after resolving toolchain setup issues.
- Installed necessary packages for 64-bit compilation: `mingw64-x86_64-gcc-core`, `g++`, `make`, `bison`, `git`.
- Configured CLion to use the correct compilers and build tool from `C:\cygwin64\bin`.
- Verified that ioquake3 builds and runs, both as a client and as a dedicated server.
- Switched to Visual Studio 2019 for enclave development using SGX in simulation mode.
- Created `DevEnclave` solution and implemented `update_health()` ECALL inside the enclave.
- Defined ECALL to take current health, damage, and max health; performed secure clamping in enclave memory.
- Generated EDL bridge code and fixed missing `*_u.h` / `*_t.c` by manually invoking the Edger8r tool.
- Resolved runtime errors by placing SGX DLLs into correct simulation/debug directories (root level, not per app).
- Created a standalone **SGXAnticheat console app** inside the solution, which accepts test values and returns validated health using enclave ECALLs.
- Designed the architecture to support multi-command dispatch (e.g., HEALTH, POSITION, INVENTORY) for future anticheat extensions.

**Problems Encountered**:  
- Initial CLion build failed due to missing compilers in Cygwin and unrecognized `make` binary.  
- Visual Studio test apps failed due to missing bridge headers and incorrect DLL placement.  
- SGX simulation wouldn’t load enclave unless DLLs were placed in specific root folders.

**Solution**:  
- Installed required Cygwin packages and explicitly set compiler paths in CLion toolchain.  
- Ran `edger8r` manually to generate missing files from `.edl`.  
- Copied all `sgx_urts.dll` and related DLLs into both `x64/Debug` and `x64/Simulation` folders at the root of `DevEnclave`.  
- Verified that ECALL logic works correctly and prints expected values from the standalone app.

**Reflection**:  
This week helped reinforce the importance of modularity in SGX-integrated systems. The incompatibility between MSVC and MinGW forced me to reevaluate how tightly coupled I wanted my secure logic to be to the engine. Rather than fight the build system, I embraced separation via a standalone anticheat process — mirroring real-world architectures like Easy Anti-Cheat and Vanguard. This separation doesn’t just make integration easier — it makes the security model cleaner. ioquake3 doesn’t need to “know” what the enclave is doing; it only needs to trust the result. That’s a powerful boundary. It also became clear how fragile enclave integration can be on Windows without proper project setup. Small misplacements (like a DLL in the wrong folder) can silently cause critical runtime failures. I'm now more confident working within SGX simulation mode and am laying groundwork for extensibility beyond health (e.g., positional checks, inventory validation).

**Next Steps**:  
- Finalize IPC glue between ioquake3 and the SGXAnticheat app.  
- Replace health logic in `G_Damage()` with a call to the external enclave interface.  
- Extend enclave ECALLs to support additional cheat-proof logic for position and inventory validation.  
- Consider porting to Open Enclave SDK if hardware SGX integration proves limiting later on.

---

## 2025-01-13
**Task**: Built and validated ioquake3 multiplayer loopback and online connectivity.
- Followed official instructions to compile ioquake3 using Cygwin + MinGW on Windows.
- Resolved all build dependencies and successfully compiled both `ioquake3.exe` (client) and `ioq3ded.exe` (dedicated server).
- Launched the dedicated server locally and connected to it using the game client via `127.0.0.1`.
- Also confirmed that the ioquake3 client can connect to public online servers, validating full network functionality.

**Problems Encountered**:
- None significant during this stage. The MinGW+Cygwin toolchain worked cleanly after package configuration.

**Solution**:
- Used `/connect 127.0.0.1` from the in-game console to join locally hosted server.

**Reflection**:
- Unlike last term, I now have a stable multiplayer environment to work from.
- This unlocks the ability to inspect real-time game state changes between client and server — essential for later injecting SGX-based validation or protection.
- Having real loopback and online connectivity ensures I can properly test secure communication, latency impact, and gameplay integrity under modified logic.

---

## 2025-01-13
**Task**: Rebuilt dev environment and resolved SGX simulation runtime linking issues using NuGet SDK and plugin tools.
- After a full system wipe, I had to restore my SGX development stack from scratch. I decided to then move my current dev to my main PC for ease of use, as I would be using simulation mode for now anyway.
- Instead of repeating the manual extraction process from last term, I opted to install the Intel SGX SDK and headers via the NuGet Marketplace, which were newly available.
- Used `SEConfigureVS2019.vsix` and `SEWizardVS2019.vsix` to enable the SGX project templates in Visual Studio 2019.
- Successfully rebuilt the default enclave sample and retargeted my existing TestEnclave and ConsoleApplications to use the new SDK layout and simulation mode.
- Encountered runtime errors where the simulator reported `sgx_urts_simd.dll` and others as missing, despite being present in the host application directory.

**Problems Encountered**:
- Windows reported missing DLLs like `sgx_urts_simd.dll` at runtime.
- Initially assumed that placing them alongside `ConsoleApplication2.exe` would suffice, but this failed.
- Found that SGX’s simulation runtime expects these DLLs to be placed specifically in the output directories of both the enclave project and the untrusted apps.

**Solution**:
- Identified correct folder expectations by cross-referencing simulation behavior and comparing project wizard defaults.
- Copied all necessary simulation-mode DLLs (both x86 and x64) into the following folders:
  - `TestEnclave/x64/Simulation`, `TestEnclave/Simulation`
  - Same structure for `ConsoleApplication1` and `ConsoleApplication2`
- Ensured signed enclave DLL (`TestEnclave.signed.dll`) was used, and Unicode/wide string mismatch was fixed using `L"..."` string literals.

**Reflection**:
- This marks a full restoration of SGX simulation capability on my current dev machine.
- Compared to last term’s manual SDK install, this NuGet + plugin approach is cleaner and more portable.
- The DLL layout expectations were undocumented and non-obvious, but solving them gives me confidence in handling future low-level toolchain issues.
- With simulation now working, I can shift focus toward enclave logic integration and ioquake3 interaction.
- I also discovered that by copying all SGX DLLs from the PSW distribution into the relevant Debug and Simulation output folders, the apps would at least launch cleanly under the debugger even when built in non-simulation mode. However, enclave creation fails as expected due to the lack of actual SGX hardware on this system.
- This confirms that the SGX SDK is now fully integrated and operational.


---

## 2024-12-01
**Task**: Expanded the SGX enclave functionality to support potion consumption alongside shot damage simulation.
- Added a new ECALL, `ecall_consume_potion`, to simulate the effects of five different potion types: Health, Damage, Berserkers, Weakness, and Normalcy.
- Modified the existing enclave to ensure compatibility with both potion and shot damage simulations while maintaining separation of functionality.
- Developed a new application that exclusively focuses on potion consumption, demonstrating modular reuse of the enclave.
- Ensured that health boundaries are enforced, with special outputs for critical health conditions like "YOU DIED!" and "GODLIKE!!!".

**Problems Encountered**:
- Required careful integration to avoid conflicts between the two simulation functionalities.
- Debugging potion effects to ensure consistent updates to health and proper handling of boundary cases.

**Solution**:
- Implemented separate ECALLs for damage and potion simulation, ensuring isolated logic for each feature.
- Updated the EDL file to support both ECALLs, providing reusable functionality across applications.
- Verified the enclave's behavior through extensive testing in both applications.

**Next Steps**:
- Explore the addition of new gameplay mechanics, such as armor and critical hit chances.
- Optimize the enclave code to improve performance and reduce redundancy.
- Document the expanded enclave architecture and usage scenarios for future reference.

---

## 2024-11-23
**Task**: Implemented random damage calculation based on body part hit.
- Enhanced the damage calculation function to add random modifiers for specific body parts:
    - Head: 100 base damage + (0–50 random modifier).
    - Torso: 100 base damage + (0–25 random modifier).
    - Legs: Flat 100 damage.
- Ensured that the random modifiers are strictly non-negative using unsigned integers and proper modulo operations.
- Verified functionality through multiple tests, simulating shots to various body parts.

**Problems Encountered**:
- Initially, random modifiers had the potential to be interpreted as negative due to signed integer handling.
- Debugging required to ensure proper application of the random modifier logic.

**Solution**:
- Replaced signed integers with `unsigned int` for all random values.
- Applied constraints to guarantee modifiers stay within the intended ranges.

**Next Steps**:
- Experiment with more complex mechanics, such as critical hits or armor modifiers.
- Continue refining the enclave’s functionality to support game-like interactions.

---

## 2024-11-18
**Task**: Implemented random number generation within the SGX enclave.
- Replaced the previous string manipulation logic with a secure random number generator (`ecall_generate_random`).
- Utilized the `sgx_read_rand` function to generate a 32-bit random number securely within the enclave.
- Updated the untrusted application to call the new ECALL and display the random number.

**Problems Encountered**:
- Minor issues with header inclusions and function prototypes during the transition from the previous ECALL.
- Debugging required to ensure proper memory alignment and buffer handling.

**Solution**:
- Ensured the SGX headers were correctly included for random number generation.
- Verified the enclave functionality by running multiple tests to ensure consistent behavior.

**Next Steps**:
- Expand the enclave's functionality to include additional secure operations.
- Document the usage of `sgx_read_rand` and its constraints for future reference.

---

## 2024-11-15
**Task**: Successfully implemented and tested a functional SGX project.
- Found a [YouTube tutorial](https://www.youtube.com/watch?v=x3c62hsZbX0) that demonstrated the correct setup for an SGX project.
- Simplified the enclave functionality by replacing the random number generation with a string manipulation ECALL.
- Updated paths to match the project's folder structure, ensuring the enclave file was correctly located.
- Verified the enclave's ability to modify a buffer passed from the untrusted application.

**Problems Encountered**:
- The SGX error code `0x2` (file not found) persisted until the absolute path to the enclave file was provided.
- Misunderstandings of EDL syntax and buffer handling initially caused incorrect behavior.

**Solution**:
- Used the tutorial as a guide to align project setup, build steps, and runtime configurations with best practices.
- Simplified the project to focus on a single working ECALL, reducing potential points of failure.

**Next Steps**:
- Expand functionality by adding more ECALLs and OCALLs for secure data processing.
- Document the lessons learned to streamline future SGX development.

---

## 2024-11-14
**Task**: Troubleshooted build and runtime errors in the TestEnclave project.
- Corrected the working directory configuration in the Visual Studio project settings.
- Addressed missing autogenerated header files by ensuring the `sgx_edger8r` tool was invoked properly during the build.
- Implemented debug output to log the current working directory and identify runtime issues.

**Problems Encountered**:
- Continued runtime failure when creating the enclave due to incorrect paths or missing dependencies.
- Limited feedback from SGX runtime error codes made debugging challenging.

**Next Steps**:
- Research SGX error codes and identify possible causes of enclave creation failure.
- Review official Intel SGX documentation and community forums for additional insights.

---

## 2024-11-13
**Task**: Began setting up a simple SGX project with a TestEnclave.
- Created an initial SGX project using the Intel SGX SDK.
- Defined a basic `ecall_generate_random` function to test communication between the enclave and the untrusted application.
- Encountered numerous build errors, including missing header files and undefined references.

**Problems Encountered**:
- `TestEnclave_u.h` and other autogenerated files were not being created due to improper project configuration.
- Misconfigured working directory caused runtime errors when attempting to load the enclave.

**Next Steps**:
- Investigate and resolve missing autogenerated files by verifying `edger8r` tool execution.
- Fix runtime working directory issues to ensure the enclave file is located correctly.

---

## 2024-11-12
**Task**: Addressed foundational issues and established a functional framework for SGX development.
- Resolved enclave build errors by adding a minimal public root ECALL (`ecall_dummy`).
- Successfully created and destroyed an SGX enclave from the untrusted application.
- Established communication between the untrusted application and the enclave using a placeholder ECALL.
- Validated the build pipeline for both the enclave and the application.

**Problems Encountered**:
- Missing public root ECALL in the enclave, causing build failures.
- Dependency management for SGX-specific headers and libraries required careful configuration.

**Next Steps**:
- Expand the enclave functionality beyond placeholder ECALLs.
- Experiment with secure data processing and enclave-based computation.
- Document learnings from the debugging and build process to streamline future development.

---

## 2024-11-08
**Task**: Built and ran the SampleEnclave project successfully.
- Compiled the SampleEnclave project using the SGX plugin in Visual Studio.
- Executed the built enclave and verified the expected output.
- Confirmed proper SGX functionality and interaction between the application and the enclave.

**Problems Encountered**:
- None. The process completed without errors after resolving previous DLL issues.

**Next Steps**:
- Begin modifying the SampleEnclave to include custom and unique logic, to learn the ins and outs of the system, in preparation for ioquake3 integration.
- Explore performance benchmarks and overhead measurements for enclave operations.

---

## 2024-11-08
**Task**: Resolved DLL issues and switched to "Simulation" mode.
- Identified and imported the required DLLs from the SGX SDK and runtime libraries.
- Updated Visual Studio project settings to include the correct paths for the dependencies.
- Switched build mode from "Debug" to "Simulation" to address compatibility issues with the SGX plugin.

**Problems Encountered**:
- The missing DLLs were not documented clearly in the build instructions, requiring manual search and validation.

**Next Steps**:
- Rebuild the project in "Simulation" mode and test functionality.
- Verify that the "Simulation" build behaves as expected and explore SGX integration further.

---

## 2024-11-07-cont
**Task**: Troubleshooting missing DLL errors in Visual Studio with SGX plugin.
- Attempted to build SGX-enabled projects in Visual Studio.
- Encountered missing DLL issues related to runtime dependencies for the SGX plugin.
- Identified the missing files as part of the SGX SDK and runtime.

**Problems Encountered**:
- Visual Studio build failed due to missing DLLs.
- Documentation for resolving missing DLL issues was unclear, requiring further investigation.

**Next Steps**:
- Verify that the SGX SDK and runtime are correctly installed and configured.
- Update system PATH and library directories in Visual Studio to resolve dependencies.
- Consult Intel's SGX plugin documentation and community forums for additional guidance.

---

## 2024-11-07
**Task**: Verified SGX activation within QEMU/KVM and installed relevant drivers in Windows.
- Confirmed that SGX is properly enabled in the QEMU virtual machine environment.
- Installed and configured necessary drivers in a Windows guest environment for compatibility testing.
- Validated basic SGX provisioning functionality in the virtualized environment.

**Problems Encountered**:
- Minor compatibility issues with driver installation on Windows, resolved by updating to the latest versions (such as Intel SGX SDK and Windows 10 SDK).

**Next Steps**:
- Begin integrating ioquake3 with the SGX-enabled environment.
- Conduct performance benchmarks on both Linux and Windows guests to measure SGX overhead.

---

## 2024-11-05
**Task**: Cross-compiled ioquake3 for Windows.
- Installed `mingw-w64`.
- Successfully built Windows executables for both `x86` and `x86_64` architectures using the `make` command.

**Problems Encountered**:
- Minor issues with mingw-w64 installation resolved by updating system PATH.

**Next Steps**:
- Test Windows builds in a virtualized environment/standard Windows PC to verify functionality.
- Begin exploring SGX integration for C programs.

---

## 2024-11-04-cont
**Task**: Built ioquake3 on Linux.
- Installed SDL2 development libraries and cloned the ioquake3 repository.
- Successfully compiled ioquake3 using the `make` command.
- Verified the build by running the executable on Linux.
- Playtested for 3 hours.

**Problems Encountered**:
- None.

**Next Steps**:
- Proceed to cross-compile ioquake3 for Windows using mingw-w64.

---

## 2024-11-04
**Task**: Documenting a week-long break due to illness.
- Took a week off from project work to recover from COVID after attending MCM Comic Con.

**Problems Encountered**:
- None directly related to the project, but lost progress due to illness.

**Next Steps**:
- Build ioquake3 on development platforms (Linux and Windows).

---

## 2024-10-27
**Task**: Researched SGX support in mainline Linux kernel and QEMU builds.
- Investigated configuration requirements for SGX-enabled virtualization.
- Explored official documentation and community forums for setup guidelines.

**Problems Encountered**:
- None, as no practical steps were taken yet.

**Next Steps**:
- Plan the environment setup and test SGX support in QEMU with sample configurations.

---

## 2024-10-26
**Task**: Debugged SGX provisioning issues and finalized QEMU configurations.
- Adjusted QEMU commands to remove provisioning key requirements.

**Problems Encountered**:
- QEMU failed to enable SGX provisioning due to BIOS misconfigurations.
- Resolved kernel support issues by reinstalling SGX driver.

**Next Steps**:
- Conduct performance benchmarks on the SGX-enabled VM.
- Begin integrating SGX-secured components into the game framework.

---

## 2024-10-25
**Task**: Built custom QEMU with SGX support enabled.
- Compiled QEMU from source with SGX-specific flags.

**Problems Encountered**:
- Missing dependencies (`keymap-gen`) during Meson setup.
- Addressed warnings and errors by updating submodules and dependencies.

**Next Steps**:
- Test provisioning key support for advanced SGX features.
- Document the build process and configurations.

---

## 2024-10-22
**Task**: Enabled SGX in BIOS and verified functionality.
- Configured BIOS settings to enable SGX and Flexible Launch Control.
- Confirmed SGX support through kernel logs (`dmesg | grep sgx`).

**Problems Encountered**:
- Initial BIOS configurations lacked provisioning key support.
- Resolved by updating BIOS firmware and settings.

**Next Steps**:
- Test SGX functionality in QEMU with the new BIOS configurations.

---

## 2024-10-20
**Task**: Researched Intel SGX capabilities and compiled custom kernel.
- Built Linux kernel 5.13.4 from source to enable SGX virtualization.
- Installed SGX DCAP driver for enhanced provisioning support.

**Problems Encountered**:
- Lengthy kernel build times on limited hardware.
- Resolved missing dependencies for kernel modules.

**Next Steps**:
- Configure QEMU to use the custom kernel and enable SGX.

---

## 2024-10-15
**Task**: Set up project repository and initial configurations.
- Initialized Git repository.
- Added `.gitignore` to exclude unnecessary files.

**Problems Encountered**:
- None.

**Next Steps**:
- Begin environment setup for SGX development.
