# Project Diary

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
