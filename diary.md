# Project Diary

# Project Diary

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
