# Project Diary

## 2024-11-04
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
