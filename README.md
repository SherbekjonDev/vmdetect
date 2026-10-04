# VMDetect — VM Detection Research Lab

A research toolkit for studying VM detection techniques used by anti-cheat systems, DRM software, and sandbox evasion. Built as part of the **FothOS Special Edition** project — an AI-native security research platform.

**Lab result: `0 DETECTED / 0 SUSPICIOUS` across all 37 checks.**  
**Real-hardware result: Multiple commercial kernel-mode (ring-0) anti-cheat systems confirmed bypassed on real hardware with GPU passthrough.**

> **Note:** The bypass implementation is not published. Sharing working bypass code for commercial security software would be irresponsible and likely illegal. This repo contains the detection scanner (`vmdetect.py`) and documents the research methodology — not the exploit.

---

## Confirmed Results

**Hardware:** Acer Nitro V16 — Ryzen 7 8845HS, RTX 4050 6GB, 16GB DDR5  
**Setup:** FothOS SE v2.2.1 (live USB), QEMU/KVM, RTX 4050 vfio-pci passthrough, Windows 11 guest

| Target | Type | Result |
|--------|------|--------|
| Industry-leading kernel-mode anti-cheat (ring-0) | AAA titles | **BYPASSED** — games ran inside VM, zero detections |
| Additional commercial anti-cheat systems | multiple titles | **BYPASSED** — same session |

---

## How Anti-Cheats Detect VMs (and How Each Layer Was Beaten)

Modern strong anti-cheats don't rely on a single check. They run dozens of independent detection layers simultaneously — the idea being that even if you beat 36 of them, the 37th catches you. Here's what they look for and what the research found:

**CPUID instruction**
The CPU itself reports whether a hypervisor is present via a single bit in the `ECX` register (leaf `0x1`). Anti-cheats execute this at the bare-metal instruction level using JIT shellcode — no Python, no WinAPI, directly in memory. They also read the hypervisor vendor string at leaf `0x40000000` which returns strings like `KVMKVMKVM` or `VMwareVMware` on unpatched setups.
→ *Bypassed at the QEMU CPU emulation layer before Windows even boots.*

**Hardware identity (BIOS / SMBIOS)**
Anti-cheats read the machine's BIOS strings from the registry and WMI — manufacturer, product name, BIOS version, baseboard serial. A VM with default settings reports `QEMU` or `SeaBIOS` here immediately.
→ *Bypassed by injecting a real, internally consistent hardware identity at the hypervisor level.*

**GPU and PCI tree**
The graphics card model and PCI vendor IDs are checked. A QEMU virtual GPU has a specific PCI vendor ID (`VEN_1234`) that doesn't exist in any real hardware. Ring-0 drivers can read this directly via IOCTL, bypassing Device Manager entirely.
→ *Bypassed via GPU passthrough — the real physical GPU was handed directly to the VM, so Windows saw the actual hardware.*

**Timing and performance**
Every time a VM handles a sensitive CPU instruction, it causes a "VM-exit" — a context switch to the hypervisor that takes thousands of extra CPU cycles. Anti-cheats measure sleep jitter, CPU loop benchmarks, and the delta between `RDTSC` readings before and after a `CPUID` call. On a normal VM this delta spikes to 1000–5000 cycles. On bare metal it's ~187 cycles.
→ *Bypassed through CPU isolation (dedicated physical cores, no scheduler interruption) and instruction-level intervention.*

**Driver and process artifacts**
Every major VM platform installs guest drivers — VirtIO network, VBoxGuest, VMware Tools, QEMU guest agent. Their `.sys` files and running processes are fingerprinted.
→ *Bypassed by not installing any guest drivers and using AHCI/SATA disk mode instead of VirtIO.*

**Network identity**
MAC addresses have vendor prefixes (OUIs). `52:54:00` is QEMU's default — immediately flagged. QEMU's default NAT gateway `10.0.2.2` also appears in ARP tables and `ipconfig` output.
→ *Bypassed by assigning a MAC from a real hardware vendor OUI and using a custom network configuration.*

**PowerShell / WMI surface**
TPM presence, Secure Boot state, screen resolution, and Windows event logs are checked via PowerShell. A VM without TPM emulation or with a tiny virtual display resolution is suspicious.
→ *Bypassed via TPM 2.0 emulation and consistent display configuration.*

---

## Research Status — Closed

**This research is closed. All bypass implementation files have been permanently deleted.**

The session that produced the confirmed results ran from a live ISO with no disk persistence. The laptop was accidentally powered off mid-session (lid close → kernel panic → force shutdown). Upon reboot, the host system required a full reinstall. No bypass code survived.

What remains is this documentation — the detection methodology, the scanner, and the research findings. The implementation does not exist anymore.

**Do not attempt to reproduce this.** Not as a hobby, not as an "ethical hacker," not for any game. The legal exposure from bypassing commercial security software at the kernel level is serious in most jurisdictions. The companies behind these systems have dedicated legal teams and actively pursue cases. This research was conducted under controlled conditions with full awareness of the risks. Publishing it here is documentation of findings, not an invitation to replicate them.

The fact that this worked is interesting. The fact that you can't get the code for it is intentional.

---

## What This Repo Contains

| File | Purpose |
|------|---------|
| `vmdetect.py` | Detection scanner — 8 layers, 37 checks, runs inside Windows 11 |
| `requirements.txt` | Python deps for the scanner |
| `setup.ps1` | Scanner setup script |

The bypass system (QEMU launch configuration, Windows-side hooks, network spoofing) is **not included**.

---

## foth-ghost — AI Research Overlay

A companion tool built for the host (Linux) side of the research setup. Runs as a minimal always-on-top overlay daemon during active VM sessions.

**What it does:**
- Sits invisibly on the host desktop while the VM runs fullscreen
- On hotkey: captures the current screen state and sends it to an AI model
- Returns a response in under 1 second directly on screen
- Operates at the kernel input level (evdev) so hotkeys fire even when QEMU has grabbed the keyboard — something standard X11 hotkey tools cannot do

**Why it exists:** When doing live VM detection testing, you often need to query something quickly without breaking the VM session (switching windows, alt-tabbing, opening a terminal). foth-ghost lets the researcher stay inside the VM environment while getting instant AI-assisted analysis of what's on screen.

**AI chain:** OCR-first (faster, no upload) → vision model fallback for non-text content. Multiple provider fallbacks so it keeps working if any API is down.

**Not published** — the implementation is part of FothOS SE internals.

---

## VMDetect — 8 Detection Layers

`vmdetect.py` covers every major surface a security scanner or anti-cheat uses to detect virtualization. Run it inside a Windows 11 VM to measure how detectable that VM is.

### Layer 1: CPUID (JIT shellcode)

Allocates RWX memory, writes x64 shellcode, executes `CPUID` at the CPU instruction level — bypasses any software-layer hook.

```
Check 1  CPUID.1:ECX[31]          hypervisor present bit
Check 2  CPUID 0x40000000 vendor  KVM / VMware / VBox / Hyper-V string
Check 3  CPUID 0x40000001 EAX     KVM feature flags
```

The shellcode per register:
```
push rbx       ; rbx is non-volatile in Win64 ABI
mov  eax, ecx  ; leaf from first arg
xor  ecx, ecx  ; sub-leaf = 0
cpuid
mov  eax, <reg>
pop  rbx
ret
```

---

### Layer 2: Registry

```
Check 4–9    HKLM\HARDWARE\DESCRIPTION\System\BIOS — manufacturer, product, vendor, version, baseboard
Check 10     Disk\Enum — disk model strings (QEMU / VBOX / VMWARE)
Check 11     DefaultTTL — Linux default 64 vs Windows default 128
Check 12–17  VM-specific driver keys — Hyper-V Guest Params, VMware Tools, VBox GA, vmbus, netkvm, vioscsi
```

---

### Layer 3: WMI

```
Check 18  Win32_ComputerSystem → HypervisorPresent, Manufacturer, Model
Check 19  Win32_BIOS → Manufacturer, Version
Check 20  Win32_DiskDrive → Model, SerialNumber
Check 21  Win32_VideoController → Name, AdapterCompatibility
Check 22  Win32_NetworkAdapter → Name, MAC OUI, Manufacturer
```

Known VM GPU strings checked: `QEMU, VBOX, VMWARE, BOCHS, QXL, SVGA, VIRTUAL, BASIC DISPLAY, STANDARD VGA`  
Known VM NIC OUIs checked: `52:54:00` (QEMU), `00:0c:29` (VMware), `08:00:27` (VBox), `00:15:5d` (Hyper-V), `00:16:3e` (Xen)

---

### Layer 4: Processes

```
Check 23–28  vmtoolsd.exe, vmwaretray.exe, vboxservice.exe, qemu-ga.exe, spice-agent.exe, vmicsvc.exe, prl_tools.exe
```

---

### Layer 5: Files / Drivers

```
Check 29  System32\drivers\{vmhgfs, vmmouse, VBoxGuest, VBoxSF, netkvm, vioscsi, balloon}.sys
          + C:\Windows\System32\qemu-ga.exe
```

---

### Layer 6: Network MAC OUI

```
Check 30  MAC prefix lookup against all known hypervisor OUI ranges
```

---

### Layer 7: Timing

```
Check 31  Sleep jitter variance — VM exits cause irregular latency spikes (threshold: 8.0 ms²)
Check 32  CPU loop benchmark   — 2,000,000 iteration sum (threshold: 200ms)
```

VM exits on `time.sleep` inflate jitter variance measurably. A bare-metal machine with a normal power plan sits well under 8 ms².

---

### Layer 8: PowerShell

```
Check 33  (Get-Tpm).TpmPresent
Check 34  Confirm-SecureBootUEFI
Check 35  systeminfo → Hyper-V Requirements line
Check 36  Win32_VideoController.CurrentHorizontalResolution
Check 37  Event log — VM-related source events (Hyper-V / VMware / VBox / QEMU)
```

---

## Scanner Results (lab environment)

```
CPUID        ✓ ECX bit 31 clear
             ✓ No hypervisor vendor string
             ✓ No KVM feature bits

Registry     ✓ Clean manufacturer / product strings
             ✓ No VM disk identifiers
             ✓ DefaultTTL = 128
             ✓ All 7 VM driver keys: absent

WMI          ✓ HypervisorPresent = False
             ✓ Clean hardware strings
             ✓ Clean disk model + serial
             ✓ Clean GPU name and vendor
             ✓ MAC OUI: clean (not hypervisor-assigned)

Processes    ✓ No VM guest agent processes
Files        ✓ No VM driver files on disk
Network      ✓ MAC OUI clean

Timing       ✓ Sleep jitter variance = 1.612 ms²
             ✓ CPU loop = 146.7 ms

PowerShell   ✓ TPM present
             ✓ Secure Boot ON
             ✓ No hypervisor mention in systeminfo
             ✓ Resolution: 1920px
             ✓ 0 VM-related event log entries

VERDICT: ████████████████████ BARE METAL
         0 DETECTED · 0 SUSPICIOUS · 37 checks
```

---

## Planned Checks (not yet implemented)

Five additional detection vectors that the bypass addresses but `vmdetect.py` doesn't yet test:

| # | Check | Detection method |
|---|-------|-----------------|
| 38 | PCI vendor IDs | Enumerate `VEN_1234`, `VEN_1AF4`, `VEN_1B36` in registry |
| 39 | Default gateway IP | `10.0.2.2` = QEMU NAT default |
| 40 | RDPMC counter | Hardware performance counter reads |
| 41 | RDTSC delta | VM-exit overhead on CPUID instruction (~1000–5000 extra cycles) |
| 42 | Cache timing variance | Cross-vCPU cache eviction noise |

---

## Usage

```bash
# Install deps (Windows)
pip install -r requirements.txt

# Run all 37 checks
python vmdetect.py

# JSON output (for scripting / CI)
python vmdetect.py --json

# Specific layers only
python vmdetect.py --category CPUID WMI Registry

# Screenshot bypass test (captures screen even with WDA_EXCLUDEFROMCAPTURE active)
python vmdetect.py --screenshot --screenshot-delay 5
```

---

## Project Context

Part of **FothOS Special Edition** — a security research platform built on Arch Linux + BlackArch with native KVM/QEMU support and GPU passthrough capabilities.

**Research goal:** Map the complete VM detection surface used by modern security software, validate each layer with a working detection tool, and understand what's bypassed vs. what remains detectable. The scanner (`vmdetect.py`) is the measurable artifact — it lets anyone quantify how stealthy their VM setup is across all 8 layers in one run.

---

## Known Hard Problems

Even with all 37 checks clean, these remain genuinely difficult:

- **ivshmem PCI device** (`VEN_1AF4:DEV_1110`) — Looking Glass shared memory appears in the PCI tree. Registry rename covers Device Manager but not kernel-level enumeration via IOCTL.
- **ACPI suspend + GPU passthrough** — closing the lid with a GPU in vfio-pci state triggers kernel panic on most configs. Must disable lid suspend before starting the VM.
- **Live ISO** — no persistence; any kernel panic or forced power-off loses the entire session state.

---

## License

MIT — research and educational use only.
