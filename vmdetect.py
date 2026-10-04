#!/usr/bin/env python3
"""
VMDetect - FothOS VM Detection Lab v1.0
Run inside Windows 11 VM to test stealth. Covers 8 attack layers.
"""

import argparse
import ctypes
import ctypes.wintypes
import json
import os
import re
import struct
import subprocess
import sys
import time
import winreg
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── optional deps (graceful fallback) ─────────────────────────────────────────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    import mss
    import mss.tools
    HAS_MSS = True
except ImportError:
    HAS_MSS = False

# ── result model ──────────────────────────────────────────────────────────────

CLEAN      = "CLEAN"
DETECTED   = "DETECTED"
SUSPICIOUS = "SUSPICIOUS"
ERROR      = "ERROR"

@dataclass
class Check:
    name:     str
    category: str
    status:   str
    detail:   str
    severity: int = 2   # 1=info  2=medium  3=critical


# ── CPUID (x64 JIT shellcode) ─────────────────────────────────────────────────
#
# Windows x64 calling convention: first arg → RCX
# Each shellcode: void* fn(uint32 leaf)  →  returns uint32 from chosen register
#
#   push rbx          ; rbx is non-volatile in Win64 ABI
#   mov  eax, ecx     ; eax = leaf
#   xor  ecx, ecx     ; sub-leaf = 0
#   cpuid
#   mov  eax, <reg>   ; return chosen register
#   pop  rbx
#   ret
#
_CPUID_SC = {
    # eax already in eax after cpuid
    'eax': b'\x53\x89\xC8\x31\xC9\x0F\xA2\x5B\xC3',
    # 89 D8 = MOV EAX, EBX
    'ebx': b'\x53\x89\xC8\x31\xC9\x0F\xA2\x89\xD8\x5B\xC3',
    # 89 C8 = MOV EAX, ECX
    'ecx': b'\x53\x89\xC8\x31\xC9\x0F\xA2\x89\xC8\x5B\xC3',
    # 89 D0 = MOV EAX, EDX
    'edx': b'\x53\x89\xC8\x31\xC9\x0F\xA2\x89\xD0\x5B\xC3',
}

def _cpuid(leaf: int, reg: str) -> Optional[int]:
    """Execute CPUID via JIT shellcode. Returns None on failure."""
    try:
        code = _CPUID_SC[reg]
        k32 = ctypes.windll.kernel32
        k32.VirtualAlloc.restype  = ctypes.c_void_p
        k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
        k32.VirtualFree.restype   = ctypes.c_bool
        k32.VirtualFree.argtypes  = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]

        mem = k32.VirtualAlloc(None, len(code), 0x3000, 0x40)  # MEM_COMMIT|RESERVE + PAGE_EXECUTE_RW
        if not mem:
            return None
        ctypes.memmove(mem, code, len(code))
        fn = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_uint32)(mem)
        result = fn(ctypes.c_uint32(leaf))
        k32.VirtualFree(mem, 0, 0x8000)  # MEM_RELEASE
        return result
    except Exception:
        return None


class CPUIDModule:
    def check_hypervisor_bit(self) -> Check:
        ecx = _cpuid(1, 'ecx')
        if ecx is None:
            return Check("Hypervisor bit CPUID.1:ECX[31]", "CPUID", ERROR, "Shellcode failed")
        if ecx & (1 << 31):
            return Check("Hypervisor bit CPUID.1:ECX[31]", "CPUID", DETECTED,
                         f"SET — hypervisor present  ECX=0x{ecx:08X}", severity=3)
        return Check("Hypervisor bit CPUID.1:ECX[31]", "CPUID", CLEAN,
                     f"Clear  ECX=0x{ecx:08X}")

    def check_vendor_string(self) -> Check:
        ebx = _cpuid(0x40000000, 'ebx')
        ecx = _cpuid(0x40000000, 'ecx')
        edx = _cpuid(0x40000000, 'edx')
        if None in (ebx, ecx, edx):
            return Check("Hypervisor vendor CPUID 0x40000000", "CPUID", ERROR, "Shellcode failed")
        vendor = struct.pack('<III', ebx, ecx, edx).rstrip(b'\x00').decode('ascii', errors='replace')
        KNOWN = {
            'KVMKVMKVM': 'KVM',
            'VMwareVMware': 'VMware',
            'VBoxVBoxVBox': 'VirtualBox',
            'Microsoft Hv': 'Hyper-V',
            'XenVMMXenVMM': 'Xen',
            'TCGTCGTCGTCG': 'QEMU/TCG',
            'prl hyperv': 'Parallels',
        }
        for sig, name in KNOWN.items():
            if vendor.startswith(sig):
                return Check("Hypervisor vendor CPUID 0x40000000", "CPUID", DETECTED,
                             f"'{vendor}' → {name}", severity=3)
        if ebx == ecx == edx == 0:
            return Check("Hypervisor vendor CPUID 0x40000000", "CPUID", CLEAN, "No vendor string")
        return Check("Hypervisor vendor CPUID 0x40000000", "CPUID", SUSPICIOUS,
                     f"Unknown vendor: '{vendor}'  (0x{ebx:08X} 0x{ecx:08X} 0x{edx:08X})", severity=2)

    def check_kvm_features(self) -> Check:
        eax = _cpuid(0x40000001, 'eax')
        if eax is None:
            return Check("KVM feature bits CPUID 0x40000001", "CPUID", ERROR, "Shellcode failed")
        KVM_BITS = {0:'CLOCKSOURCE', 1:'NOP_IO_DELAY', 4:'CLOCKSOURCE2',
                    5:'ASYNC_PF', 8:'PV_EOI', 9:'PV_UNHALT', 24:'CLOCKSOURCE_STABLE'}
        found = [name for bit, name in KVM_BITS.items() if eax & (1 << bit)]
        if found:
            return Check("KVM feature bits CPUID 0x40000001", "CPUID", DETECTED,
                         f"KVM features: {', '.join(found)}", severity=3)
        return Check("KVM feature bits CPUID 0x40000001", "CPUID", CLEAN, f"EAX=0x{eax:08X}")

    def run(self) -> List[Check]:
        return [self.check_hypervisor_bit(), self.check_vendor_string(), self.check_kvm_features()]


# ── Registry ──────────────────────────────────────────────────────────────────

def _reg_read(hive, path: str, key: str) -> Optional[str]:
    try:
        with winreg.OpenKey(hive, path) as k:
            return str(winreg.QueryValueEx(k, key)[0])
    except Exception:
        return None

def _reg_exists(hive, path: str) -> bool:
    try:
        winreg.OpenKey(hive, path).Close()
        return True
    except Exception:
        return False

VM_STRINGS = ['QEMU', 'VBOX', 'VMWARE', 'BOCHS', 'SEABIOS', 'VIRTUAL', 'INNOTEK', 'KVM']

class RegistryModule:
    def check_bios_strings(self) -> List[Check]:
        results = []
        path = r"HARDWARE\DESCRIPTION\System\BIOS"
        fields = [
            ('SystemManufacturer', 'BIOS Manufacturer'),
            ('SystemProductName',  'BIOS Product Name'),
            ('BIOSVendor',         'BIOS Vendor'),
            ('BIOSVersion',        'BIOS Version'),
            ('BaseBoardManufacturer', 'Baseboard Manufacturer'),
            ('BaseBoardProduct',   'Baseboard Product'),
        ]
        for reg_key, label in fields:
            val = _reg_read(winreg.HKEY_LOCAL_MACHINE, path, reg_key)
            if val is None:
                results.append(Check(f"Reg BIOS: {label}", "Registry", ERROR, "Key missing"))
                continue
            match = next((s for s in VM_STRINGS if s in val.upper()), None)
            if match:
                results.append(Check(f"Reg BIOS: {label}", "Registry", DETECTED,
                                     f"'{val}' contains '{match}'", severity=3))
            else:
                results.append(Check(f"Reg BIOS: {label}", "Registry", CLEAN, val))
        return results

    def check_disk_enum(self) -> Check:
        path = r"SYSTEM\CurrentControlSet\Services\Disk\Enum"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                count = int(winreg.QueryValueEx(k, 'Count')[0])
                disks = []
                for i in range(count):
                    try:
                        disks.append(str(winreg.QueryValueEx(k, str(i))[0]))
                    except Exception:
                        pass
            for disk in disks:
                match = next((s for s in VM_STRINGS if s in disk.upper()), None)
                if match:
                    return Check("Reg Disk Enum", "Registry", DETECTED,
                                 f"'{disk}' contains '{match}'", severity=3)
            return Check("Reg Disk Enum", "Registry", CLEAN, f"{len(disks)} disk(s): {disks}")
        except Exception as e:
            return Check("Reg Disk Enum", "Registry", ERROR, str(e))

    def check_vm_keys(self) -> List[Check]:
        KEYS = [
            (r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", "Hyper-V Guest Params"),
            (r"SOFTWARE\VMware, Inc.\VMware Tools",                  "VMware Tools"),
            (r"SOFTWARE\Oracle\VirtualBox Guest Additions",          "VirtualBox GA"),
            (r"SYSTEM\CurrentControlSet\Services\VBoxGuest",         "VBoxGuest driver"),
            (r"SYSTEM\CurrentControlSet\Services\vmbus",             "VMbus (Hyper-V)"),
            (r"SYSTEM\CurrentControlSet\Services\netkvm",            "netkvm (VirtIO NIC)"),
            (r"SYSTEM\CurrentControlSet\Services\vioscsi",           "vioscsi (VirtIO SCSI)"),
        ]
        results = []
        for path, label in KEYS:
            exists = _reg_exists(winreg.HKEY_LOCAL_MACHINE, path)
            results.append(Check(f"Reg VM Key: {label}", "Registry",
                                 DETECTED if exists else CLEAN,
                                 f"{'EXISTS' if exists else 'absent'}: HKLM\\{path}",
                                 severity=3 if exists else 1))
        return results

    def check_ttl(self) -> Check:
        path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        val = _reg_read(winreg.HKEY_LOCAL_MACHINE, path, 'DefaultTTL')
        if val is None:
            return Check("Reg DefaultTTL", "Registry", SUSPICIOUS,
                         "Not set (default OS value, Linux default=64, Windows=128)", severity=1)
        ttl = int(val)
        if ttl == 128:
            return Check("Reg DefaultTTL", "Registry", CLEAN, f"TTL={ttl} (Windows default)")
        if ttl == 64:
            return Check("Reg DefaultTTL", "Registry", DETECTED,
                         f"TTL={ttl} — Linux default, not typical for Windows", severity=2)
        return Check("Reg DefaultTTL", "Registry", SUSPICIOUS, f"TTL={ttl} (unusual)", severity=1)

    def run(self) -> List[Check]:
        return [*self.check_bios_strings(), self.check_disk_enum(),
                *self.check_vm_keys(), self.check_ttl()]


# ── WMI ───────────────────────────────────────────────────────────────────────

VM_MAC_OUI: Dict[str, str] = {
    '52:54:00': 'QEMU/KVM',
    '00:0c:29': 'VMware',
    '00:50:56': 'VMware vSphere',
    '08:00:27': 'VirtualBox',
    '00:15:5d': 'Hyper-V',
    '00:16:3e': 'Xen',
}

class WMIModule:
    def __init__(self):
        self._c: Optional[object] = None
        if HAS_WMI:
            try:
                self._c = wmi.WMI()
            except Exception:
                pass

    def _q(self, wql: str) -> List:
        if not self._c:
            return []
        try:
            return self._c.query(wql)
        except Exception:
            return []

    def check_computer_system(self) -> List[Check]:
        rows = self._q("SELECT Manufacturer, Model, HypervisorPresent FROM Win32_ComputerSystem")
        if not rows:
            return [Check("WMI Win32_ComputerSystem", "WMI", ERROR, "Query failed")]
        results = []
        for row in rows:
            mfr   = getattr(row, 'Manufacturer', '') or ''
            model = getattr(row, 'Model', '') or ''
            hv    = getattr(row, 'HypervisorPresent', None)
            results.append(Check("WMI HypervisorPresent", "WMI",
                                 DETECTED if hv else CLEAN,
                                 f"HypervisorPresent={hv}", severity=3 if hv else 1))
            combo = (mfr + model).upper()
            match = next((s for s in VM_STRINGS if s in combo), None)
            if match:
                results.append(Check("WMI Manufacturer/Model", "WMI", DETECTED,
                                     f"'{mfr} / {model}' → '{match}'", severity=3))
            else:
                results.append(Check("WMI Manufacturer/Model", "WMI", CLEAN, f"{mfr} / {model}"))
        return results

    def check_bios(self) -> List[Check]:
        rows = self._q("SELECT Manufacturer, Version, SerialNumber FROM Win32_BIOS")
        if not rows:
            return [Check("WMI Win32_BIOS", "WMI", ERROR, "Query failed")]
        results = []
        for row in rows:
            mfr = getattr(row, 'Manufacturer', '') or ''
            ver = getattr(row, 'Version', '') or ''
            sn  = getattr(row, 'SerialNumber', '') or ''
            match = next((s for s in VM_STRINGS if s in (mfr+ver).upper()), None)
            if match:
                results.append(Check("WMI BIOS", "WMI", DETECTED,
                                     f"'{mfr} / {ver}' → '{match}'", severity=3))
            else:
                results.append(Check("WMI BIOS", "WMI", CLEAN, f"{mfr} / {ver} SN={sn}"))
        return results

    def check_disks(self) -> List[Check]:
        rows = self._q("SELECT Model, SerialNumber FROM Win32_DiskDrive")
        if not rows:
            return [Check("WMI Win32_DiskDrive", "WMI", ERROR, "Query failed")]
        results = []
        for row in rows:
            model = getattr(row, 'Model', '') or ''
            sn    = getattr(row, 'SerialNumber', '') or ''
            match = next((s for s in VM_STRINGS if s in model.upper()), None)
            if match:
                results.append(Check("WMI Disk Drive", "WMI", DETECTED,
                                     f"Model='{model}' SN='{sn}'", severity=2))
            else:
                results.append(Check("WMI Disk Drive", "WMI", CLEAN, f"Model='{model}' SN='{sn}'"))
        return results

    def check_video(self) -> List[Check]:
        rows = self._q("SELECT Name, AdapterCompatibility FROM Win32_VideoController")
        if not rows:
            return [Check("WMI Win32_VideoController", "WMI", ERROR, "Query failed")]
        VM_GPU = ['QEMU', 'VBOX', 'VMWARE', 'BOCHS', 'QXL', 'SVGA', 'VIRTUAL', 'BASIC DISPLAY', 'STANDARD VGA']
        results = []
        for row in rows:
            name   = getattr(row, 'Name', '') or ''
            compat = getattr(row, 'AdapterCompatibility', '') or ''
            match  = next((s for s in VM_GPU if s in (name+compat).upper()), None)
            if match:
                results.append(Check("WMI GPU", "WMI", DETECTED,
                                     f"'{name}' ({compat}) → '{match}'", severity=2))
            else:
                results.append(Check("WMI GPU", "WMI", CLEAN, f"'{name}'"))
        return results

    def check_network(self) -> List[Check]:
        rows = self._q("SELECT Name, MACAddress, Manufacturer FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL")
        if not rows:
            return [Check("WMI Network Adapters", "WMI", ERROR, "Query failed")]
        results = []
        VM_NIC = ['QEMU', 'VMWARE', 'VBOX', 'VIRTUALBOX', 'VIRTIO', 'HYPER-V', 'PARALLELS']
        for row in rows:
            name = getattr(row, 'Name', '') or ''
            mac  = (getattr(row, 'MACAddress', '') or '').lower().replace('-', ':')
            mfr  = getattr(row, 'Manufacturer', '') or ''
            oui  = mac[:8]
            if oui in VM_MAC_OUI:
                results.append(Check("WMI NIC MAC OUI", "WMI", DETECTED,
                                     f"MAC {mac} → OUI={oui} = {VM_MAC_OUI[oui]}  [{name}]",
                                     severity=3))
                continue
            match = next((s for s in VM_NIC if s in (name+mfr).upper()), None)
            if match:
                results.append(Check("WMI NIC Name", "WMI", DETECTED,
                                     f"'{name}' by '{mfr}'", severity=2))
            else:
                results.append(Check("WMI NIC", "WMI", CLEAN, f"'{name}' MAC={mac}"))
        return results

    def run(self) -> List[Check]:
        if not HAS_WMI:
            return [Check("WMI Module", "WMI", ERROR, "pip install wmi  →  then re-run")]
        return [*self.check_computer_system(), *self.check_bios(),
                *self.check_disks(), *self.check_video(), *self.check_network()]


# ── Processes ─────────────────────────────────────────────────────────────────

VM_PROCS: Dict[str, Tuple[str, int]] = {
    'vmtoolsd.exe':   ('VMware Tools daemon', 3),
    'vmwaretray.exe': ('VMware Tray', 3),
    'vmwareuser.exe': ('VMware User', 3),
    'vboxservice.exe':('VirtualBox Service', 3),
    'vboxtray.exe':   ('VirtualBox Tray', 3),
    'qemu-ga.exe':    ('QEMU Guest Agent', 3),
    'spice-agent.exe':('SPICE Agent', 2),
    'vdagent.exe':    ('SPICE VD Agent', 2),
    'vmicsvc.exe':    ('Hyper-V IC Services', 3),
    'balloon.exe':    ('Hyper-V Balloon', 2),
    'prl_tools.exe':  ('Parallels Tools', 3),
}

class ProcessModule:
    def run(self) -> List[Check]:
        if HAS_PSUTIL:
            running = {p.name().lower() for p in psutil.process_iter(['name'])}
        else:
            try:
                out = subprocess.check_output('tasklist /FO CSV /NH', shell=True,
                                              text=True, stderr=subprocess.DEVNULL)
                running = {l.split(',')[0].strip('"').lower() for l in out.splitlines() if l}
            except Exception:
                return [Check("Processes", "Processes", ERROR, "Could not enumerate processes")]

        found = []
        for proc, (label, sev) in VM_PROCS.items():
            if proc in running:
                found.append(Check(f"Process: {proc}", "Processes", DETECTED,
                                   f"Running → {label}", severity=sev))
        if not found:
            found.append(Check("Processes: VM Guest Agents", "Processes", CLEAN,
                               "No VM agent processes found"))
        return found


# ── Files / Drivers ───────────────────────────────────────────────────────────

VM_FILES: Dict[str, Tuple[str, int]] = {
    r'C:\Windows\System32\drivers\vmhgfs.sys':   ('VMware HGFS', 3),
    r'C:\Windows\System32\drivers\vmmouse.sys':  ('VMware Mouse', 2),
    r'C:\Windows\System32\drivers\vm3dmp.sys':   ('VMware 3D', 2),
    r'C:\Windows\System32\drivers\VBoxGuest.sys':('VirtualBox Guest', 3),
    r'C:\Windows\System32\drivers\VBoxSF.sys':   ('VirtualBox SharedFolders', 3),
    r'C:\Windows\System32\drivers\VBoxMouse.sys':('VirtualBox Mouse', 2),
    r'C:\Windows\System32\drivers\VBoxVideo.sys':('VirtualBox Video', 2),
    r'C:\Windows\System32\drivers\vioser.sys':   ('VirtIO Serial', 2),
    r'C:\Windows\System32\drivers\vioscsi.sys':  ('VirtIO SCSI', 2),
    r'C:\Windows\System32\drivers\netkvm.sys':   ('VirtIO NIC', 3),
    r'C:\Windows\System32\drivers\balloon.sys':  ('Hyper-V Balloon', 2),
    r'C:\Windows\System32\qemu-ga.exe':          ('QEMU Guest Agent', 3),
    r'C:\Program Files\QEMU\qemu-ga.exe':        ('QEMU Guest Agent', 3),
}

class FilesModule:
    def run(self) -> List[Check]:
        found = []
        for path, (label, sev) in VM_FILES.items():
            if os.path.exists(path):
                found.append(Check(f"File: {os.path.basename(path)}", "Files/Drivers",
                                   DETECTED, f"{path} → {label}", severity=sev))
        if not found:
            found.append(Check("Files/Drivers: VM artifacts", "Files/Drivers", CLEAN,
                               "No VM driver files found"))
        return found


# ── Network MAC ───────────────────────────────────────────────────────────────

class NetworkModule:
    def _get_macs(self) -> List[str]:
        macs = []
        if HAS_PSUTIL:
            try:
                for addrs in psutil.net_if_addrs().values():
                    for a in addrs:
                        if hasattr(psutil, 'AF_LINK') and a.family == psutil.AF_LINK:
                            macs.append(a.address.lower())
            except Exception:
                pass
        if not macs:
            try:
                out = subprocess.check_output('getmac /FO CSV /NH /V', shell=True,
                                              text=True, stderr=subprocess.DEVNULL)
                for line in out.splitlines():
                    parts = [p.strip('"') for p in line.split(',')]
                    if len(parts) >= 3:
                        mac = parts[2].replace('-', ':').lower()
                        if re.match(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}', mac):
                            macs.append(mac)
            except Exception:
                pass
        return macs

    def run(self) -> List[Check]:
        macs = self._get_macs()
        if not macs:
            return [Check("Network MAC OUI", "Network", ERROR, "Could not enumerate MACs")]
        results = []
        for mac in macs:
            oui = mac[:8]
            if oui in VM_MAC_OUI:
                results.append(Check("Network MAC OUI", "Network", DETECTED,
                                     f"MAC {mac} → {VM_MAC_OUI[oui]}", severity=3))
            else:
                results.append(Check("Network MAC", "Network", CLEAN, f"MAC {mac} (OUI clean)"))
        return results


# ── Timing ────────────────────────────────────────────────────────────────────

class TimingModule:
    def check_sleep_jitter(self) -> Check:
        samples = []
        for _ in range(20):
            t0 = time.perf_counter()
            time.sleep(0.001)
            samples.append((time.perf_counter() - t0) * 1000)
        avg = sum(samples) / len(samples)
        variance = sum((s - avg) ** 2 for s in samples) / len(samples)
        if variance > 8.0:
            return Check("Timing: Sleep jitter", "Timing", SUSPICIOUS,
                         f"High variance={variance:.2f}ms²  (VM exits add latency)", severity=1)
        return Check("Timing: Sleep jitter", "Timing", CLEAN, f"Variance={variance:.3f}ms²")

    def check_cpu_loop(self) -> Check:
        t0 = time.perf_counter()
        x = sum(range(2_000_000))
        elapsed = (time.perf_counter() - t0) * 1000
        if elapsed > 200:
            return Check("Timing: CPU loop", "Timing", SUSPICIOUS,
                         f"{elapsed:.1f}ms — possibly throttled VM", severity=1)
        return Check("Timing: CPU loop", "Timing", CLEAN, f"{elapsed:.1f}ms")

    def run(self) -> List[Check]:
        return [self.check_sleep_jitter(), self.check_cpu_loop()]


# ── PowerShell extra checks ───────────────────────────────────────────────────

class PowerShellModule:
    def _ps(self, cmd: str) -> Optional[str]:
        try:
            return subprocess.check_output(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd],
                text=True, stderr=subprocess.DEVNULL, timeout=15
            ).strip()
        except Exception:
            return None

    def check_tpm(self) -> Check:
        out = self._ps("(Get-Tpm).TpmPresent")
        if out is None:
            return Check("PowerShell: TPM present", "PowerShell", ERROR, "Get-Tpm failed")
        if out.lower() == 'true':
            return Check("PowerShell: TPM present", "PowerShell", CLEAN,
                         "TPM reported present (could be swtpm 2.0 emulation)")
        return Check("PowerShell: TPM present", "PowerShell", SUSPICIOUS,
                     f"TpmPresent={out}", severity=1)

    def check_secure_boot(self) -> Check:
        out = self._ps("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue")
        if out is None:
            return Check("PowerShell: Secure Boot", "PowerShell", SUSPICIOUS,
                         "Cmdlet unavailable — BIOS/legacy mode?", severity=1)
        if out.lower() == 'true':
            return Check("PowerShell: Secure Boot", "PowerShell", CLEAN, "Secure Boot ON")
        return Check("PowerShell: Secure Boot", "PowerShell", SUSPICIOUS,
                     f"Secure Boot={out}", severity=1)

    def check_hyperv_present(self) -> Check:
        out = self._ps("(systeminfo | Select-String 'Hyper-V Requirements').Line")
        if out and 'hypervisor has been detected' in out.lower():
            return Check("PowerShell: systeminfo Hyper-V", "PowerShell", DETECTED,
                         out.strip(), severity=2)
        return Check("PowerShell: systeminfo Hyper-V", "PowerShell", CLEAN,
                     out.strip() if out else "No hypervisor mention")

    def check_screen_res(self) -> Check:
        out = self._ps(
            "(Get-WmiObject Win32_VideoController | Select-Object -First 1).CurrentHorizontalResolution"
        )
        if out is None:
            return Check("PowerShell: Screen resolution", "PowerShell", ERROR, "Query failed")
        try:
            w = int(out)
            if w < 800:
                return Check("PowerShell: Screen resolution", "PowerShell", SUSPICIOUS,
                             f"Width={w}px — very low, typical for unconfigured VM", severity=1)
        except ValueError:
            pass
        return Check("PowerShell: Screen resolution", "PowerShell", CLEAN, f"Width={out}px")

    def check_event_log(self) -> Check:
        out = self._ps(
            "Get-EventLog -LogName System -Source '*Hyper*','*VMware*','*VBox*','*QEMU*' "
            "-Newest 5 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -Expand Count"
        )
        if out is None:
            return Check("PowerShell: Event log VM entries", "PowerShell", ERROR, "Query failed")
        count = int(out) if out.isdigit() else 0
        if count > 0:
            return Check("PowerShell: Event log VM entries", "PowerShell", DETECTED,
                         f"{count} VM-related event log entries found", severity=2)
        return Check("PowerShell: Event log VM entries", "PowerShell", CLEAN, "No VM events found")

    def run(self) -> List[Check]:
        return [self.check_tpm(), self.check_secure_boot(), self.check_hyperv_present(),
                self.check_screen_res(), self.check_event_log()]


# ── Screen Capture (bypass screenshot protection) ─────────────────────────────

class ScreenCapture:
    """
    Capture screen even when apps use SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE).

    Method 1 — DXGI Desktop Duplication (mss library):
        Reads directly from GPU output. Bypasses WDA_EXCLUDEFROMCAPTURE on Windows 10/11.
        Apps that set their window as excluded still show up because DXGI captures
        at the compositor level before exclusion is applied to the capture API.

    Method 2 — GDI BitBlt (ctypes, no deps):
        Fallback. Bypasses basic SetWindowDisplayAffinity but not HDCP/DRM fullscreen.

    Method 3 — PrintWindow PW_RENDERFULLCONTENT (per-window):
        Forces re-render of a specific window bypassing WDA_EXCLUDEFROMCAPTURE.
        Used when you know the target HWND.
    """

    @staticmethod
    def _output_path(suffix='') -> str:
        desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
        ts = int(time.time())
        return os.path.join(desktop, f'vmdetect_cap{suffix}_{ts}.png')

    @staticmethod
    def _gdi_capture(path: str) -> bool:
        """Pure ctypes GDI BitBlt — no extra deps."""
        try:
            user32 = ctypes.windll.user32
            gdi32  = ctypes.windll.gdi32

            w = user32.GetSystemMetrics(0)
            h = user32.GetSystemMetrics(1)

            hdc     = user32.GetDC(None)
            hdc_mem = gdi32.CreateCompatibleDC(hdc)
            hbmp    = gdi32.CreateCompatibleBitmap(hdc, w, h)
            gdi32.SelectObject(hdc_mem, hbmp)
            gdi32.BitBlt(hdc_mem, 0, 0, w, h, hdc, 0, 0, 0x00CC0020)  # SRCCOPY

            # BITMAPINFOHEADER
            bi_size = 40
            bi = struct.pack('<IiiHHIIiiII', bi_size, w, -h, 1, 32, 0, w*h*4, 0, 0, 0, 0)
            buf = (ctypes.c_byte * (w * h * 4))()
            gdi32.GetDIBits(hdc_mem, hbmp, 0, h, buf, bi + b'\x00'*4, 0)

            # Write minimal BMP then convert via struct
            bmp_path = path.replace('.png', '.bmp')
            file_size = 54 + w * h * 4
            bfh = struct.pack('<HIHH I', 0x4D42, file_size, 0, 0, 54)
            with open(bmp_path, 'wb') as f:
                f.write(bfh + bi + bytes(buf))

            # Convert BMP → PNG if Pillow available
            try:
                from PIL import Image
                Image.open(bmp_path).save(path)
                os.remove(bmp_path)
            except ImportError:
                os.rename(bmp_path, path.replace('.png', '.bmp'))
                path = path.replace('.png', '.bmp')

            gdi32.DeleteObject(hbmp)
            gdi32.DeleteDC(hdc_mem)
            user32.ReleaseDC(None, hdc)
            return True
        except Exception:
            return False

    @staticmethod
    def _print_window_capture(hwnd: int, path: str) -> bool:
        """
        PrintWindow with PW_RENDERFULLCONTENT — forces re-render of one window,
        bypassing WDA_EXCLUDEFROMCAPTURE even on Windows 11.
        """
        try:
            from PIL import Image
            user32 = ctypes.windll.user32
            gdi32  = ctypes.windll.gdi32

            rect = ctypes.wintypes.RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rect))
            w = rect.right  - rect.left
            h = rect.bottom - rect.top
            if w <= 0 or h <= 0:
                return False

            hdc_win = user32.GetDC(hwnd)
            hdc_mem = gdi32.CreateCompatibleDC(hdc_win)
            hbmp    = gdi32.CreateCompatibleBitmap(hdc_win, w, h)
            gdi32.SelectObject(hdc_mem, hbmp)

            PW_RENDERFULLCONTENT = 0x00000002
            user32.PrintWindow(hwnd, hdc_mem, PW_RENDERFULLCONTENT)

            bi  = struct.pack('<IiiHHIIiiII', 40, w, -h, 1, 32, 0, w*h*4, 0, 0, 0, 0)
            buf = (ctypes.c_byte * (w * h * 4))()
            gdi32.GetDIBits(hdc_mem, hbmp, 0, h, buf, bi + b'\x00'*4, 0)

            img = Image.frombytes('RGBA', (w, h), bytes(buf), 'raw', 'BGRA')
            img.save(path)

            gdi32.DeleteObject(hbmp)
            gdi32.DeleteDC(hdc_mem)
            user32.ReleaseDC(hwnd, hdc_win)
            return True
        except Exception:
            return False

    def capture_full(self, delay: float = 0, output: str = '') -> str:
        """
        Full-screen capture bypassing screenshot protection.
        delay: seconds to wait before capturing (use to switch to target app first).
        """
        if delay > 0:
            if HAS_RICH:
                Console().print(f"[cyan]Capturing in {delay:.0f}s — switch to your target app now...[/cyan]")
            else:
                print(f"Capturing in {delay:.0f}s — switch to target app now...")
            time.sleep(delay)

        path = output or self._output_path()

        # Method 1: DXGI via mss (best — bypasses WDA_EXCLUDEFROMCAPTURE)
        if HAS_MSS:
            try:
                with mss.mss() as sct:
                    mon = sct.monitors[0]   # 0 = all monitors combined
                    img = sct.grab(mon)
                    mss.tools.to_png(img.rgb, img.size, output=path)
                    return path
            except Exception:
                pass

        # Method 2: GDI BitBlt fallback
        if self._gdi_capture(path):
            return path

        return ''

    def capture_window(self, title_substr: str, delay: float = 0, output: str = '') -> str:
        """
        Capture a specific window by partial title match using PrintWindow PW_RENDERFULLCONTENT.
        Bypasses WDA_EXCLUDEFROMCAPTURE for that window even if DXGI can't.
        """
        if delay > 0:
            if HAS_RICH:
                Console().print(f"[cyan]Window capture in {delay:.0f}s...[/cyan]")
            time.sleep(delay)

        path = output or self._output_path(f'_win')

        EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
        handles = []

        def _cb(hwnd, _):
            length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
            if title_substr.lower() in buf.value.lower() and ctypes.windll.user32.IsWindowVisible(hwnd):
                handles.append(hwnd)
            return True

        ctypes.windll.user32.EnumWindows(EnumWindowsProc(_cb), 0)

        if not handles:
            return ''

        return path if self._print_window_capture(handles[0], path) else ''


# ── Orchestrator ──────────────────────────────────────────────────────────────

ALL_MODULES = {
    'CPUID':      CPUIDModule,
    'Registry':   RegistryModule,
    'WMI':        WMIModule,
    'Processes':  ProcessModule,
    'Files':      FilesModule,
    'Network':    NetworkModule,
    'Timing':     TimingModule,
    'PowerShell': PowerShellModule,
}

def run_checks(categories: Optional[List[str]] = None) -> List[Check]:
    results = []
    for name, cls in ALL_MODULES.items():
        if categories and name not in categories:
            continue
        try:
            results.extend(cls().run())
        except Exception as e:
            results.append(Check(name, name, ERROR, f"Module crashed: {e}"))
    return results


# ── Output ────────────────────────────────────────────────────────────────────

STATUS_STYLE = {
    CLEAN:      ('[green]✓ CLEAN[/green]',     'green'),
    DETECTED:   ('[bold red]✗ DETECTED[/bold red]', 'red'),
    SUSPICIOUS: ('[yellow]? SUSPICIOUS[/yellow]', 'yellow'),
    ERROR:      ('[dim]! ERROR[/dim]',          'dim'),
}

def print_rich(results: List[Check]):
    console = Console()
    console.print()
    console.print(Panel.fit(
        "[bold red]VMDetect Lab v1.0[/bold red]  ·  [cyan]FothOS Attack Tool[/cyan]\n"
        "[dim]8 attack layers  ·  run inside Windows 11 to test VM stealth[/dim]",
        border_style="red"
    ))
    console.print()

    cats: Dict[str, List[Check]] = {}
    for r in results:
        cats.setdefault(r.category, []).append(r)

    for cat, items in cats.items():
        t = Table(title=f"[bold cyan]{cat}[/bold cyan]", box=box.SIMPLE_HEAD,
                  show_header=True, header_style="bold")
        t.add_column("Status",  width=18)
        t.add_column("Check",   width=46)
        t.add_column("Detail")
        for r in items:
            s, color = STATUS_STYLE.get(r.status, ('?', 'white'))
            detail = r.detail if len(r.detail) <= 90 else r.detail[:87] + '...'
            t.add_row(s, r.name, f"[dim]{detail}[/dim]")
        console.print(t)

    detected   = [r for r in results if r.status == DETECTED]
    suspicious = [r for r in results if r.status == SUSPICIOUS]
    total      = len([r for r in results if r.status != ERROR])
    clean      = total - len(detected) - len(suspicious)

    if not detected and not suspicious:
        verdict, border = "[bold green]BARE METAL  (or perfect stealth — nothing leaked)[/bold green]", "green"
    elif not detected:
        verdict, border = "[bold yellow]SUSPICIOUS  — looks mostly clean but some weak signals[/bold yellow]", "yellow"
    elif len(detected) <= 4:
        verdict, border = "[bold orange1]LIKELY VM  — partial artifacts leaked[/bold orange1]", "yellow"
    else:
        verdict, border = "[bold red]VM DETECTED  — multiple layers leaked[/bold red]", "red"

    leaked_lines = '\n'.join(
        f"  [red]✗[/red] [{r.category}] {r.name}: {r.detail[:70]}"
        for r in detected[:15]
    ) or "  [green]none[/green]"
    if len(detected) > 15:
        leaked_lines += f"\n  [dim]... and {len(detected)-15} more[/dim]"

    console.print(Panel(
        f"{verdict}\n\n"
        f"  [red]Detected[/red]: {len(detected)}  ·  "
        f"[yellow]Suspicious[/yellow]: {len(suspicious)}  ·  "
        f"[green]Clean[/green]: {clean}  ·  "
        f"Total: {total}\n\n"
        f"[bold]Leaked checks:[/bold]\n{leaked_lines}",
        title="[bold]VERDICT[/bold]", border_style=border
    ))

def print_plain(results: List[Check]):
    print("\n=== VMDetect Lab v1.0 ===\n")
    for r in results:
        sym = {'CLEAN': '✓', 'DETECTED': '✗', 'SUSPICIOUS': '?', 'ERROR': '!'}.get(r.status, '?')
        print(f"  [{r.category}] {sym} {r.name}: {r.detail}")
    detected   = [r for r in results if r.status == DETECTED]
    suspicious = [r for r in results if r.status == SUSPICIOUS]
    total      = len([r for r in results if r.status != ERROR])
    print(f"\nVERDICT: {len(detected)} DETECTED / {len(suspicious)} SUSPICIOUS / {total} total checks")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="VMDetect — FothOS VM Detection Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Categories: {', '.join(ALL_MODULES.keys())}"
    )
    parser.add_argument('--json',             action='store_true', help='Output JSON report')
    parser.add_argument('--no-color',         action='store_true', help='Plain text output')
    parser.add_argument('--category',         nargs='+', metavar='CAT',
                        help='Run only these categories')
    parser.add_argument('--screenshot',       action='store_true',
                        help='Capture full screen (bypasses screenshot protection) and exit')
    parser.add_argument('--screenshot-delay', type=float, default=0, metavar='SEC',
                        help='Wait N seconds before screenshot (switch to target app first)')
    parser.add_argument('--screenshot-window', metavar='TITLE',
                        help='Capture a specific window by partial title match')
    parser.add_argument('--screenshot-out',   metavar='PATH',
                        help='Output path for screenshot (default: Desktop/vmdetect_cap_<ts>.png)')
    args = parser.parse_args()

    # ── Screenshot-only mode ──────────────────────────────────────────────────
    if args.screenshot or args.screenshot_window:
        if sys.platform != 'win32':
            print("ERROR: Screenshot mode requires Windows.")
            sys.exit(1)
        cap = ScreenCapture()
        out = args.screenshot_out or ''
        if args.screenshot_window:
            path = cap.capture_window(args.screenshot_window, delay=args.screenshot_delay, output=out)
        else:
            path = cap.capture_full(delay=args.screenshot_delay, output=out)

        if path:
            if HAS_RICH and not args.no_color:
                Console().print(f"[green]Screenshot saved:[/green] {path}")
            else:
                print(f"Screenshot saved: {path}")
        else:
            print("ERROR: Screenshot failed — no mss or GDI available.")
            sys.exit(1)
        return

    if sys.platform != 'win32':
        print("ERROR: VMDetect must run inside Windows. Copy vmdetect.py to the Windows VM.")
        sys.exit(1)

    cats = args.category if args.category else None

    if HAS_RICH and not args.json and not args.no_color:
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
            t = p.add_task("Running all detection layers...", total=None)
            results = run_checks(cats)
        print_rich(results)
    else:
        results = run_checks(cats)
        if args.json:
            print(json.dumps([{
                'name': r.name, 'category': r.category,
                'status': r.status, 'detail': r.detail, 'severity': r.severity,
            } for r in results], indent=2))
            return
        print_plain(results)

    # Save JSON report to Desktop
    report = [{'name': r.name, 'category': r.category, 'status': r.status,
                'detail': r.detail, 'severity': r.severity} for r in results]
    out_path = os.path.join(os.path.expanduser('~'), 'Desktop', 'vmdetect_report.json')
    try:
        with open(out_path, 'w') as f:
            json.dump(report, f, indent=2)
        if HAS_RICH and not args.no_color:
            Console().print(f"\n[dim]Report → {out_path}[/dim]")
        else:
            print(f"\nReport saved: {out_path}")
    except Exception:
        pass


if __name__ == '__main__':
    main()
