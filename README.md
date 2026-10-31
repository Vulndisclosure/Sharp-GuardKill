
# CredGuard Killer 

(C# port of CredGuardRuntimeShutdown. https://github.com/S12cybersecurity/CredGuardRuntimeShutdown)

A minimal, dependency-free PoC that disables Windows **Credential Guard** at runtime by signaling the internal LSA ISO event `\LSA_ISO_DISABLE_CREDENTIAL_GUARD`.

The tool is designed for offensive security research, red-team engagements, and lab environments where you need to tear down Credential Guard without a reboot and **verify with certainty** whether the teardown actually succeeded.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Precise Teardown Confirmation](#precise-teardown-confirmation)
- [Exit Codes](#exit-codes)
- [Requirements](#requirements)
- [Compilation](#compilation)
- [Usage](#usage)
- [Sliver `execute-assembly` Notes](#sliver-execute-assembly-notes)
- [Why Not WMI](#why-not-wmi)
- [Limitations](#limitations)
- [Disclaimer](#disclaimer)

---

## Overview

Windows Credential Guard isolates LSA secrets inside a Hyper-V-backed secure process (`LsaIso.exe`, aka *LSA ISO*). The underlying mechanism used by Windows itself to disable CredGuard during shutdown is a named event, `\LSA_ISO_DISABLE_CREDENTIAL_GUARD`, exposed in the `lsaiso` namespace.

This PoC:

1. Enables `SeDebugPrivilege` on its own process token.
2. Steals a SYSTEM token from `winlogon.exe` / `services.exe` / `lsass.exe`.
3. Opens the CredGuard teardown event under SYSTEM impersonation.
4. Signals it via `NtSetEvent`.
5. **Polls `NtOpenEvent` until the event disappears**, proving the teardown completed.
6. Reverts impersonation and exits with a status code that encodes the outcome.

No reboot. No WMI. No `System.Management.dll`. No registry writes. No process spawns. Only `mscorlib` + `System.dll`.

---

## How It Works

Credential Guard is implemented as a component running inside `LsaIso.exe`, which itself runs under VBS (Virtualization-Based Security). When VBS shuts down (or when CredGuard is deliberately disabled), the normal Windows sequence is:

```

lsaiso creates \LSA_ISO_DISABLE_CREDENTIAL_GUARD
↓
caller opens + signals the event (NT AUTHORITY\SYSTEM required)
↓
lsaiso sees the signal and unloads the CredGuard subsystem
↓
lsaiso deletes the event

```

Because `lsaiso` destroys the event **only after** the CredGuard subsystem has been unloaded, the **existence of the event after signaling** is a reliable, race-free indicator of whether the teardown completed.

The PoC leverages this behavior directly — it does not need WMI, registry, or process-marker heuristics.

---

## Precise Teardown Confirmation

After signaling, the tool enters a **polling loop** (1 s interval, 10 s timeout). Each iteration calls `NtOpenEvent` on the same name and interprets the NTSTATUS:

| NTSTATUS | Meaning | Action |
|---|---|---|
| `STATUS_OBJECT_NAME_NOT_FOUND` (`0xC0000034`) | Event has been deleted by `lsaiso` → **teardown confirmed** | Exit `0` |
| `STATUS_SUCCESS` (`0x00000000`) | Event still present → teardown in progress | Sleep, retry |
| `STATUS_ACCESS_DENIED` (`0xC0000022`) | Event exists, but no rights (event still alive) | Sleep, retry |
| Other | Treat as still present | Sleep, retry |

On timeout, the tool exits with `3`.

This is the only reliable way to confirm CredGuard teardown in-process without WMI:

- The registry keeps `LsaCfgFlags=1/2` even after teardown (it reflects *intent*, not *runtime*).
- `LsaIso.exe` keeps running after teardown (it hosts more than just CredGuard).
- WMI `Win32_DeviceGuard.SecurityServicesRunning` does reflect runtime state, but requires `System.Management.dll` from the GAC — a fragile dependency under `execute-assembly`.

---

## Exit Codes

```

Code 0  - CredGuard disabled (or already disabled, teardown confirmed)
Code 1  - SYSTEM impersonation failed (missing privileges)
Code 3  - Signal delivered, but event did not disappear within 10s (teardown incomplete)
Code 4  - Failed to open the event (likely ACCESS_DENIED)
Code 5  - NtSetEvent failed
Code 99 - Unexpected result

```

---

## Requirements

**Target:**

- Windows 10 / 11 / Server 2016+ with Virtualization-Based Security **enabled and running**
- Credential Guard **configured** (otherwise there is nothing to tear down — exit `0` / `AlreadyOff`)
- Caller process running as **SYSTEM** (or as Administrator with `SeDebugPrivilege`, plus at least one SYSTEM process reachable via `OpenProcess`)
- **x64** process (do not run from a 32-bit host)

**Build host:**

- Mono (`mcs`) — tested on Kali Linux
- or .NET Framework `csc.exe` 3.5 / 4.0
- or Roslyn `csc.exe` from Visual Studio / Build Tools

---

## Compilation

The source targets the **C# 3.0** syntax level to maximize compiler compatibility (Mono `mcs`, .NET 3.5 `csc`, .NET 4.x `csc`, Roslyn). No C# 6/7/8 features are used.

### Mono (Kali / Linux)

```bash
TERM=dumb mcs -target:exe -platform:x64 -optimize+ \
  -out:CredGuardPoc.exe \
  -r:System.dll \
  CredGuardPoc.cs
```

The TERM=dumb prefix works around a Mono bug on some distros where terminfo files exceed the 4 KB limit and crash System.Console initialization.

.NET Framework (Windows)

```cmd
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
  /target:exe /platform:x64 /optimize+ ^
  /out:CredGuardPoc.exe ^
  /r:System.dll ^
  CredGuardPoc.cs
```

Roslyn (Windows, from VS or Build Tools)

```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe" ^
  /target:exe /platform:x64 /optimize+ ^
  /out:CredGuardPoc.exe ^
  /r:System.dll ^
  CredGuardPoc.cs
```

Verification

```cmd
dumpbin /headers CredGuardPoc.exe | findstr machine
```

Expected output:

```
8664 machine (x64)
```

Assembly dependencies should be limited to mscorlib and System:

```cmd
dumpbin /dependents CredGuardPoc.exe
```

---

Usage

Standalone (interactive)

```
CredGuardPoc.exe
```

Requires the current token to be NT AUTHORITY\SYSTEM (or elevated admin with SeDebugPrivilege).

```
=== CredGuardPoc.exe (Mono teardown-only, with precise confirmation) ===

[Stage 0] Enable SeDebugPrivilege
  [+] SeDebugPrivilege enabled

[Stage 1] Impersonate SYSTEM
  [+] Thread impersonating SYSTEM via winlogon.exe (PID 708)

[Stage 2] Signal + confirm teardown (max 10s)
  [+] NtSetEvent OK (prev=0), polling for teardown...
  [~] 1s: event still present, waiting...
  [+] Confirmed: event gone after 2s -> CredGuard torn down

[Stage 3] Revert impersonation
  [+] Reverted

[Result] Disabled
```

Sliver execute-assembly

From a 64-bit beacon running as SYSTEM:

```bash
execute-assembly /path/CredGuardPoc.exe
```

If the beacon is not SYSTEM, use getsystem and migrate into a SYSTEM-owned process first:

```bash
getsystem
migrate <pid_of_system_process>
execute-assembly /path/CredGuardPoc.exe
```

Sliver captures stdout, and the exit code is visible via the beacon console.

---

Sliver execute-assembly Notes

· 64-bit only. The PE is /platform:x64. Loading it from a 32-bit implant yields BadImageFormatException before Main.
· No GAC dependencies. The assembly references only mscorlib and System, both of which are always present in any Windows CLR host.
· No System.Management. The WMI approach was deliberately dropped — see Why Not WMI.
· No process spawns. No powershell.exe, no WmiPrvSE.exe, no child processes.
· No file writes. Everything happens in-memory.
· Reverts impersonation before exiting, so the beacon thread is not left as SYSTEM.

---

Why Not WMI

The original design used Win32_DeviceGuard from root\Microsoft\Windows\DeviceGuard to read SecurityServicesRunning. That approach is functionally correct but problematic under execute-assembly:

1. GAC resolution is unreliable. execute-assembly loads the assembly into the existing AppDomain without a full Fusion/GAC resolver. System.Management.dll frequently fails to resolve, producing FileNotFoundException or TypeLoadException at the first call site.
2. Cross-platform build hazards. mcs on Linux links against Mono's System.Management (partially stubbed), and the resulting PE references the Windows GAC token — a subtle mismatch.
3. COM initialization. ManagementObjectSearcher calls CoInitializeEx, which can conflict with the host process's apartment state (RPC_E_CHANGED_MODE).
4. OPSEC noise. Each WMI query spawns WmiPrvSE.exe and generates DCOM/RPC traffic — extra IOCs in an already sensitive context.

The NtOpenEvent polling loop replaces WMI with a more precise runtime signal at zero dependency cost.

---

Limitations

· VBS must be running. If Virtualization-Based Security is disabled at the firmware/OS level, the lsaiso namespace does not exist — the tool exits 0 / AlreadyOff.
· CredGuard must be configured. If LsaCfgFlags was never set (or was set to 0), the event is not created — exit 0 / AlreadyOff.
· SYSTEM required. SeDebugPrivilege alone is insufficient; the caller must successfully impersonate SYSTEM to acquire the required handle.
· Bypass is not persistent. CredGuard is disabled in the current VBS session only. A reboot re-enables it. Persistence requires modifying the registry or GPO — out of scope for this tool.
· No PPL bypass. This tool does not touch RunAsPPL protection on lsass.exe; that is a separate, unrelated mechanism.

---

Disclaimer

This tool is provided strictly for authorized security testing, red-team engagements, CTF environments, and personal lab research.

Using it against systems without explicit written permission is illegal and unethical. The author assumes no responsibility for misuse.

---

Made by @Vulndisclosure

```
