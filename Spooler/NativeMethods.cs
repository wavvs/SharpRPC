//
// Copyright (c) Ping Castle. All rights reserved.
// https://www.pingcastle.com
//
// Licensed under the Non-Profit OSL. See LICENSE file in the project root for full license information.
//
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading;
using System.Text;

namespace Spooler
{
    internal class NativeMethods
    {
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW",
            CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
           CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr Handle);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
           CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PolicyHandle, UInt32 InformationClass, out IntPtr IntPtrPolicyInformation);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
           CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr intptrServer, out IntPtr ServerHandle, UInt32 DesiredAccess);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
           CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr ServerHandle, ref IntPtr EnumerationContext, out IntPtr IntptrBuffer, UInt32 PreferedMaximumLength, out UInt32 CountReturned);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
           CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr ServerHandle, Int32 DesiredAccess, byte[] sid, out IntPtr DomainHandle);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
           CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr DomainHandle, ref IntPtr EnumerationContext, Int32 UserAccountControl, out IntPtr IntptrBuffer, Int32 PreferedMaximumLength, ref UInt32 CountReturned);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, string pPrinterName, out IntPtr pHandle, string pDatatype, ref rprn.DEVMODE_CONTAINER pDevModeContainer, int AccessRequired);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, IntPtr hPrinter, uint fdwFlags, uint fdwOptions, string pszLocalMachine, uint dwPrinterLocal, IntPtr intPtr3);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingFree(ref IntPtr lpString);

        //#region RpcStringBindingCompose

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcStringBindingCompose(
            String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options,
            out IntPtr lpBindingString
            );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct SEC_WINNT_AUTH_IDENTITY
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string User;
            public int UserLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Domain;
            public int DomainLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Password;
            public int PasswordLength;
            public int Flags;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_SECURITY_QOS
        {
            public Int32 Version;
            public Int32 Capabilities;
            public Int32 IdentityTracking;
            public Int32 ImpersonationType;
        };

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingSetAuthInfo(IntPtr Binding, String ServerPrincName,
                                                             UInt32 AuthnLevel, UInt32 AuthnSvc,
                                                             IntPtr identity,
                                                             uint AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoExW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, ref SEC_WINNT_AUTH_IDENTITY AuthIdentity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, ref SEC_WINNT_AUTH_IDENTITY AuthIdentity, UInt32 AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, UIntPtr pointer, UInt32 AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        internal static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, UInt32 OptionValue);

        [DllImport("Rpcrt4.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern Int32 RpcEpResolveBinding(IntPtr Binding, IntPtr RpcClientInterface);

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            public uint LowPart;
            public uint HighPart;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
            IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint GetSystemDirectory([Out] StringBuilder lpBuffer, uint uSize);

        [DllImport("userenv.dll", SetLastError = true)]
        internal static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags,
            string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr
            lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out
            PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool RevertToSelf();
    }
}
