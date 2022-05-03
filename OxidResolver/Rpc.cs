﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

// Source Executable: c:\windows\system32\rpcss.dll
// Interface ID: 99fcfec4-5260-101b-bbcb-00aa0021347a
// Interface Version: 0.0
// Client Generated: 02.05.2022 20:55:10
// NtApiDotNet Version: 1.1.33

namespace OxidResolver
{

    #region Marshal Helpers
    internal class _Marshal_Helper : NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer
    {
        public void Write_0(Struct_0 p0)
        {
            WriteStruct<Struct_0>(p0);
        }
        public void Write_1(Struct_2 p0)
        {
            WriteStruct<Struct_2>(p0);
        }
        public void Write_2(short[] p0, long p1)
        {
            WriteConformantArray<short>(p0, p1);
        }
        public void Write_3(short[] p0, long p1)
        {
            WriteConformantArray<short>(p0, p1);
        }
        public void Write_4(long[] p0, long p1)
        {
            WriteConformantArray<long>(p0, p1);
        }
        public void Write_5(long[] p0, long p1)
        {
            WriteConformantArray<long>(p0, p1);
        }
    }
    internal class _Unmarshal_Helper : NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer
    {
        public _Unmarshal_Helper(NtApiDotNet.Win32.Rpc.RpcClientResponse r) :
                base(r.NdrBuffer, r.Handles, r.DataRepresentation)
        {
        }
        public _Unmarshal_Helper(byte[] ba) :
                base(ba)
        {
        }
        public Struct_0 Read_0()
        {
            return ReadStruct<Struct_0>();
        }
        public Struct_2 Read_1()
        {
            return ReadStruct<Struct_2>();
        }
        public short[] Read_2()
        {
            return ReadConformantArray<short>();
        }
        public short[] Read_3()
        {
            return ReadConformantArray<short>();
        }
        public long[] Read_4()
        {
            return ReadConformantArray<long>();
        }
        public long[] Read_5()
        {
            return ReadConformantArray<long>();
        }
    }
    #endregion
    #region Complex Types
    public struct Struct_0 : NtApiDotNet.Ndr.Marshal.INdrConformantStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt16(Member0);
            m.WriteInt16(Member2);
            m.Write_2(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(Member4, "Member4"), Member0);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt16();
            Member2 = u.ReadInt16();
            Member4 = u.Read_2();
        }
        int NtApiDotNet.Ndr.Marshal.INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 2;
        }
        public short Member0;
        public short Member2;
        public short[] Member4;
        public static Struct_0 CreateDefault()
        {
            Struct_0 ret = new Struct_0();
            ret.Member4 = new short[0];
            return ret;
        }
        public Struct_0(short Member0, short Member2, short[] Member4)
        {
            this.Member0 = Member0;
            this.Member2 = Member2;
            this.Member4 = Member4;
        }
    }
    public struct Struct_2 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt16(Member0);
            m.WriteInt16(Member2);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt16();
            Member2 = u.ReadInt16();
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 2;
        }
        public short Member0;
        public short Member2;
        public static Struct_2 CreateDefault()
        {
            return new Struct_2();
        }
        public Struct_2(short Member0, short Member2)
        {
            this.Member0 = Member0;
            this.Member2 = Member2;
        }
    }
    #endregion
    #region Client Implementation
    public sealed class IObjectExporter : NtApiDotNet.Win32.Rpc.RpcClientBase
    {
        public IObjectExporter() :
                base("99fcfec4-5260-101b-bbcb-00aa0021347a", 0, 0)
        {
        }
        private _Unmarshal_Helper SendReceive(int p, _Marshal_Helper m)
        {
            return new _Unmarshal_Helper(SendReceive(p, m.DataRepresentation, m.ToArray(), m.Handles));
        }
        public uint ResolveOxid(long p0, short p1, short[] p2, out System.Nullable<Struct_0> p3, out System.Guid p4, out int p5)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteInt64(p0);
            m.WriteInt16(p1);
            m.Write_3(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p2, "p2"), p1);
            _Unmarshal_Helper u = SendReceive(0, m);
            p3 = u.ReadReferentValue<Struct_0>(new System.Func<Struct_0>(u.Read_0), false);
            p4 = u.ReadGuid();
            p5 = u.ReadInt32();
            return u.ReadUInt32();
        }
        public uint SimplePing(long p0)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteInt64(p0);
            _Unmarshal_Helper u = SendReceive(1, m);
            return u.ReadUInt32();
        }
        public uint ComplexPing(ref long p0, short p1, short p2, short p3, long[] p4, long[] p5, out short p6)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteInt64(p0);
            m.WriteInt16(p1);
            m.WriteInt16(p2);
            m.WriteInt16(p3);
            m.WriteReferent(p4, new System.Action<long[], long>(m.Write_4), p2);
            m.WriteReferent(p5, new System.Action<long[], long>(m.Write_5), p3);
            _Unmarshal_Helper u = SendReceive(2, m);
            p0 = u.ReadInt64();
            p6 = u.ReadInt16();
            return u.ReadUInt32();
        }
        // async
        public uint ServerAlive()
        {
            _Marshal_Helper m = new _Marshal_Helper();
            _Unmarshal_Helper u = SendReceive(3, m);
            return u.ReadUInt32();
        }
        public uint ResolveOxid2(long p0, short p1, short[] p2, out System.Nullable<Struct_0> p3, out System.Guid p4, out int p5, out Struct_2 p6)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteInt64(p0);
            m.WriteInt16(p1);
            m.Write_3(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p2, "p2"), p1);
            _Unmarshal_Helper u = SendReceive(4, m);
            p3 = u.ReadReferentValue<Struct_0>(new System.Func<Struct_0>(u.Read_0), false);
            p4 = u.ReadGuid();
            p5 = u.ReadInt32();
            p6 = u.Read_1();
            return u.ReadUInt32();
        }
        // async
        public uint ServerAlive2(out Struct_2 p0, out System.Nullable<Struct_0> p1, out int p2)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            _Unmarshal_Helper u = SendReceive(5, m);
            p0 = u.Read_1();
            p1 = u.ReadReferentValue<Struct_0>(new System.Func<Struct_0>(u.Read_0), false);
            p2 = u.ReadInt32();
            return u.ReadUInt32();
        }
    }
    #endregion
}

