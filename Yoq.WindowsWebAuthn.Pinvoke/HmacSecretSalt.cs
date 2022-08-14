using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Yoq.WindowsWebAuthn.Pinvoke
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawHmacSecretSalt
    {
        int FirstSize;
        IntPtr First;
        int SecondSize;
        IntPtr Second;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawCredWithHmacSecretSalt
    {
        int CredIdSize;
        IntPtr CredId;
        IntPtr HmacSecretSaltRaw;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawHmacSecretSaltValues
    {
        int ListCount;
        IntPtr ListEntries;
    }
}
