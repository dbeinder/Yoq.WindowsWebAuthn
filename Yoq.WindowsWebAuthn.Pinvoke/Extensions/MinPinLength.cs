using System;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke.Extensions
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class MinPinLengthBoolData : RawWebAuthnExtensionData
    {
        public bool Bool;
    }

    public class MinPinLengthCreationExtension : WebAuthnCreationExtensionInput
    {
        public override ExtensionType Type => ExtensionType.MinPinLength;
        internal override RawWebAuthnExtensionData GetExtensionData() => new MinPinLengthBoolData { Bool = true };
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class MinPinLengthQueryData : RawWebAuthnExtensionData
    {
        public int MinPinLength;
    }

    public class MinPinLengthQueryResultExtension : WebAuthnCreationExtensionOutput
    {
        public override ExtensionType Type => ExtensionType.MinPinLength;
        public int MinPinLength;
        static MinPinLengthQueryResultExtension() => Register(ExtensionType.MinPinLength, r =>
        {
            var value = -1;
            if (r.ExtensionDataBytes > 0)
                value = Marshal.PtrToStructure<MinPinLengthQueryData>(r.ExtensionData).MinPinLength;
            return new MinPinLengthQueryResultExtension { MinPinLength = value };
        });
    }

    // MakeCredential Input Type:   BOOL.
    //      - pvExtension must point to a BOOL with the value TRUE to request the minPinLength.
    //      - cbExtension must contain the sizeof(BOOL).
    // MakeCredential Output Type:  DWORD.
    //      - pvExtension will point to a DWORD with the minimum pin length if returned by the authenticator
    //      - cbExtension will contain the sizeof(DWORD).
    // GetAssertion Input Type:     Not Supported
    // GetAssertion Output Type:    Not Supported
}
