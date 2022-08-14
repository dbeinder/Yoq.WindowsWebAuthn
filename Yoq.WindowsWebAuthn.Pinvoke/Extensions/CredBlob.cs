using System;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke.Extensions
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawCredBlob : RawWebAuthnExtensionData
    {
        public int CredBlobBytes;
        public IntPtr CredBlob;
        public RawCredBlob(byte[] blob)
        {
            if (blob == null) return;
            CredBlobBytes = blob.Length;
            CredBlob = Marshal.AllocHGlobal(CredBlobBytes);
            Marshal.Copy(blob, 0, CredBlob, CredBlobBytes);
        }

        ~RawCredBlob() => FreeMemory();
        protected void FreeMemory()
        {
            if (CredBlob != IntPtr.Zero) return;
            Helper.SafeFreeHGlobal(ref CredBlob);
        }
        public override void Dispose()
        {
            FreeMemory();
            GC.SuppressFinalize(this);
        }
    }

    public class CredBlobCreationExtension : WebAuthnCreationExtensionInput
    {
        public override ExtensionType Type => ExtensionType.CredBlob;
        public byte[] CredBlob;
        public CredBlobCreationExtension(byte[] credBlob) => CredBlob = credBlob;
        internal override RawWebAuthnExtensionData GetExtensionData() => new RawCredBlob(CredBlob);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawCredBlobBoolData : RawWebAuthnExtensionData
    {
        public bool Bool;
    }

    public class CredBlobCreationSuccessExtension : WebAuthnCreationExtensionOutput
    {
        public override ExtensionType Type => ExtensionType.CredBlob;
        public bool Success;
        static CredBlobCreationSuccessExtension() => Register(ExtensionType.CredBlob, r =>
        {
            var success = false;
            if (r.ExtensionDataBytes > 0)
                success = Marshal.PtrToStructure<RawCredBlobBoolData>(r.ExtensionData).Bool;
            return new CredBlobCreationSuccessExtension { Success = success };
        });
    }

    public class CredBlobRequestExtension : WebAuthnAssertionExtensionInput
    {
        public override ExtensionType Type => ExtensionType.CredBlob;
        internal override RawWebAuthnExtensionData GetExtensionData() => new RawCredBlobBoolData() { Bool = true };
    }
    public class CredBlobRequestResultExtension : WebAuthnAssertionExtensionOutput
    {
        public override ExtensionType Type => ExtensionType.CredBlob;
        public byte[] CredBlob;

        static CredBlobRequestResultExtension() => Register(ExtensionType.CredBlob, r =>
        {
            byte[] blob = null;
            if (r.ExtensionDataBytes > 0)
            {
                var rawBlob = Marshal.PtrToStructure<RawCredBlob>(r.ExtensionData);
                if (rawBlob.CredBlobBytes > 0 && rawBlob.CredBlob != IntPtr.Zero)
                    Marshal.Copy(rawBlob.CredBlob, blob, 0, rawBlob.CredBlobBytes);
            }
            return new CredBlobRequestResultExtension { CredBlob = blob };
        });
    }

    // MakeCredential Input Type:   WEBAUTHN_CRED_BLOB_EXTENSION.
    //      - pvExtension must point to a WEBAUTHN_CRED_BLOB_EXTENSION struct
    //      - cbExtension must contain the sizeof(WEBAUTHN_CRED_BLOB_EXTENSION).
    // MakeCredential Output Type:  BOOL.
    //      - pvExtension will point to a BOOL with the value TRUE if credBlob was successfully created
    //      - cbExtension will contain the sizeof(BOOL).
    // GetAssertion Input Type:     BOOL.
    //      - pvExtension must point to a BOOL with the value TRUE to request the credBlob.
    //      - cbExtension must contain the sizeof(BOOL).
    // GetAssertion Output Type:    WEBAUTHN_CRED_BLOB_EXTENSION.
    //      - pvExtension will point to a WEBAUTHN_CRED_BLOB_EXTENSION struct if the authenticator
    //        returns the credBlob in the signed extensions
    //      - cbExtension will contain the sizeof(WEBAUTHN_CRED_BLOB_EXTENSION).
}
