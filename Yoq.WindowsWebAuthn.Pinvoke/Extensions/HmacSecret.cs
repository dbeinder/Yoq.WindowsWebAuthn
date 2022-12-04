using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke.Extensions
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class HmacSecretBoolData : RawWebAuthnExtensionData
    {
        public bool Bool;
    }

    public class HmacSecretCreationExtension : WebAuthnCreationExtensionInput
    {
        public override ExtensionType Type => ExtensionType.HmacSecret;
        internal override RawWebAuthnExtensionData GetExtensionData() => new HmacSecretBoolData { Bool = true };
    }

    public class HmacSecretResultExtension : WebAuthnCreationExtensionOutput
    {
        public override ExtensionType Type => ExtensionType.HmacSecret;
        public bool Success;
        static HmacSecretResultExtension() => Register(ExtensionType.HmacSecret, r =>
        {
            var success = false;
            if (r.ExtensionDataBytes > 0)
                success = Marshal.PtrToStructure<HmacSecretBoolData>(r.ExtensionData).Bool;
            return new HmacSecretResultExtension { Success = success };
        });
    }


    public class PrfSalt
    {
        public byte[] First, Second;
    }

    public class HmacSecretAssertionExtension : WebAuthnAssertionExtensionInput
    {
        public bool UseRawSalts = false;
        public PrfSalt GlobalSalt;
        public Dictionary<byte[], PrfSalt> SaltsByCredential;
        public override ExtensionType Type => ExtensionType.HmacSecret;
        internal override RawWebAuthnExtensionData GetExtensionData() => new HmacSecretBoolData { Bool = true };
    }

    public class HmacSecretAssertionResultExtension : WebAuthnAssertionExtensionOutput
    {
        public override ExtensionType Type => ExtensionType.HmacSecret;
        public byte[] First, Second;
    }

    //// MakeCredential Input Type:   BOOL.
    ////      - pvExtension must point to a BOOL with the value TRUE.
    ////      - cbExtension must contain the sizeof(BOOL).
    //// MakeCredential Output Type:  BOOL.
    ////      - pvExtension will point to a BOOL with the value TRUE if credential
    ////        was successfully created with HMAC_SECRET.
    ////      - cbExtension will contain the sizeof(BOOL).
    //// GetAssertion Input Type:     Not Supported
    //// GetAssertion Output Type:    Not Supported
}
