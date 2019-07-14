using System;
using System.Runtime.InteropServices;

namespace Yoq.Windows.WebAuthn
{
    // authenticatorGetAssertion output.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawAssertion
    {
        // Version of this structure, to allow for modifications in the future.
        protected int StructVersion;

        // Size of cbAuthenticatorData.
        public int AuthenticatorDataBytes;

        // Authenticator data that was created for this assertion.
        public IntPtr AuthenticatorData;

        // Size of pbSignature.
        public int SignatureBytes;

        // Signature that was generated for this assertion.
        public IntPtr Signature;

        // Credential that was used for this assertion.
        public RawCredential Credential;

        // Size of User Id
        public int UserIdBytes;

        // UserId
        public IntPtr UserId;

        public Assertion MarshalToPublic()
        {
            var authData = new byte[AuthenticatorDataBytes];
            if (AuthenticatorDataBytes > 0) Marshal.Copy(AuthenticatorData, authData, 0, AuthenticatorDataBytes);

            var sig = new byte[SignatureBytes];
            if (SignatureBytes > 0) Marshal.Copy(Signature, sig, 0, SignatureBytes);

            var uid = new byte[UserIdBytes];
            if (UserIdBytes > 0) Marshal.Copy(UserId, uid, 0, UserIdBytes);

            var cred = Credential.MarshalToPublic();

            return new Assertion
            {
                AuthenticatorData = authData,
                Signature = sig,
                UserId = UserIdBytes == 0 ? null : uid,
                Credential = cred
            };
        }
    }

    public class Assertion
    {
        // Authenticator data that was created for this assertion.
        public byte[] AuthenticatorData;

        // Signature that was generated for this assertion.
        public byte[] Signature;

        // Credential that was used for this assertion.
        public Credential Credential;

        // UserId
        public byte[] UserId;

        // set to TRUE if the above U2fAppId from GetAssertionOptions was used instead of rpId
        public bool U2fAppIdUsed;
    }
}