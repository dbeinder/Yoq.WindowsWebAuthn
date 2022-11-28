using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawCredentialDetails
    {
        // Version of this structure, to allow for modifications in the future.
        protected int StructVersion = 1;

        // Size of pbCredentialID.
        public int CredentialIdBytes;
        IntPtr CredentialId;

        // RP Info
        IntPtr RpInformation;

        // User Info
        IntPtr UserInformation;

        // Removable or not.
        public bool IsRemovable;

        public CredentialDetails MarshalToPublic()
        {
            var rpInfo = Marshal.PtrToStructure<RelayingPartyInfo>(RpInformation);
            var rawUserInfo = Marshal.PtrToStructure<RawUserInfo>(UserInformation);
            var userInfo = rawUserInfo.MarshalToPublic();

            var cid = new byte[CredentialIdBytes];
            if (CredentialIdBytes > 0) Marshal.Copy(CredentialId, cid, 0, CredentialIdBytes);
            return new CredentialDetails { CredentialId = cid, RelayingParty = rpInfo, User = userInfo };
        }
    }

    public class CredentialDetails
    {
        public byte[] CredentialId;

        public RelayingPartyInfo RelayingParty;
        public UserInfo User;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawCredentialDetailsList
    {
        public int Count;
        public IntPtr Credentials;

        public List<CredentialDetails> MarshalToPublic() => Enumerable.Range(0, Count)
                .Select(n => Marshal.PtrToStructure<RawCredentialDetails>(Marshal.ReadIntPtr(Credentials, IntPtr.Size * n)).MarshalToPublic())
                .ToList();
    }
}
