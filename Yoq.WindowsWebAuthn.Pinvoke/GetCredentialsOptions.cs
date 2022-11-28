using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawGetCredentialsOptions
    {
        // Version of this structure, to allow for modifications in the future.
        protected int StructVersion = 1;

        // Optional.
        public string RelayingPartyId;

        // Optional. BrowserInPrivate Mode. Defaulting to FALSE.
        public bool BrowserInPrivateMode;

        public RawGetCredentialsOptions() { }
        public RawGetCredentialsOptions(string rpId, bool privateMode)
        {
            RelayingPartyId = rpId;
            BrowserInPrivateMode = privateMode;
        }
    }
}
