using System.Runtime.InteropServices;

namespace Yoq.Windows.WebAuthn
{
    // Information about an RP Entity
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class RelayingPartyInfo
    {
        // Version of this structure, to allow for modifications in the future.
        // This field is required and should be set to CURRENT_VERSION above.
        protected int StructVersion = 1;

        // Identifier for the RP. This field is required.
        public string Id;

        // Contains the friendly name of the Relying Party, such as "Acme Corporation", "Widgets Inc" or "Awesome Site".
        // This field is required.
        public string Name;

        // Optional URL pointing to RP's logo. 
        public string IconUrl;
    }
}
