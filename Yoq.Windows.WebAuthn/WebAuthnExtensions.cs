using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Yoq.Windows.WebAuthn
{
    //TODO: unfinished, GetAssertion API does not support extensions yet

    ////+------------------------------------------------------------------------------------------
    //// Hmac-Secret extension
    ////-------------------------------------------------------------------------------------------

    //#define WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET                  L"hmac-secret"
    //// Below type definitions is for WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET
    //// MakeCredential Input Type:   BOOL.
    ////      - pvExtension must point to a BOOL with the value TRUE.
    ////      - cbExtension must contain the sizeof(BOOL).
    //// MakeCredential Output Type:  BOOL.
    ////      - pvExtension will point to a BOOL with the value TRUE if credential
    ////        was successfully created with HMAC_SECRET.
    ////      - cbExtension will contain the sizeof(BOOL).
    //// GetAssertion Input Type:     Not Supported
    //// GetAssertion Output Type:    Not Supported

    ////+------------------------------------------------------------------------------------------
    ////  credProtect  extension
    ////-------------------------------------------------------------------------------------------

    public enum UserVerification : int
    {
        Any = 0,
        Optional = 1,
        OptionalWithCredentialIdList = 2,
        Required = 3
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class CredProtectExtensionIn
    {
        // One of the above WEBAUTHN_USER_VERIFICATION_* values
        public UserVerification Type;

        // Set the following to TRUE to require authenticator support for the credProtect extension
        public bool RequireCredProtect;
    }


    //#define WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT                 L"credProtect"
    //// Below type definitions is for WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT
    //// MakeCredential Input Type:   WEBAUTHN_CRED_PROTECT_EXTENSION_IN.
    ////      - pvExtension must point to a WEBAUTHN_CRED_PROTECT_EXTENSION_IN struct
    ////      - cbExtension will contain the sizeof(WEBAUTHN_CRED_PROTECT_EXTENSION_IN).
    //// MakeCredential Output Type:  DWORD.
    ////      - pvExtension will point to a DWORD with one of the above WEBAUTHN_USER_VERIFICATION_* values
    ////        if credential was successfully created with CRED_PROTECT.
    ////      - cbExtension will contain the sizeof(DWORD).
    //// GetAssertion Input Type:     Not Supported
    //// GetAssertion Output Type:    Not Supported


    // Information about Extensions.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawWebauthnExtension
    {
        public string ExtensionIdentifier;
        public int ExtensionDataBytes;
        public IntPtr ExtensionData;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawWebauthnExtensions
    {
        public int Count;
        public IntPtr Extensions;
    }

    public class WebAuthnExtension
    {
        public ExtensionType ExtensionTypeIdentifier;
        //TODO: derive class for each extension
    }
}
