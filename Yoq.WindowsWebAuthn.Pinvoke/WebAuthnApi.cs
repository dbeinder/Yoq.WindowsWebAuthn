using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke
{
    /* API changes since V1:
            V2:
                added credProtect extension

            V3:
                added minPinLength extension
                added credBlob extension
                RawAuthenticatorMakeCredentialOptions   StructVersion 4
                AuthenticatorGetAssertionOptions        StructVersion 5
                CredentialAttestation                   StructVersion 4
                Assertion                               StructVersion 2

            V4: [WIP, DLL not seen yet]
                RawAuthenticatorMakeCredentialOptions   StructVersion 5
                AuthenticatorGetAssertionOptions        StructVersion 6
                Assertion                               StructVersion 3
                new APIs:
                    WebAuthNGetPlatformCredentialList
                    WebAuthNFreePlatformCredentialList
                    WebAuthNDeletePlatformCredential
     */
    public static class WebAuthnApi
    {
        public static bool CheckApiAvailable()
        {
            var getApiVersionMethod = typeof(WebAuthnApi).GetMethod(nameof(RawGetApiVersionNumber), BindingFlags.Public | BindingFlags.Static);
            try { Marshal.Prelink(getApiVersionMethod); }
            catch { return false; }
            return true;
        }

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetApiVersionNumber", CharSet = CharSet.Unicode)]
        public static extern int RawGetApiVersionNumber();


        private static int? _apiVersion;
        public static int ApiVersion => _apiVersion ?? (_apiVersion = RawGetApiVersionNumber()).Value;


        [DllImport("webauthn.dll", EntryPoint = "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable", CharSet = CharSet.Unicode)]
        public static extern WebAuthnHResult IsUserVerifyingPlatformAuthenticatorAvailable(
            out bool isUserVerifyingPlatformAuthenticatorAvailable);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetErrorName", CharSet = CharSet.Unicode)]
        private static extern IntPtr RawGetErrorName(WebAuthnHResult result);

        public static string GetErrorName(WebAuthnHResult result) => Marshal.PtrToStringUni(RawGetErrorName(result));

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetCancellationId")]
        public static extern WebAuthnHResult GetCancellationId([Out] out Guid cancellationId);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNCancelCurrentOperation")]
        public static extern WebAuthnHResult CancelCurrentOperation([In, MarshalAs(UnmanagedType.LPStruct)]
            Guid cancellationId);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNFreeCredentialAttestation")]
        private static extern void FreeRawCredentialAttestation(IntPtr rawCredentialAttestation);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNFreeAssertion")]
        private static extern void FreeRawAssertion(IntPtr rawAssertion);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNAuthenticatorMakeCredential", CharSet = CharSet.Unicode)]
        private static extern WebAuthnHResult RawAuthenticatorMakeCredential(
            [In] IntPtr windowHandle,
            [In] RelayingPartyInfo rpInfo,
            [In] RawUserInfo rawUserInfo,
            [In] RawCoseCredentialParameters rawCoseCredParams,
            [In] RawClientData rawClientData,
            [In, Optional] RawAuthenticatorMakeCredentialOptions rawMakeCredentialOptions,
            [Out] out IntPtr rawCredentialAttestation);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNAuthenticatorGetAssertion", CharSet = CharSet.Unicode)]
        private static extern WebAuthnHResult RawAuthenticatorGetAssertion(
            [In] IntPtr hWnd,
            [In, Optional] string rpId,
            [In] RawClientData rawClientData,
            [In, Optional] RawAuthenticatorGetAssertionOptions rawGetAssertionOptions,
            [Out] out IntPtr rawAssertionPtr);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetPlatformCredentialList", CharSet = CharSet.Unicode)]
        private static extern WebAuthnHResult GetRawPlatformCredentialList(
            [In] RawGetCredentialsOptions getCredOptions,
            [Out] out IntPtr credDetailsListPtr);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNFreePlatformCredentialList", CharSet = CharSet.Unicode)]
        private static extern WebAuthnHResult FreeRawPlatformCredentialList([In] IntPtr credDetailsListPtr);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNDeletePlatformCredential", CharSet = CharSet.Unicode)]
        private static extern WebAuthnHResult RawDeletePlatformCredential([In] int credIdLen, [In] IntPtr credId);

        public static WebAuthnHResult AuthenticatorMakeCredential(IntPtr window,
            RelayingPartyInfo rp,
            UserInfo user,
            ICollection<CoseCredentialParameter> coseParams,
            ClientData clientData,
            AuthenticatorMakeCredentialOptions makeOptions,
            out CredentialAttestation credential)
        {
            credential = null;

            var rawUser = new RawUserInfoOut(user);
            var rawCredList = new RawCoseCredentialParameters(coseParams);
            var rawClientData = new RawClientData(clientData);
            var rawMakeCredOptions = makeOptions == null
                ? null
                : new RawAuthenticatorMakeCredentialOptions(makeOptions);

            var res = RawAuthenticatorMakeCredential(window, rp, rawUser, rawCredList, rawClientData,
                rawMakeCredOptions, out var rawCredPtr);

            if (rawCredPtr != IntPtr.Zero)
            {
                var rawCredObj = Marshal.PtrToStructure<RawCredentialAttestation>(rawCredPtr);
                credential = rawCredObj?.MarshalToPublic();
                FreeRawCredentialAttestation(rawCredPtr);
            }

            rawUser.Dispose();
            rawCredList.Dispose();
            rawClientData.Dispose();
            rawMakeCredOptions?.Dispose();

            return res;
        }

        public static WebAuthnHResult AuthenticatorGetAssertion(
            IntPtr window,
            string rpId,
            ClientData clientData,
            AuthenticatorGetAssertionOptions getOptions,
            out Assertion assertion)
        {
            assertion = null;

            var rawClientData = new RawClientData(clientData);
            var rawGetOptions = getOptions == null
                ? null
                : new RawAuthenticatorGetAssertionOptions(getOptions);

            var res = RawAuthenticatorGetAssertion(window, rpId, rawClientData, rawGetOptions, out var rawAsnPtr);

            if (rawAsnPtr != IntPtr.Zero)
            {
                var rawAssertion = Marshal.PtrToStructure<RawAssertion>(rawAsnPtr);
                assertion = rawAssertion?.MarshalToPublic();
                FreeRawAssertion(rawAsnPtr);
            }

            rawClientData.Dispose();
            rawGetOptions?.Dispose();

            return res;
        }

        public static WebAuthnHResult GetPlatformCredentialList(
            out List<CredentialDetails> credentials,
            string rpId = null,
            bool isPrivateWindow = false)
        {
            var opts = new RawGetCredentialsOptions { BrowserInPrivateMode = isPrivateWindow, RelayingPartyId = rpId };
            var res = GetRawPlatformCredentialList(opts, out var credListPtr);

            if (res == WebAuthnHResult.NteNotFound)
            {
                credentials = new List<CredentialDetails>();
                return WebAuthnHResult.Ok;
            }

            credentials = null;
            if (credListPtr != IntPtr.Zero)
            {
                var rawList = Marshal.PtrToStructure<RawCredentialDetailsList>(credListPtr);
                credentials = rawList.MarshalToPublic();
                FreeRawPlatformCredentialList(credListPtr);
            }

            return res;
        }

        public static WebAuthnHResult DeletePlatformCredential(byte[] credentialId)
        {
            var credIdRaw = Marshal.AllocHGlobal(credentialId.Length);
            Marshal.Copy(credentialId, 0, credIdRaw, credentialId.Length);
            var res = RawDeletePlatformCredential(credentialId.Length, credIdRaw);
            Marshal.FreeHGlobal(credIdRaw);
            return res;
        }
    }
}
