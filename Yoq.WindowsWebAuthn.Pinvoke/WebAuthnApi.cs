using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke
{
    public static class WebAuthnApi
    {
        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetApiVersionNumber", CharSet = CharSet.Unicode)]
        public static extern int GetApiVersionNumber();

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

        public static WebAuthnHResult AuthenticatorMakeCredential(IntPtr window,
            RelayingPartyInfo rp,
            UserInfo user,
            ICollection<CoseCredentialParameter> coseParams,
            ClientData clientData,
            AuthenticatorMakeCredentialOptions makeOptions,
            out CredentialAttestation credential)
        {
            //TODO: extensions
            credential = null;

            var rawUser = new RawUserInfo(user);
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
            //TODO: extensions
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

                if (assertion != null && rawGetOptions != null)
                    assertion.U2fAppIdUsed = rawGetOptions.CheckU2fAppIdUsed();

                FreeRawAssertion(rawAsnPtr);
            }

            rawClientData.Dispose();
            rawGetOptions?.Dispose();

            return res;
        }
    }
}