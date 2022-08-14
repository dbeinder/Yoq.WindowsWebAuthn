using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawAuthenticatorGetAssertionOptions
    {
        // Version of this structure, to allow for modifications in the future.
        protected int StructVersion = 5;

        // Time that the operation is expected to complete within.
        // This is used as guidance, and can be overridden by the platform.
        public int TimeoutMilliseconds;

        // Allowed Credentials List.
        public RawCredentialsList AllowCredentialsList;

        // Optional extensions to parse when performing the operation.
        public RawWebAuthnExtensionsOut Extensions;

        // Optional. Platform vs Cross-Platform Authenticators.
        public AuthenticatorAttachment AuthenticatorAttachment;

        // User Verification Requirement.
        public UserVerificationRequirement UserVerificationRequirement;

        // Reserved for future Use
        protected int ReservedFlags = 0;

        // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2

        // Optional identifier for the U2F AppId. Converted to UTF8 before being hashed. Not lower cased.
        public string U2fAppId;

        // If the following is non-NULL, then, set to TRUE if the above pwszU2fAppid was used instead of
        // PCWSTR pwszRpId;
        internal IntPtr U2fAppIdUsedBoolPtr; //*bool

        // Cancellation Id - Optional - See WebAuthNGetCancellationId
        internal IntPtr CancellationId; //*Guid

        // @@ WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4 (API v1)

        // Allow Credential List. If present, "CredentialList" will be ignored.
        internal IntPtr AllowCredentialsExListPtr; //*WEBAUTHN_CREDENTIAL_LIST

        // @@ WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_5 (API v3)

        internal LargeBlobOperation CredLargeBlobOperation;
        internal int CredLargeBlobBytes;
        internal IntPtr CredLargeBlob;

        // @@ WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6 (API v4)

        // PRF values which will be converted into HMAC-SECRET values according to WebAuthn Spec.
        //internal IntPtr HmacSecretSaltValues;

        // Optional. BrowserInPrivate Mode. Defaulting to FALSE.
        //internal bool BrowserInPrivateMode;

        // ------------ ignored ------------
        private readonly RawCredentialExList _allowedCredentialsExList;
        private readonly RawWebAuthnExtensionOut[] _rawExtensions;
        private readonly RawWebAuthnExtensionData[] _rawExtensionData;

        public RawAuthenticatorGetAssertionOptions() { }
        public RawAuthenticatorGetAssertionOptions(AuthenticatorGetAssertionOptions getOptions)
        {
            AllowCredentialsList = new RawCredentialsList(getOptions.AllowedCredentials);

            if (getOptions.AllowedCredentialsEx?.Count > 0)
            {
                _allowedCredentialsExList = new RawCredentialExList(getOptions.AllowedCredentialsEx);
                AllowCredentialsExListPtr = Marshal.AllocHGlobal(Marshal.SizeOf<RawCredentialExList>());
                Marshal.StructureToPtr(_allowedCredentialsExList, AllowCredentialsExListPtr, false);
            }

            CancellationId = IntPtr.Zero;
            if (getOptions.CancellationId.HasValue)
            {
                CancellationId = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
                Marshal.StructureToPtr(getOptions.CancellationId.Value, CancellationId, false);
            }

            U2fAppId = getOptions.U2fAppId;
            U2fAppIdUsedBoolPtr = getOptions.U2fAppId == null ? StaticBoolFalse : StaticBoolTrue;

            TimeoutMilliseconds = getOptions.TimeoutMilliseconds;
            AuthenticatorAttachment = getOptions.AuthenticatorAttachment;
            UserVerificationRequirement = getOptions.UserVerificationRequirement;

            var ex = getOptions.Extensions?.Select(e => new { e.Type, Data = e.GetExtensionData() }).ToList();
            _rawExtensionData = ex?.Select(e => e.Data).ToArray();
            _rawExtensions = ex?.Select(e => new RawWebAuthnExtensionOut(e.Type, e.Data)).ToArray();
            Extensions = new RawWebAuthnExtensionsOut(_rawExtensions);

            CredLargeBlobOperation = getOptions.LargeBlobOperation;
            if (getOptions.LargeBlob != null)
            {
                CredLargeBlobBytes = getOptions.LargeBlob.Length;
                CredLargeBlob = Marshal.AllocHGlobal(CredLargeBlobBytes);
                Marshal.Copy(getOptions.LargeBlob, 0, CredLargeBlob, CredLargeBlobBytes);
            }
        }

        ~RawAuthenticatorGetAssertionOptions() => FreeMemory();

        protected void FreeMemory()
        {
            AllowCredentialsList.Dispose();
            _allowedCredentialsExList?.Dispose();
            if (_rawExtensions != null) foreach (var ext in _rawExtensions) ext.Dispose();
            if (_rawExtensionData != null) foreach (var ext in _rawExtensionData) ext.Dispose();

            Helper.SafeFreeHGlobal(ref AllowCredentialsExListPtr);
            Helper.SafeFreeHGlobal(ref CancellationId);
            Helper.SafeFreeHGlobal(ref CredLargeBlob);
        }

        public void Dispose()
        {
            FreeMemory();
            GC.SuppressFinalize(this);
        }

        static readonly IntPtr StaticBoolTrue, StaticBoolFalse;
        static RawAuthenticatorGetAssertionOptions()
        {
            StaticBoolTrue = Marshal.AllocHGlobal(Marshal.SizeOf<bool>());
            Marshal.StructureToPtr(true, StaticBoolTrue, false);
            StaticBoolFalse = Marshal.AllocHGlobal(Marshal.SizeOf<bool>());
            Marshal.StructureToPtr(false, StaticBoolTrue, false);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class AuthenticatorGetAssertionOptions
    {
        // Time that the operation is expected to complete within.
        // This is used as guidance, and can be overridden by the platform.
        public int TimeoutMilliseconds = 30000;

        // Allowed Credentials List.
        public ICollection<Credential> AllowedCredentials;

        // Allowed CredentialsEx List. If present, "AllowedCredentials" will be ignored.
        public ICollection<CredentialEx> AllowedCredentialsEx;

        // Optional extensions to parse when performing the operation.
        public IReadOnlyCollection<WebAuthnAssertionExtensionInput> Extensions;

        // Optional. Platform vs Cross-Platform Authenticators.
        public AuthenticatorAttachment AuthenticatorAttachment;

        // User Verification Requirement.
        public UserVerificationRequirement UserVerificationRequirement;

        // Optional identifier for the U2F AppId. Converted to UTF8 before being hashed. Not lower cased.
        public string U2fAppId;

        // Cancellation Id - Optional - See WebAuthNGetCancellationId
        public Guid? CancellationId;

        public LargeBlobOperation LargeBlobOperation;
        public byte[] LargeBlob;
    }
}
