using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawAuthenticatorGetAssertionOptions
    {
        // Version of this structure, to allow for modifications in the future.
        protected int StructVersion = 4;

        // Time that the operation is expected to complete within.
        // This is used as guidance, and can be overridden by the platform.
        public int TimeoutMilliseconds;

        // Allowed Credentials List.
        public RawCredentialsList AllowCredentialsList;

        // Optional extensions to parse when performing the operation.
        public RawWebauthnExtensions Extensions;

        // Optional. Platform vs Cross-Platform Authenticators.
        public AuthenticatorAttachment AuthenticatorAttachment;

        // User Verification Requirement.
        public UserVerificationRequirement UserVerificationRequirement;

        // Reserved for future Use
        protected int ReservedFlags = 0;

        //
        // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2
        //

        // Optional identifier for the U2F AppId. Converted to UTF8 before being hashed. Not lower cased.
        public string U2fAppId;

        // If the following is non-NULL, then, set to TRUE if the above pwszU2fAppid was used instead of
        // PCWSTR pwszRpId;
        internal IntPtr U2fAppIdUsedBoolPtr; //*bool

        //
        // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3
        //

        // Cancellation Id - Optional - See WebAuthNGetCancellationId
        internal IntPtr CancellationId; //*Guid

        //
        // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4
        //

        // Allow Credential List. If present, "CredentialList" will be ignored.
        internal IntPtr AllowCredentialsExListPtr; //*WEBAUTHN_CREDENTIAL_LIST

        ///-----------------------
        //should not be marshaled / ignored
        private readonly RawCredentialExList _allowedCredentialsExList;

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
            U2fAppIdUsedBoolPtr = Marshal.AllocHGlobal(Marshal.SizeOf<bool>());

            TimeoutMilliseconds = getOptions.TimeoutMilliseconds;
            AuthenticatorAttachment = getOptions.AuthenticatorAttachment;
            UserVerificationRequirement = getOptions.UserVerificationRequirement;

            Extensions = new RawWebauthnExtensions { Count = 0, Extensions = IntPtr.Zero }; //TODO
        }

        public bool CheckU2fAppIdUsed() => U2fAppIdUsedBoolPtr != IntPtr.Zero && Marshal.ReadByte(U2fAppIdUsedBoolPtr) > 0;

        ~RawAuthenticatorGetAssertionOptions() => FreeMemory();

        protected void FreeMemory()
        {
            AllowCredentialsList.Dispose();
            _allowedCredentialsExList?.Dispose();

            Helper.SafeFreeHGlobal(ref AllowCredentialsExListPtr);
            Helper.SafeFreeHGlobal(ref U2fAppIdUsedBoolPtr);
            Helper.SafeFreeHGlobal(ref CancellationId);
        }

        public void Dispose()
        {
            FreeMemory();
            GC.SuppressFinalize(this);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class AuthenticatorGetAssertionOptions
    {
        // Version of this structure, to allow for modifications in the future.
        protected int StructVersion = 4;

        // Time that the operation is expected to complete within.
        // This is used as guidance, and can be overridden by the platform.
        public int TimeoutMilliseconds = 30000;

        // Allowed Credentials List.
        public ICollection<Credential> AllowedCredentials;

        // Allowed CredentialsEx List. If present, "AllowedCredentials" will be ignored.
        public ICollection<CredentialEx> AllowedCredentialsEx;

        // Optional extensions to parse when performing the operation.
        public ICollection<WebAuthnExtension> Extensions;

        // Optional. Platform vs Cross-Platform Authenticators.
        public AuthenticatorAttachment AuthenticatorAttachment;

        // User Verification Requirement.
        public UserVerificationRequirement UserVerificationRequirement;

        // Optional identifier for the U2F AppId. Converted to UTF8 before being hashed. Not lower cased.
        public string U2fAppId;

        // Cancellation Id - Optional - See WebAuthNGetCancellationId
        public Guid? CancellationId;
    }
}
