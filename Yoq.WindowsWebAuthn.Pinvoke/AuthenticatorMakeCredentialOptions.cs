using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Yoq.WindowsWebAuthn.Pinvoke
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class RawAuthenticatorMakeCredentialOptions
    {
        // Version of this structure, to allow for modifications in the future.
        protected int StructVersion = 3;

        // Time that the operation is expected to complete within.
        // This is used as guidance, and can be overridden by the platform.
        public int TimeoutMilliseconds;

        // Credentials used for exclusion.
        public RawCredentialsList ExcludeCredentialsList;

        // Optional extensions to parse when performing the operation.
        public RawWebauthnExtensions Extensions;

        // Optional. Platform vs Cross-Platform Authenticators.
        public AuthenticatorAttachment AuthenticatorAttachment;

        // Optional. Require key to be resident or not. Defaulting to FALSE;
        public bool RequireResidentKey;

        // User Verification Requirement.
        public UserVerificationRequirement UserVerificationRequirement;

        // Attestation Conveyance Preference.
        public AttestationConveyancePreference AttestationConveyancePreference;

        // Reserved for future Use
        protected int ReservedFlags = 0;

        //
        // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_2
        //

        // Cancellation Id - Optional - See WebAuthNGetCancellationId
        public IntPtr CancellationId;

        //
        // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3
        //

        // Exclude Credential List. If present, "CredentialList" will be ignored.
        public IntPtr ExcludeCredentialsExListPtr;

        ///-----------------------
        //should not be marshaled / ignored
        private readonly RawCredentialExList _excludeCredentialsExList;

        public RawAuthenticatorMakeCredentialOptions() { }
        public RawAuthenticatorMakeCredentialOptions(AuthenticatorMakeCredentialOptions makeOptions)
        {
            ExcludeCredentialsList = new RawCredentialsList(makeOptions.ExcludeCredentials);

            if (makeOptions.ExcludeCredentialsEx?.Count > 0)
            {
                _excludeCredentialsExList = new RawCredentialExList(makeOptions.ExcludeCredentialsEx);
                ExcludeCredentialsExListPtr = Marshal.AllocHGlobal(Marshal.SizeOf<RawCredentialExList>());
                Marshal.StructureToPtr(_excludeCredentialsExList, ExcludeCredentialsExListPtr, false);
            }

            CancellationId = IntPtr.Zero;
            if (makeOptions.CancellationId.HasValue)
            {
                CancellationId = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
                Marshal.StructureToPtr(makeOptions.CancellationId.Value, CancellationId, false);
            }

            TimeoutMilliseconds = makeOptions.TimeoutMilliseconds;
            AuthenticatorAttachment = makeOptions.AuthenticatorAttachment;
            UserVerificationRequirement = makeOptions.UserVerificationRequirement;
            AttestationConveyancePreference = makeOptions.AttestationConveyancePreference;
            RequireResidentKey = makeOptions.RequireResidentKey;

            Extensions = new RawWebauthnExtensions { Count = 0, Extensions = IntPtr.Zero }; //TODO
        }

        ~RawAuthenticatorMakeCredentialOptions() => FreeMemory();

        protected void FreeMemory()
        {
            ExcludeCredentialsList.Dispose();
            _excludeCredentialsExList?.Dispose();

            Helper.SafeFreeHGlobal(ref ExcludeCredentialsExListPtr);
            Helper.SafeFreeHGlobal(ref CancellationId);
        }

        public void Dispose()
        {
            FreeMemory();
            GC.SuppressFinalize(this);
        }
    }

    public class AuthenticatorMakeCredentialOptions
    {
        // Time that the operation is expected to complete within.
        // This is used as guidance, and can be overridden by the platform.
        public int TimeoutMilliseconds = 30000;

        // Credentials used for exclusion.
        public ICollection<Credential> ExcludeCredentials;

        // Exclude Credential List. If present, "ExcludeCredentials" will be ignored.
        public ICollection<CredentialEx> ExcludeCredentialsEx;

        // Optional extensions to parse when performing the operation.
        public ICollection<WebAuthnExtension> Extensions;

        // Optional. Platform vs Cross-Platform Authenticators.
        public AuthenticatorAttachment AuthenticatorAttachment;

        // Optional. Require key to be resident or not. Defaulting to FALSE;
        public bool RequireResidentKey;

        // User Verification Requirement.
        public UserVerificationRequirement UserVerificationRequirement;

        // Attestation Conveyance Preference.
        public AttestationConveyancePreference AttestationConveyancePreference;

        // Cancellation Id - Optional - See WebAuthNGetCancellationId
        public Guid? CancellationId;
    }
}
