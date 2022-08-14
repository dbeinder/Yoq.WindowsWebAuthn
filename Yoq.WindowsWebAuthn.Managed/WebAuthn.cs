using Yoq.WindowsWebAuthn.Pinvoke;
using F2 = Fido2NetLib;

namespace Yoq.WindowsWebAuthn.Managed
{
    public enum WebAuthnResult
    {
        Success,
        UserCancelled,
        Cancelled,
        InvalidStateError,
        ConstraintError,
        NotSupportedError,
        NotAllowedError,
        UnknownError
    }

    public static class WebAuthn
    {
        private static bool? _available;
        public static bool ApiAvailable => _available ?? (_available = WebAuthnApi.CheckApiAvailable()).Value;
        public static int ApiVersion => WebAuthnApi.ApiVersion;

        private static bool? _userVerifyingPlatformAuthenticatorAvailable;
        public static bool UserVerifyingPlatformAuthenticatorAvailable
        {
            get
            {
                if (_userVerifyingPlatformAuthenticatorAvailable.HasValue) return _userVerifyingPlatformAuthenticatorAvailable.Value;
                if (WebAuthnApi.IsUserVerifyingPlatformAuthenticatorAvailable(out var avl) == WebAuthnHResult.Ok)
                    _userVerifyingPlatformAuthenticatorAvailable = avl;
                else
                    _userVerifyingPlatformAuthenticatorAvailable = false;
                return _userVerifyingPlatformAuthenticatorAvailable.Value;
            }
        }

        private static bool CheckFailure(WebAuthnHResult hresult, out WebAuthnResult result)
        {
            result = WebAuthnResult.Success;
            if (hresult == WebAuthnHResult.Ok) return false;
            if (hresult == WebAuthnHResult.Canceled)
                result = WebAuthnResult.UserCancelled;
            else
            {
                var errorText = WebAuthnApi.GetErrorName(hresult);
                result = Enum.TryParse<WebAuthnResult>(errorText, out var en) ? en : WebAuthnResult.UnknownError;
            }
            return true;
        }

        public static WebAuthnResult MakeCredential(IntPtr hwnd, F2.CredentialCreateOptions opts, string origin, out F2.AuthenticatorAttestationRawResponse response, CancellationToken? ct = null)
        {
            Guid? cancelGuid = null;
            CancellationTokenRegistration? cancelReg = null;
            if (ct.HasValue)
            {
                WebAuthnApi.GetCancellationId(out var cg);
                cancelGuid = cg;
                cancelReg = ct.Value.Register(() => WebAuthnApi.CancelCurrentOperation(cg));
            }

            response = null;
            var clientData = opts.ToClientData(origin);
            var res = WebAuthnApi.AuthenticatorMakeCredential(hwnd, opts.ToRelayingPartyInfo(), opts.ToUserInfo(),
                                                                    opts.ToCoseParamsList(), clientData,
                                                                    opts.ToAuthenticatorMakeCredentialOptions(cancelGuid),
                                                                    out var credential);
            cancelReg?.Dispose();
            if (cancelReg?.Token.IsCancellationRequested ?? false) return WebAuthnResult.Cancelled;
            if (CheckFailure(res, out var result)) return result;

            response = new F2.AuthenticatorAttestationRawResponse
            {
                Id = credential.CredentialId,
                RawId = credential.CredentialId,
                Response = new F2.AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = credential.AttestationObject,
                    ClientDataJson = clientData.ClientDataJSON
                },
                Type = F2.Objects.PublicKeyCredentialType.PublicKey
            };

            return WebAuthnResult.Success;
        }

        public static WebAuthnResult GetAssertion(IntPtr hwnd, F2.AssertionOptions opts, string origin, out F2.AuthenticatorAssertionRawResponse response, CancellationToken? ct = null)
        {
            Guid? cancelGuid = null;
            CancellationTokenRegistration? cancelReg = null;
            if (ct.HasValue)
            {
                WebAuthnApi.GetCancellationId(out var cg);
                cancelGuid = cg;
                cancelReg = ct.Value.Register(() => WebAuthnApi.CancelCurrentOperation(cg));
            }

            response = null;
            var clientData = opts.ToClientData(origin);
            var res = WebAuthnApi.AuthenticatorGetAssertion(hwnd, opts.RpId, clientData, opts.ToAssertionOptions(cancelGuid), out var assertion);

            cancelReg?.Dispose();
            if (cancelReg?.Token.IsCancellationRequested ?? false) return WebAuthnResult.Cancelled;
            if (CheckFailure(res, out var result)) return result;

            response = new F2.AuthenticatorAssertionRawResponse()
            {
                Id = assertion.Credential.CredentialId,
                RawId = assertion.Credential.CredentialId,
                Type = F2.Objects.PublicKeyCredentialType.PublicKey,
                Response = new F2.AuthenticatorAssertionRawResponse.AssertionResponse()
                {
                    AuthenticatorData = assertion.AuthenticatorData,
                    Signature = assertion.Signature,
                    UserHandle = assertion.UserId,
                    ClientDataJson = clientData.ClientDataJSON
                },
            };

            return WebAuthnResult.Success;
        }

        public static Task<(WebAuthnResult, F2.AuthenticatorAttestationRawResponse)> MakeCredentialAsync(IntPtr hwnd, F2.CredentialCreateOptions opts, string origin, CancellationToken? ct = null)
            => Task.Run(() => { var res = MakeCredential(hwnd, opts, origin, out var resp, ct); return (res, resp); });

        public static Task<(WebAuthnResult, F2.AuthenticatorAssertionRawResponse)> GetAssertionAsync(IntPtr hwnd, F2.AssertionOptions opts, string origin, CancellationToken? ct = null)
            => Task.Run(() => { var res = GetAssertion(hwnd, opts, origin, out var resp, ct); return (res, resp); });
    }
}
