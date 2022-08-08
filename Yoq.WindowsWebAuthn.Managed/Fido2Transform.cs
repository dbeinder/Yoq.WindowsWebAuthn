using System.Text.Json;
using Yoq.WindowsWebAuthn.Pinvoke;
using F2 = Fido2NetLib;

namespace Yoq.WindowsWebAuthn.Managed
{
    internal static class Fido2Transform
    {
        public static RelayingPartyInfo ToRelayingPartyInfo(this F2.CredentialCreateOptions opts)
            => new() { Id = opts.Rp.Id, Name = opts.Rp.Name };

        public static UserInfo ToUserInfo(this F2.CredentialCreateOptions opts)
            => new() { UserId = opts.User.Id, Name = opts.User.Name, DisplayName = opts.User.DisplayName };

        public static List<CoseCredentialParameter> ToCoseParamsList(this F2.CredentialCreateOptions opts)
            => opts.PubKeyCredParams.Select(p => new CoseCredentialParameter((CoseAlgorithm)p.Alg)).ToList();

        public static AuthenticatorMakeCredentialOptions ToAuthenticatorMakeCredentialOptions(this F2.CredentialCreateOptions opt, Guid? cancellationId = null) => new()
        {
            TimeoutMilliseconds = (int)opt.Timeout,
            UserVerificationRequirement = opt.AuthenticatorSelection.UserVerification.FromF2(),
            AuthenticatorAttachment = opt.AuthenticatorSelection.AuthenticatorAttachment.FromF2(),
            RequireResidentKey = opt.AuthenticatorSelection.RequireResidentKey,
            AttestationConveyancePreference = opt.Attestation.FromF2(),
            ExcludeCredentialsEx = opt.ExcludeCredentials.Select(ec => ec.FromF2()).ToList(),
            CancellationId = cancellationId
        };

        public static UserVerificationRequirement FromF2(this F2.Objects.UserVerificationRequirement? uvr)
            => uvr?.FromF2() ?? UserVerificationRequirement.Any;
        public static UserVerificationRequirement FromF2(this F2.Objects.UserVerificationRequirement uvr) => uvr switch
        {
            F2.Objects.UserVerificationRequirement.Preferred => UserVerificationRequirement.Preferred,
            F2.Objects.UserVerificationRequirement.Required => UserVerificationRequirement.Required,
            F2.Objects.UserVerificationRequirement.Discouraged => UserVerificationRequirement.Discouraged,
            _ => throw new NotImplementedException(uvr.ToString())
        };

        public static AuthenticatorAttachment FromF2(this F2.Objects.AuthenticatorAttachment? aa) => aa switch
        {
            null => AuthenticatorAttachment.Any,
            F2.Objects.AuthenticatorAttachment.Platform => AuthenticatorAttachment.Platform,
            F2.Objects.AuthenticatorAttachment.CrossPlatform => AuthenticatorAttachment.CrossPlatform,
            _ => throw new NotImplementedException(aa.ToString())
        };

        public static AttestationConveyancePreference FromF2(this F2.Objects.AttestationConveyancePreference acp) => acp switch
        {
            F2.Objects.AttestationConveyancePreference.None => AttestationConveyancePreference.None,
            F2.Objects.AttestationConveyancePreference.Direct => AttestationConveyancePreference.Direct,
            F2.Objects.AttestationConveyancePreference.Indirect => AttestationConveyancePreference.Indirect,
            _ => throw new NotImplementedException(acp.ToString())
        };

        public static CtapTransport FromF2(this F2.Objects.AuthenticatorTransport[]? transports)
        {
            var flags = CtapTransport.NoRestrictions;
            if (transports != null)
                foreach (var transport in transports) flags |= transport.FromF2();
            return flags;
        }

        public static CtapTransport FromF2(this F2.Objects.AuthenticatorTransport transport) => transport switch
        {
            F2.Objects.AuthenticatorTransport.Internal => CtapTransport.Internal,
            F2.Objects.AuthenticatorTransport.Ble => CtapTransport.BLE,
            F2.Objects.AuthenticatorTransport.Usb => CtapTransport.USB,
            F2.Objects.AuthenticatorTransport.Nfc => CtapTransport.NFC,
            _ => throw new NotImplementedException(transport.ToString())
        };

        public static CredentialType FromF2(this F2.Objects.PublicKeyCredentialType? pkct) => pkct switch
        {
            null => CredentialType.PublicKey, // TODO: verify this
            F2.Objects.PublicKeyCredentialType.PublicKey => CredentialType.PublicKey,
            _ => throw new NotImplementedException(pkct.ToString())
        };

        public static CredentialEx FromF2(this F2.Objects.PublicKeyCredentialDescriptor pkcd)
            => new(pkcd.Id, pkcd.Type.FromF2(), pkcd.Transports.FromF2());


        //make sure '+' are not escaped by JsonSerializer
        private static readonly JsonSerializerOptions _jso = new JsonSerializerOptions() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        public static ClientData ToClientData(this F2.CredentialCreateOptions opt, string origin, HashAlgorithm hashAlg = HashAlgorithm.Sha256)
        {
            return new ClientData
            {
                ClientDataJSON = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    type = "webauthn.create",
                    challenge = Convert.ToBase64String(opt.Challenge),
                    origin = origin
                }, _jso),
                HashAlgorithm = hashAlg
            };
        }

        public static ClientData ToClientData(this F2.AssertionOptions opt, string origin, HashAlgorithm hashAlg = HashAlgorithm.Sha256)
        {
            return new ClientData
            {
                ClientDataJSON = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    type = "webauthn.get",
                    challenge = Convert.ToBase64String(opt.Challenge),
                    origin = origin
                }, _jso),
                HashAlgorithm = hashAlg
            };
        }

        public static AuthenticatorGetAssertionOptions ToAssertionOptions(this F2.AssertionOptions opt, Guid? cancellationId = null) => new()
        {
            CancellationId = cancellationId,
            TimeoutMilliseconds = (int)opt.Timeout,
            UserVerificationRequirement = opt.UserVerification.FromF2(),
            AllowedCredentialsEx = opt.AllowCredentials.Select(ec => ec.FromF2()).ToList()
        };
    }
}
