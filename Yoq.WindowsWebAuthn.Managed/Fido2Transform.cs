using System.Text.Encodings.Web;
using System.Text.Json;
using Yoq.WindowsWebAuthn.Pinvoke;
using Yoq.WindowsWebAuthn.Pinvoke.Extensions;
using F2 = Fido2NetLib;

namespace Yoq.WindowsWebAuthn.Managed
{
    internal static class Fido2Transform
    {
        #region Enums
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

        public static CredentialType FromF2(this F2.Objects.PublicKeyCredentialType pkct) => pkct switch
        {
            F2.Objects.PublicKeyCredentialType.PublicKey => CredentialType.PublicKey,
            _ => throw new NotImplementedException(pkct.ToString())
        };
        #endregion

        public static RelayingPartyInfo ToRelayingPartyInfo(this F2.CredentialCreateOptions opts)
            => new() { Id = opts.Rp.Id, Name = opts.Rp.Name };

        public static UserInfo ToUserInfo(this F2.CredentialCreateOptions opts)
            => new() { UserId = opts.User.Id, Name = opts.User.Name, DisplayName = opts.User.DisplayName };

        public static List<CoseCredentialParameter> ToCoseParamsList(this F2.CredentialCreateOptions opts)
            => opts.PubKeyCredParams.Select(p => new CoseCredentialParameter((CoseAlgorithm)p.Alg)).ToList();

        public static CredentialEx FromF2(this F2.Objects.PublicKeyCredentialDescriptor pkcd)
            => new(pkcd.Id, pkcd.Type.FromF2(), pkcd.Transports.FromF2());

        public static IReadOnlyCollection<WebAuthnCreationExtensionInput>? BuildCreationExtensions(this F2.CredentialCreateOptions opt)
        {
            // https://github.com/passwordless-lib/fido2-net-lib/issues/190
            // return new[] { new CredProtectExtensionIn() };
            // return new[] { new HmacSecretCreationExtension() };
            return null;
        }

        public static IReadOnlyCollection<WebAuthnAssertionExtensionInput>? BuildAssertionExtensions(this F2.AssertionOptions opt)
        {
            // https://github.com/passwordless-lib/fido2-net-lib/issues/190
            //return new[] {
            //    new HmacSecretAssertionExtension() {
            //        //UseRawSalts = true,
            //        GlobalSalt = new PrfSalt() {
            //            First = new byte[] { 12 },
            //            Second = new byte[] { 13 }
            //        },
            //        //SaltsByCredential = opt.AllowCredentials
            //        //    .ToDictionary(c => c.Id, c => new PrfSalt() {
            //        //        First = new byte[] { 12 },
            //        //        Second = new byte[] { 13 }
            //        //    })
            //    }
            //};
            return null;
        }

        public static ClientData ToClientData(this F2.CredentialCreateOptions opt, string origin, HashAlgorithm hashAlg = HashAlgorithm.Sha256) => new()
        {
            ClientDataJSON = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.create",
                challenge = F2.Base64Url.Encode(opt.Challenge),
                origin = origin
            }),
            HashAlgorithm = hashAlg
        };

        public static ClientData ToClientData(this F2.AssertionOptions opt, string origin, HashAlgorithm hashAlg = HashAlgorithm.Sha256) => new()
        {
            ClientDataJSON = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "webauthn.get",
                challenge = F2.Base64Url.Encode(opt.Challenge),
                origin = origin
            }),
            HashAlgorithm = hashAlg
        };

        public static AuthenticatorMakeCredentialOptions ToAuthenticatorMakeCredentialOptions(this F2.CredentialCreateOptions opt, Guid? cancellationId = null) => new()
        {
            TimeoutMilliseconds = (int)opt.Timeout,
            UserVerificationRequirement = opt.AuthenticatorSelection.UserVerification.FromF2(),
            AuthenticatorAttachment = opt.AuthenticatorSelection.AuthenticatorAttachment.FromF2(),
            RequireResidentKey = opt.AuthenticatorSelection.ResidentKey == F2.Objects.ResidentKeyRequirement.Required,
            PreferResidentKey = opt.AuthenticatorSelection.ResidentKey == F2.Objects.ResidentKeyRequirement.Preferred,
            AttestationConveyancePreference = opt.Attestation.FromF2(),
            ExcludeCredentialsEx = opt.ExcludeCredentials.Select(ec => ec.FromF2()).ToList(),
            CancellationId = cancellationId,
            Extensions = opt.BuildCreationExtensions()
        };

        public static AuthenticatorGetAssertionOptions ToAssertionOptions(this F2.AssertionOptions opt, Guid? cancellationId = null) => new()
        {
            CancellationId = cancellationId,
            TimeoutMilliseconds = (int)opt.Timeout,
            UserVerificationRequirement = opt.UserVerification.FromF2(),
            AllowedCredentialsEx = opt.AllowCredentials.Select(ec => ec.FromF2()).ToList(),
            U2fAppId = opt.Extensions?.AppID,
            Extensions = opt.BuildAssertionExtensions()
        };
    }
}
