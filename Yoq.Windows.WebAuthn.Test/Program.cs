using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
using F2 = Fido2NetLib.Objects;

namespace Yoq.Windows.WebAuthn.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine($"webauthn.dll API version: {WebAuthnApi.GetApiVersionNumber()}");
            WebAuthnApi.IsUserVerifyingPlatformAuthenticatorAvailable(out var vpa);
            Console.WriteLine($"Verifying Platform Authenticator available: {vpa}");

            var config = new Fido2.Configuration
            {
                ChallengeSize = 32,
                Origin = "https://foo.net/bar",
                ServerDomain = "foo.net",
                ServerName = "Foo Server"
            };
            var user1 = new User { Name = "Testuser1", Id = new byte[32] };
            new Random().NextBytes(user1.Id);

            var fido2NetLib = new Fido2(config);
            var excl = new List<F2.PublicKeyCredentialDescriptor>();

            var selection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = F2.AuthenticatorAttachment.CrossPlatform,
                RequireResidentKey = false,
                UserVerification = F2.UserVerificationRequirement.Discouraged
            };

            //generate valid Fido2 request with Fido2Net
            var f2req = fido2NetLib.RequestNewCredential(user1, excl, selection, F2.AttestationConveyancePreference.Direct);

            //translate objects into our own types
            var rp = new RelayingPartyInfo { Id = f2req.Rp.Id, Name = f2req.Rp.Name };
            var user = new UserInfo { UserId = f2req.User.Id, Name = f2req.User.Name, DisplayName = f2req.User.DisplayName };

            var json = $"{{\r\n\t\"type\" : \"webauthn.create\",\r\n\t\"challenge\" : \"{Convert.ToBase64String(f2req.Challenge)}\",\r\n\t\"origin\" : \"{config.Origin}\"\r\n}}";

            var clientData = new ClientData { ClientDataJSON = Encoding.UTF8.GetBytes(json), HashAlgorithm = HashAlgorithm.Sha256 };
            var coseParams = f2req.PubKeyCredParams.Select(p => new CoseCredentialParameter((CoseAlgorithm)p.Alg)).ToList();
            var makeOptions = new AuthenticatorMakeCredentialOptions
            {
                TimeoutMilliseconds = (int)f2req.Timeout,
                UserVerificationRequirement = (UserVerificationRequirement)f2req.AuthenticatorSelection.UserVerification + 1,
                AuthenticatorAttachment = ((AuthenticatorAttachment?)f2req.AuthenticatorSelection.AuthenticatorAttachment + 1) ?? AuthenticatorAttachment.Any,
                RequireResidentKey = f2req.AuthenticatorSelection.RequireResidentKey,
                AttestationConveyancePreference = (AttestationConveyancePreference)f2req.Attestation + 1,
                ExcludeCredentialsEx = f2req.ExcludeCredentials
                    .Select(ec => new CredentialEx(ec.Id,
                        ec.Transports.Aggregate(CtapTransport.NoRestrictions, (acc, n) => acc | (CtapTransport)(1 << (int)n)))).ToList()
            };

            //call WinAPI
            var windowHandle = Process.GetCurrentProcess().MainWindowHandle;
            var res = WebAuthnApi.AuthenticatorMakeCredential(windowHandle, rp, user, coseParams, clientData, makeOptions, out var credential);
            if (res != WebAuthnResult.Ok)
            {
                Console.WriteLine(WebAuthnApi.GetErrorName(res));
                return;
            }

            //translate back and verify
            var resp = new AuthenticatorAttestationRawResponse
            {
                Id = credential.CredentialId,
                RawId = credential.CredentialId,
                Response = new AuthenticatorAttestationRawResponse.ResponseData
                {
                    AttestationObject = credential.AttestationObject,
                    ClientDataJson = Encoding.UTF8.GetBytes(json)
                },
                Type = F2.PublicKeyCredentialType.PublicKey
            };
            var makeRes = fido2NetLib.MakeNewCredentialAsync(resp, f2req, _ => Task.FromResult(true)).Result;
            Console.WriteLine($"Register Result: {makeRes.Result.Status}");
            Console.WriteLine($"Attestation CN: {credential.CommonAttestation.Certificates.FirstOrDefault()?.Subject}");


            for (; ; )
            {
                //--------------------- Assertion ----------------


                var allowed = new List<F2.PublicKeyCredentialDescriptor>
                {
                    new F2.PublicKeyCredentialDescriptor(credential.CredentialId)
                };

                //generate valid Fido2 request with Fido2Net
                var f2reqA = fido2NetLib.GetAssertionOptions(allowed, F2.UserVerificationRequirement.Discouraged);

                //translate objects into our own types

                var jsonA =
                    $"{{\r\n\t\"type\" : \"webauthn.get\",\r\n\t\"challenge\" : \"{Convert.ToBase64String(f2reqA.Challenge)}\",\r\n\t\"origin\" : \"{config.Origin}\"\r\n}}";

                var clientDataA = new ClientData
                {
                    ClientDataJSON = Encoding.UTF8.GetBytes(jsonA),
                    HashAlgorithm = HashAlgorithm.Sha256
                };

                WebAuthnApi.GetCancellationId(out var cancelId);

                var getOptions = new AuthenticatorGetAssertionOptions()
                {
                    CancellationId = cancelId,
                    TimeoutMilliseconds = (int)f2reqA.Timeout,
                    UserVerificationRequirement = (UserVerificationRequirement)f2reqA.UserVerification + 1,
                    AllowedCredentialsEx = f2reqA.AllowCredentials
                        .Select(ec => new CredentialEx(ec.Id,
                            ec.Transports?.Aggregate(CtapTransport.NoRestrictions,
                                (acc, n) => acc | (CtapTransport)(1 << (int)n))
                            ?? CtapTransport.NoRestrictions)).ToList()
                };


                //call WinAPI
                Console.WriteLine("Canceling Assertion in 5sec...");
                Task.Run(async () =>
                {
                    await Task.Delay(5000);
                    WebAuthnApi.CancelCurrentOperation(cancelId);
                });

                
                res = WebAuthnApi.AuthenticatorGetAssertion(windowHandle, config.ServerDomain, clientDataA, getOptions, out var assertion);
                if (res != WebAuthnResult.Ok)
                {
                    if (res == WebAuthnResult.Canceled)
                    {
                        Console.WriteLine("Canceled");
                        Console.ReadKey();
                        continue;
                    }

                    Console.WriteLine($"0x{(int)res:X} " + WebAuthnApi.GetErrorName(res));
                    break;
                }

                //translate back and verify
                var respA = new AuthenticatorAssertionRawResponse()
                {
                    Id = assertion.Credential.CredentialId,
                    RawId = assertion.Credential.CredentialId,
                    Type = F2.PublicKeyCredentialType.PublicKey,
                    Response = new AuthenticatorAssertionRawResponse.AssertionResponse()
                    {
                        AuthenticatorData = assertion.AuthenticatorData,
                        Signature = assertion.Signature,
                        UserHandle = assertion.UserId,
                        ClientDataJson = Encoding.UTF8.GetBytes(jsonA)
                    },
                };
                var getResult = fido2NetLib.MakeAssertionAsync(respA, f2reqA, makeRes.Result.PublicKey, makeRes.Result.Counter,
                    _ => Task.FromResult(true)).Result;
                Console.WriteLine($"Assertion Result: {getResult.Status}");

                Console.WriteLine("Press any key to test assertion again");
                Console.ReadKey();
            }

            Console.ReadKey();
        }
    }
}
