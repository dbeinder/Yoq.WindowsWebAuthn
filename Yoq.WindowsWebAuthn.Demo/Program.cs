using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Yoq.WindowsWebAuthn.Managed;

namespace Yoq.WindowsWebAuthn.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            Run();
            Console.WriteLine("Done, press any key to exit");
            Console.ReadKey();
        }

        static void Run()
        {
            Console.WriteLine($"webauthn.dll API version: {WebAuthn.ApiVersion}");
            Console.WriteLine($"User Verifying Platform Authenticator available: {WebAuthn.UserVerifyingPlatformAuthenticatorAvailable}");

            var origin = "https://foo.net/bar";
            var config = new Fido2Configuration
            {
                ChallengeSize = 32,
                Origins = new HashSet<string>() { origin },
                ServerDomain = "foo.net",
                ServerName = "Foo Server"
            };
            var user1 = new Fido2User { Name = "TestUser1", Id = RandomNumberGenerator.GetBytes(32) };

            var fido2NetLib = new Fido2(config);
            var excl = new List<PublicKeyCredentialDescriptor>();

            var selection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform,
                RequireResidentKey = false,
                UserVerification = UserVerificationRequirement.Discouraged
            };

            //generate valid Fido2 request with Fido2Net
            var f2req = fido2NetLib.RequestNewCredential(user1, excl, selection, AttestationConveyancePreference.Direct);

            Console.WriteLine("Credential Creation (auto cancel in 10sec)");
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var windowHandle = WinApiHelper.GetConsoleWindow();
            var res = WebAuthn.MakeCredential(windowHandle, f2req, origin, out var response, cts.Token);
            Console.WriteLine(res);
            if (res != WebAuthnResult.Success) return;

            //verify
            var makeRes = fido2NetLib.MakeNewCredentialAsync(response, f2req, (param, ct) => Task.FromResult(true)).Result;
            Console.WriteLine($"Register Result: {makeRes.Status} {makeRes.ErrorMessage} Counter: {makeRes.Result?.Counter}");
            //Console.WriteLine($"Attestation CN: {credential.CommonAttestation.Certificates.FirstOrDefault()?.Subject}");


            for (; ; )
            {
                //generate valid Fido2 assertion request with Fido2Net
                var allowed = new[] { new PublicKeyCredentialDescriptor(makeRes.Result.CredentialId) };
                var f2reqA = fido2NetLib.GetAssertionOptions(allowed, UserVerificationRequirement.Discouraged);

                Console.WriteLine("Assertion (auto cancel in 5sec)");
                var cts1 = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                res = WebAuthn.GetAssertion(windowHandle, f2reqA, origin, out var respA, cts1.Token);
                Console.WriteLine(res);
                if (res == WebAuthnResult.Cancelled) continue;
                else if (res != WebAuthnResult.Success) return;

                // verify
                var getResult = fido2NetLib.MakeAssertionAsync(respA, f2reqA, makeRes.Result.PublicKey, makeRes.Result.Counter, (param, ct) => Task.FromResult(true)).Result;
                Console.WriteLine($"Assertion Result: {getResult.Status} {getResult.ErrorMessage} Counter: {getResult.Counter}");
                Console.WriteLine("Press any key to test assertion again");
                Console.ReadKey();
            }
        }
    }
}
