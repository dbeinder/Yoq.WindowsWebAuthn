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
        }

        static void Run()
        {
            Console.WriteLine($"webauthn.dll available: {WebAuthn.ApiAvailable}");
            if (!WebAuthn.ApiAvailable) return;
            Console.WriteLine($"webauthn.dll API version: {WebAuthn.ApiVersion}");
            Console.WriteLine($"User Verifying Platform Authenticator available: {WebAuthn.UserVerifyingPlatformAuthenticatorAvailable}");

            var windowHandle = WinApiHelper.GetConsoleWindow();

            var myTestOrigin = "local://demo-app";
            var config = new Fido2Configuration
            {
                ChallengeSize = 32,
                Origins = new HashSet<string>() { myTestOrigin },
                ServerDomain = "demo-app",
                ServerName = "WindowsWebAuthn Demo Server"
            };
            var fido2 = new Fido2(config);

            var timeoutCreate = false;
            var timeoutAssert = false;
            var attachment = AuthenticatorAttachment.CrossPlatform;
            var uvReqCreate = UserVerificationRequirement.Discouraged;
            var uvReqAssert = UserVerificationRequirement.Discouraged;
            var attestationReq = AttestationConveyancePreference.None;
            var needResidentKey = false;
            List<AttestationVerificationSuccess> testCreds = new();
            var userCounter = 1;
            for (; ; )
            {
                var (_, origTop) = Console.GetCursorPosition();
                Console.WriteLine();
                Console.WriteLine($"(1) Create new credential");
                Console.WriteLine($"  (2) Toggle RequireResidentKey [{(needResidentKey ? "ON" : "OFF")}] ");
                Console.WriteLine($"  (3) Toggle UserVerification requirement [{uvReqCreate}]         ");
                Console.WriteLine($"  (4) Toggle Attestation requirement [{attestationReq}]     ");
                Console.WriteLine($"  (5) Toggle Authenticator Attachment [{attachment}]        ");
                Console.WriteLine($"  (6) Toggle automatic 10sec timeout [{(timeoutCreate ? "ON" : "OFF")}] ");
                Console.WriteLine($"(7) Request Assertion");
                Console.WriteLine($"  (8) Toggle UserVerification requirement [{uvReqAssert}]         ");
                Console.WriteLine($"  (9) Toggle automatic 10sec timeout [{(timeoutAssert ? "ON" : "OFF")}] ");
                Console.WriteLine($"(0) Exit");
                Console.Write(">            ");

                var (_, top) = Console.GetCursorPosition();
                Console.SetCursorPosition(2, top);
                var selection = int.TryParse(Console.ReadLine()?.Trim(), out var s) ? s : -1;

                void JumpBack() => Console.SetCursorPosition(0, Console.GetCursorPosition().Top - (1 + top - origTop));
                List<PublicKeyCredentialDescriptor> CredSelect(string what)
                {
                    var res = new List<PublicKeyCredentialDescriptor>();
                    if (testCreds.Count == 0) return res;
                    for (var n = 0; n < testCreds.Count; n++)
                        Console.WriteLine($" [{n}] {testCreds[n].User.Name}");
                    Console.Write($"Comma separated list of credentials to {what} [none]> ");
                    var selection = Console.ReadLine()?.Trim().Split(",")
                        .Select(s => int.TryParse(s.Trim(), out var n) ? n : -1)
                        .Where(n => n >= 0 && n < testCreds.Count).ToArray() ?? Array.Empty<int>();
                    Console.Write($"Selected to {what}: ");
                    foreach (var selIdx in selection)
                    {
                        Console.Write($"{testCreds[selIdx].User.Name} ");
                        res.Add(new PublicKeyCredentialDescriptor(testCreds[selIdx].CredentialId));
                    }
                    Console.WriteLine();
                    return res;
                }

                switch (selection)
                {
                    case 0: return;
                    case 6: timeoutCreate = !timeoutCreate; JumpBack(); continue;
                    case 9: timeoutAssert = !timeoutAssert; JumpBack(); continue;
                    case 5: attachment = (AuthenticatorAttachment)(((int)attachment + 1) % 2); JumpBack(); continue;
                    case 4: attestationReq = (AttestationConveyancePreference)(((int)attestationReq + 1) % 3); JumpBack(); continue;
                    case 3: uvReqCreate = (UserVerificationRequirement)(((int)uvReqCreate + 1) % 3); JumpBack(); continue;
                    case 8: uvReqAssert = (UserVerificationRequirement)(((int)uvReqAssert + 1) % 3); JumpBack(); continue;
                    case 2: needResidentKey = !needResidentKey; JumpBack(); continue;
                    case 1:
                        Console.WriteLine("\n= Creating new credential =");
                        var username = "testuser" + userCounter++;
                        Console.Write($"Username [{username}]> ");
                        var uu = Console.ReadLine();
                        if (!string.IsNullOrWhiteSpace(uu)) username = uu;

                        var authSelection = new AuthenticatorSelection
                        {
                            AuthenticatorAttachment = attachment,
                            RequireResidentKey = needResidentKey,
                            UserVerification = uvReqCreate
                        };

                        var user = new Fido2User { Name = username, Id = RandomNumberGenerator.GetBytes(32), DisplayName = $"DisplayName({username})" };
                        var excludeCreds = CredSelect("exclude");
                        var makeRequest = fido2.RequestNewCredential(user, excludeCreds, authSelection, attestationReq);

                        var cancelSource = timeoutCreate ? new CancellationTokenSource(TimeSpan.FromSeconds(10)) : null;
                        Console.WriteLine($"Calling Windows WebAuthn API...");
                        var res = WebAuthn.MakeCredential(windowHandle, makeRequest, myTestOrigin, out var response, cancelSource?.Token);
                        Console.WriteLine($"Authenticator Response: {res}");
                        if (res != WebAuthnResult.Success) continue;

                        var makeRes = fido2.MakeNewCredentialAsync(response, makeRequest, (param, ct) => Task.FromResult(true)).Result;
                        Console.WriteLine($"MakeNewCredential Result: {makeRes.Status} {makeRes.ErrorMessage} Counter: {makeRes.Result?.Counter}");
                        if (makeRes.Result == null) continue;
                        testCreds.Add(makeRes.Result);
                        //foreach(var cert in makeRes.Result.AttestationCertificateChain) Console.WriteLine($"Attestation CN: {cert?.Subject}");
                        continue;

                    case 7:
                        Console.WriteLine("\n= Requesting a credential assertion =");
                        var allowed = CredSelect("send to authenticator");
                        var assertRequest = fido2.GetAssertionOptions(allowed, uvReqAssert);

                        cancelSource = timeoutAssert ? new CancellationTokenSource(TimeSpan.FromSeconds(10)) : null;
                        Console.WriteLine($"Calling Windows WebAuthn API...");
                        res = WebAuthn.GetAssertion(windowHandle, assertRequest, myTestOrigin, out var assertResponse, cancelSource?.Token);
                        Console.WriteLine($"Authenticator Response: {res}");
                        if (res != WebAuthnResult.Success) continue;

                        var cred = testCreds.FirstOrDefault(c => c.CredentialId.SequenceEqual(assertResponse.Id));
                        if (cred == null)
                        {
                            Console.WriteLine("Credential not found, probably resident credential created by previous run of the Demo app");
                            continue;
                        }

                        var getResult = fido2.MakeAssertionAsync(assertResponse, assertRequest, cred.PublicKey, cred.Counter, (param, ct) => Task.FromResult(true)).Result;
                        Console.WriteLine($"MakeAssertion Result: {getResult.Status} {getResult.ErrorMessage} Counter: {getResult.Counter}");
                        Console.WriteLine($"Used Credential: {cred.User.Name}");
                        continue;
                    default: continue;
                }
            }
        }
    }
}
