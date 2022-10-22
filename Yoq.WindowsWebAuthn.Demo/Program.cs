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
        const string CredentialsFile = "credentials.csv";

        class Credential
        {
            public string Name;
            public bool ResidentKey;
            public uint Counter;
            public byte[] CredentialId;
            public byte[] PublicKey;

            public Credential(AttestationVerificationSuccess s, bool isRk)
            {
                Name = s.User.Name;
                ResidentKey = isRk;
                Counter = s.Counter;
                CredentialId = s.CredentialId;
                PublicKey = s.PublicKey;
            }

            public Credential(string s)
            {
                var parts = s.Split(";");
                Name = parts[0];
                ResidentKey = bool.Parse(parts[1]);
                Counter = uint.Parse(parts[2]);
                CredentialId = Convert.FromBase64String(parts[3]);
                PublicKey = Convert.FromBase64String(parts[4]);
            }

            public string ToLine() => $"{Name};{ResidentKey};{Counter};{Convert.ToBase64String(CredentialId)};{Convert.ToBase64String(PublicKey)}";
        }

        static void Main(string[] args)
        {
            Console.WriteLine($"webauthn.dll available: {WebAuthn.ApiAvailable}");
            if (!WebAuthn.ApiAvailable) return;
            Console.WriteLine($"webauthn.dll API version: {WebAuthn.ApiVersion}");
            Console.WriteLine($"User Verifying Platform Authenticator available: {WebAuthn.UserVerifyingPlatformAuthenticatorAvailable}");

            var windowHandle = WinApiHelper.GetForegroundWindow();
            
            var myTestOrigin = "local://demo-app";
            var config = new Fido2Configuration
            {
                ChallengeSize = 32,
                Origins = new HashSet<string>() { myTestOrigin },
                ServerDomain = "demo-app",
                ServerName = "WindowsWebAuthn Demo App"
            };
            var fido2 = new Fido2(config);

            var needResidentKey = false;
            var doTimeout = false;
            var attachment = AuthenticatorAttachment.CrossPlatform;
            var uvReq = UserVerificationRequirement.Discouraged;
            var attestationReq = AttestationConveyancePreference.None;
            var transportIdx = 0;
            var transportList = new AuthenticatorTransport[]?[] { null,
                new[] { AuthenticatorTransport.Usb },new[] { AuthenticatorTransport.Nfc },
                new[] { AuthenticatorTransport.Ble }, new[]{AuthenticatorTransport.Internal } };
            AuthenticatorTransport[]? transport = null;
            List<Credential> testCreds = File.Exists(CredentialsFile) ? File.ReadAllLines(CredentialsFile).Select(s => new Credential(s)).ToList() : new();
            void UpdateCredFile() => File.WriteAllLines(CredentialsFile, testCreds.Select(c => c.ToLine()));
            var userCounter = 1;
            for (; ; )
            {
                var (_, origTop) = Console.GetCursorPosition();
                Console.WriteLine();
                Console.WriteLine($"( ) Parameters for both Create/Assert");
                Console.WriteLine($"  (3) Toggle UserVerification requirement [{uvReq}]         ");
                Console.WriteLine($"  (4) Toggle allowed transport [{(transport?[0].ToString() ?? "Any")}]       ");
                Console.WriteLine($"  (5) Toggle automatic 10sec timeout [{(doTimeout ? "ON" : "OFF")}] ");
                Console.WriteLine($"(1) Create new credential");
                Console.WriteLine($"  (6) Toggle RequireResidentKey [{(needResidentKey ? "ON" : "OFF")}] ");
                Console.WriteLine($"  (7) Toggle Attestation requirement [{attestationReq}]     ");
                Console.WriteLine($"  (8) Toggle Authenticator Attachment [{attachment}]        ");
                Console.WriteLine($"(2) Request Assertion");
                Console.WriteLine($"(9) Forget all credentials [{testCreds.Count} stored]   ");
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
                        Console.WriteLine($" [{n}] {testCreds[n].Name}");
                    Console.Write($"Comma separated list of credentials to {what} [none]> ");
                    var selection = Console.ReadLine()?.Trim().Split(",")
                        .Select(s => int.TryParse(s.Trim(), out var n) ? n : -1)
                        .Where(n => n >= 0 && n < testCreds.Count).ToArray() ?? Array.Empty<int>();
                    Console.Write($"Selected to {what}: ");
                    foreach (var selIdx in selection)
                    {
                        Console.Write($"{testCreds[selIdx].Name} ");
                        res.Add(new PublicKeyCredentialDescriptor(testCreds[selIdx].CredentialId) { Transports = transport });
                    }
                    Console.WriteLine();
                    return res;
                }

                switch (selection)
                {
                    case 0: return;
                    case 5: doTimeout = !doTimeout; JumpBack(); continue;
                    case 8: attachment = (AuthenticatorAttachment)(((int)attachment + 1) % 2); JumpBack(); continue;
                    case 7: attestationReq = (AttestationConveyancePreference)(((int)attestationReq + 1) % 3); JumpBack(); continue;
                    case 4: transport = transportList[++transportIdx % 5]; JumpBack(); continue;
                    case 3: uvReq = (UserVerificationRequirement)(((int)uvReq + 1) % 3); JumpBack(); continue;
                    case 6: needResidentKey = !needResidentKey; JumpBack(); continue;
                    case 9: File.WriteAllText(CredentialsFile, ""); testCreds.Clear(); JumpBack(); continue;
                    case 1:
                        Console.WriteLine("\n= Creating new credential =");
                        var username = "testuser" + userCounter++;
                        Console.Write($"Username [{username}]> ");
                        var uu = Console.ReadLine()?.Trim().Replace(";", "");
                        if (!string.IsNullOrWhiteSpace(uu)) username = uu;

                        var authSelection = new AuthenticatorSelection
                        {
                            AuthenticatorAttachment = attachment,
                            RequireResidentKey = needResidentKey,
                            UserVerification = uvReq
                        };

                        var user = new Fido2User { Name = username, Id = RandomNumberGenerator.GetBytes(32), DisplayName = $"DisplayName({username})" };
                        var excludeCreds = CredSelect("exclude");
                        var makeRequest = fido2.RequestNewCredential(user, excludeCreds, authSelection, attestationReq);

                        var cancelSource = doTimeout ? new CancellationTokenSource(TimeSpan.FromSeconds(10)) : null;
                        Console.WriteLine($"Calling Windows WebAuthn API...");
                        var res = WebAuthn.MakeCredential(windowHandle, makeRequest, myTestOrigin, out var response, cancelSource?.Token);
                        Console.WriteLine($"Authenticator Response: {res}");
                        if (res != WebAuthnResult.Success) continue;

                        var makeRes = fido2.MakeNewCredentialAsync(response, makeRequest, async (p, _) => !testCreds.Any(c => c.CredentialId.SequenceEqual(p.CredentialId))).Result;
                        Console.WriteLine($"MakeNewCredential Result: {makeRes.Status} {makeRes.ErrorMessage} Counter: {makeRes.Result?.Counter}");
                        if (makeRes.Result == null) continue;
                        testCreds.Add(new Credential(makeRes.Result, needResidentKey));
                        UpdateCredFile();
                        //TODO: print attestation chain, needs Fido2.Models v3.1.0
                        //foreach(var cert in makeRes.Result.AttestationCertificateChain) Console.WriteLine($"Attestation CN: {cert?.Subject}");
                        continue;

                    case 2:
                        Console.WriteLine("\n= Requesting a credential assertion =");
                        var allowed = CredSelect("send to authenticator");
                        var assertRequest = fido2.GetAssertionOptions(allowed, uvReq);

                        cancelSource = doTimeout ? new CancellationTokenSource(TimeSpan.FromSeconds(10)) : null;
                        Console.WriteLine($"Calling Windows WebAuthn API...");
                        res = WebAuthn.GetAssertion(windowHandle, assertRequest, myTestOrigin, out var assertResponse, cancelSource?.Token);
                        Console.WriteLine($"Authenticator Response: {res}");
                        if (res != WebAuthnResult.Success) continue;

                        var cred = testCreds.FirstOrDefault(c => c.CredentialId.SequenceEqual(assertResponse.Id));
                        if (cred == null)
                        {
                            Console.WriteLine($"Can't verify unknown credential, has {CredentialsFile} been cleared?");
                            continue;
                        }
                        
                        var getResult = fido2.MakeAssertionAsync(assertResponse, assertRequest, cred.PublicKey, cred.Counter, (p, _) => Task.FromResult(true)).Result;
                        Console.WriteLine($"MakeAssertion Result: {getResult.Status} {getResult.ErrorMessage} Counter: {getResult.Counter}");
                        Console.WriteLine($"Used Credential: {cred.Name}");
                        cred.Counter = getResult.Counter;
                        UpdateCredFile();
                        continue;
                    default: continue;
                }
            }
        }
    }
}
