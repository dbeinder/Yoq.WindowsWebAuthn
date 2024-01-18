using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Cbor;
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

            public Credential(RegisteredPublicKeyCredential s, bool isRk)
            {
                Name = s.User.Name;
                ResidentKey = isRk;
                Counter = s.SignCount;
                CredentialId = s.Id;
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

        static string DecodeAlgType(byte[]? pk)
        {
            try
            {
                var cpk = (CborMap)CborObject.Decode(pk);
                var alg = (COSE.Algorithm)(int)cpk.GetValue((long)COSE.KeyCommonParameter.Alg);
                return alg.ToString();
            }
            catch { return ""; }
        }

        static void Main(string[] args)
        {
            Console.WriteLine($"webauthn.dll available: {WebAuthn.ApiAvailable}");
            if (!WebAuthn.ApiAvailable) return;
            Console.WriteLine($"webauthn.dll API version: {WebAuthn.ApiVersion}");
            Console.WriteLine($"User Verifying Platform Authenticator available: {WebAuthn.UserVerifyingPlatformAuthenticatorAvailable}");

            // This handle selects the window, that the security prompt will be centered in.
            // After the prompt finishes, focus will be returned to the window choosen here.
            // (!) This is only an example, please note that GetForegroundWindow() may return:
            //   - the window handle of a different process if this process is not in the foreground
            //   - or even NULL if there is no active window at all
            // The WebAuthn API does not allow NULL, and returning to the wrong window is annoying,
            // so take care with this parameter in a real world application.
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

            var residentKeyReq = ResidentKeyRequirement.Discouraged;
            var doTimeout = false;
            var attachment = AuthenticatorAttachment.CrossPlatform;
            var uvReq = UserVerificationRequirement.Discouraged;
            var attestationReq = AttestationConveyancePreference.None;
            var credProtect = CredentialProtectionPolicy.UserVerificationOptional;
            var transportIdx = 0;
            var transportList = new AuthenticatorTransport[]?[] { null,
                new[] { AuthenticatorTransport.Usb }, new[] { AuthenticatorTransport.Nfc },
                new[] { AuthenticatorTransport.Ble }, new[] { AuthenticatorTransport.Internal } };
            AuthenticatorTransport[]? transport = null;
            List<Credential> testCreds = File.Exists(CredentialsFile) ? File.ReadAllLines(CredentialsFile).Select(s => new Credential(s)).ToList() : new();
            var userCounter = 1 + testCreds.Where(c => c.Name.StartsWith("testuser")).Select(c => int.TryParse(c.Name.AsSpan(8), out var n) ? n : 0).DefaultIfEmpty(0).Max();
            void UpdateCredFile() => File.WriteAllLines(CredentialsFile, testCreds.Select(c => c.ToLine()));
            for (; ; )
            {
                var (_, origTop) = Console.GetCursorPosition();
                Console.WriteLine();
                Console.WriteLine($"( ) Parameters for both Create/Assert");
                Console.WriteLine($"  (3) Toggle UserVerification requirement [{uvReq}]         ");
                Console.WriteLine($"  (4) Toggle allowed transport [{(transport?[0].ToString() ?? "Any")}]       ");
                Console.WriteLine($"  (5) Toggle automatic 10sec timeout [{(doTimeout ? "ON" : "OFF")}] ");
                Console.WriteLine($"(1) Create new credential");
                Console.WriteLine($"  (6) Toggle Attestation requirement [{attestationReq}]     ");
                Console.WriteLine($"  (7) Toggle Authenticator Attachment [{attachment}]        ");
                Console.WriteLine($"  (8) Toggle ResidentKey requirement [{residentKeyReq}]     ");
                Console.WriteLine($"  (9) Toggle CredProtect policy [{credProtect.ToString().Replace("UserVerification", "Uv")}]                            ");
                Console.WriteLine($"(2) Request Assertion");
                Console.WriteLine($"(10) Forget all credentials [{testCreds.Count} stored]   ");
                Console.WriteLine($"(11) Manage platform credentials");
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
                        Console.WriteLine($" [{n}] {testCreds[n].Name}{(testCreds[n].ResidentKey?" [RK]":"")}");
                    Console.Write($"Comma separated list of credentials to {what} [none]> ");
                    var selection = Console.ReadLine()?.Trim().Split(",")
                        .Select(s => int.TryParse(s.Trim(), out var n) ? n : -1)
                        .Where(n => n >= 0 && n < testCreds.Count).ToArray() ?? Array.Empty<int>();
                    Console.Write($"Selected to {what}: ");
                    foreach (var selIdx in selection)
                    {
                        Console.Write($"{testCreds[selIdx].Name} ");
                        res.Add(new(PublicKeyCredentialType.PublicKey, testCreds[selIdx].CredentialId, transport));
                    }
                    Console.WriteLine();
                    return res;
                }

                switch (selection)
                {
                    case 0: return;
                    case 3: uvReq = (UserVerificationRequirement)(((int)uvReq + 1) % 3); JumpBack(); continue;
                    case 4: transport = transportList[++transportIdx % 5]; JumpBack(); continue;
                    case 5: doTimeout = !doTimeout; JumpBack(); continue;
                    case 6: attestationReq = (AttestationConveyancePreference)(((int)attestationReq + 1) % 3); JumpBack(); continue;
                    case 7: attachment = (AuthenticatorAttachment)(((int)attachment + 1) % 2); JumpBack(); continue;
                    case 8: residentKeyReq = (ResidentKeyRequirement)(((int)residentKeyReq + 1) % 3); JumpBack(); continue;
                    case 9: credProtect = (CredentialProtectionPolicy)(((int)credProtect) % 3 + 1); JumpBack(); continue;
                    case 10: File.WriteAllText(CredentialsFile, ""); testCreds.Clear(); JumpBack(); continue;
                    case 11:
                        Console.WriteLine("\n= Platform credentials =");

                        var res = WebAuthn.GetPlatformCredentials(out var platformCredentials);
                        Console.WriteLine($"GetPlatformCredentials: {res}, found {platformCredentials?.Count ?? 0} credentials");
                        if (res != WebAuthnResult.Success) break;
                        for (var n = 0; n < platformCredentials!.Count; n++)
                            Console.WriteLine($"  [{n}] {platformCredentials[n].User.Name}");
                        if (platformCredentials.Count == 0) break;
                        Console.Write("Delete platform credential? [none]>");
                        if (int.TryParse(Console.ReadLine()?.Trim(), out var del) && del >= 0 && del < platformCredentials.Count)
                            Console.WriteLine($"DeletePlatformCredential: {WebAuthn.DeletePlatformCredential(platformCredentials[del])}");
                        break;
                    case 1:
                        Console.WriteLine("\n= Creating new credential =");
                        var username = "testuser" + userCounter++;
                        Console.Write($"Username [{username}]> ");
                        var uu = Console.ReadLine()?.Trim().Replace(";", "");
                        if (!string.IsNullOrWhiteSpace(uu)) username = uu;

                        var authSelection = new AuthenticatorSelection
                        {
                            AuthenticatorAttachment = attachment,
                            ResidentKey = residentKeyReq,
                            UserVerification = uvReq
                        };

                        var user = new Fido2User { Name = username, Id = RandomNumberGenerator.GetBytes(16), DisplayName = $"DisplayName({username})" };
                        var excludeCreds = CredSelect("exclude");
                        var extensions = new AuthenticationExtensionsClientInputs { CredentialProtectionPolicy = credProtect };
                        var makeRequest = fido2.RequestNewCredential(user, excludeCreds, authSelection, attestationReq, extensions);

                        var cancelSource = doTimeout ? new CancellationTokenSource(TimeSpan.FromSeconds(10)) : null;
                        Console.WriteLine($"Calling Windows WebAuthn API...");
                        res = WebAuthn.MakeCredential(windowHandle, makeRequest, myTestOrigin, out var response, cancelSource?.Token);
                        Console.WriteLine($"Authenticator Response: {res}");
                        if (res != WebAuthnResult.Success) continue;

                        var makeRes = fido2.MakeNewCredentialAsync(response, makeRequest, async (p, _) => !testCreds.Any(c => c.CredentialId.SequenceEqual(p.CredentialId))).Result;
                        var isResident = response.ClientExtensionResults.CredProps?.Rk;
                        var isResidentStr = isResident switch { null => "unknown", true => "yes", false => "no" };
                        var hasCredProtect = response.ClientExtensionResults.CredProtect switch { null => "unknown", CredentialProtectionPolicy p => p.ToString() };
                        Console.WriteLine($"MakeNewCredential result: {makeRes.Status} {makeRes.ErrorMessage}\n" +
                            $"  Algorithm: {DecodeAlgType(makeRes.Result?.PublicKey)}\n" +
                            $"  Counter: {makeRes.Result?.SignCount}\n" +
                            $"  IsResidentKey: {isResidentStr}\n" +
                            $"  CredProtect: {hasCredProtect}");
                        if (makeRes.Result == null) continue;
                        testCreds.Add(new Credential(makeRes.Result, isResident ?? false));
                        UpdateCredFile();

                        var attestation = AuthenticatorAttestationResponse.Parse(response).AttestationObject;
                        var verifier = AttestationVerifier.Create(attestation.Fmt);
                        var clientDataHash = SHA256.HashData(response.Response.ClientDataJson);
                        (var attType, var trustPath) = verifier.VerifyAsync(attestation.AttStmt, attestation.AuthData, clientDataHash).Result;
                        Console.WriteLine($"  Attestation Type: {attType}");
                        if (trustPath != null)
                        {
                            for (var cn = 0; cn < trustPath.Length; cn++)
                            {
                                var cert = trustPath[cn];
                                Console.WriteLine($"  Attestation[{cn}] Subject: {cert?.Subject}");
                                Console.WriteLine($"                 Issuer:  {cert?.Issuer}");
                                Console.WriteLine($"                 Serial:  {cert?.SerialNumber}");
                                Console.WriteLine($"                 Valid:   {cert?.NotBefore:yyyy-MM-dd} - {cert?.NotAfter:yyyy-MM-dd}");
                            }
                        }
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
                            Console.WriteLine($"Assertion received, but Credential was not found in {CredentialsFile}, can't verify!");
                            continue;
                        }

                        var getResult = fido2.MakeAssertionAsync(assertResponse, assertRequest, cred.PublicKey, Array.Empty<byte[]>(), cred.Counter, (p, _) => Task.FromResult(true)).Result;
                        Console.WriteLine($"MakeAssertion Result: {getResult.Status} {getResult.ErrorMessage} Counter: {getResult.SignCount}");
                        Console.WriteLine($"Used Credential: {cred.Name}");
                        cred.Counter = getResult.SignCount;
                        UpdateCredFile();
                        continue;
                    default: continue;
                }
            }
        }
    }
}
