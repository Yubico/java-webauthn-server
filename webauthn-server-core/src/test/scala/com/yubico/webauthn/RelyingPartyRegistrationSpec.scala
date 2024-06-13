// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.upokecenter.cbor.CBORObject
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.TestAuthenticator.AttestationCert
import com.yubico.webauthn.TestAuthenticator.AttestationMaker
import com.yubico.webauthn.TestAuthenticator.AttestationSigner
import com.yubico.webauthn.TpmAttestationStatementVerifier.Attributes
import com.yubico.webauthn.TpmAttestationStatementVerifier.TPM_ALG_NULL
import com.yubico.webauthn.TpmAttestationStatementVerifier.TpmRsaScheme
import com.yubico.webauthn.attestation.AttestationTrustSource
import com.yubico.webauthn.attestation.AttestationTrustSource.TrustRootsResult
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.AuthenticatorAttachment
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.AuthenticatorDataFlags
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AuthenticatorTransport
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.Extensions.CredentialProperties.CredentialPropertiesOutput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationOutput
import com.yubico.webauthn.data.Extensions.Uvm.UvmEntry
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.RegistrationExtensionInputs
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.UserVerificationRequirement
import com.yubico.webauthn.exception.RegistrationFailedException
import com.yubico.webauthn.extension.uvm.KeyProtectionType
import com.yubico.webauthn.extension.uvm.MatcherProtectionType
import com.yubico.webauthn.extension.uvm.UserVerificationMethod
import com.yubico.webauthn.test.Helpers
import com.yubico.webauthn.test.RealExamples
import com.yubico.webauthn.test.Util.toStepWithUtilities
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERUTF8String
import org.bouncycastle.asn1.x500.AttributeTypeAndValue
import org.bouncycastle.asn1.x500.RDN
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNamesBuilder
import org.bouncycastle.cert.jcajce.JcaX500NameUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.runner.RunWith
import org.mockito.Mockito
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import java.io.IOException
import java.math.BigInteger
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Security
import java.security.SignatureException
import java.security.cert.CRL
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PolicyNode
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util
import java.util.Collections
import java.util.Optional
import java.util.function.Predicate
import javax.security.auth.x500.X500Principal
import scala.jdk.CollectionConverters._
import scala.jdk.OptionConverters.RichOption
import scala.jdk.OptionConverters.RichOptional
import scala.util.Failure
import scala.util.Success
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class RelyingPartyRegistrationSpec
    extends AnyFunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks
    with TestWithEachProvider {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  private def toJsonObject(obj: Map[String, JsonNode]): JsonNode =
    jsonFactory.objectNode().setAll(obj.asJava)
  private def toJson(obj: Map[String, String]): JsonNode =
    toJsonObject(obj.view.mapValues(jsonFactory.textNode).toMap)

  private def sha256(bytes: ByteArray): ByteArray = Crypto.sha256(bytes)

  def flipByte(index: Int, bytes: ByteArray): ByteArray =
    editByte(bytes, index, b => (0xff ^ b).toByte)
  def editByte(bytes: ByteArray, index: Int, updater: Byte => Byte): ByteArray =
    new ByteArray(
      bytes.getBytes.updated(index, updater(bytes.getBytes()(index)))
    )

  private def finishRegistration(
      allowOriginPort: Boolean = false,
      allowOriginSubdomain: Boolean = false,
      allowUntrustedAttestation: Boolean = false,
      callerTokenBindingId: Option[ByteArray] = None,
      credentialRepository: CredentialRepository =
        Helpers.CredentialRepository.unimplemented,
      attestationTrustSource: Option[AttestationTrustSource] = None,
      origins: Option[Set[String]] = None,
      pubkeyCredParams: Option[List[PublicKeyCredentialParameters]] = None,
      testData: RegistrationTestData,
      clock: Clock = Clock.systemUTC(),
  ): FinishRegistrationSteps = {
    var builder = RelyingParty
      .builder()
      .identity(testData.rpId)
      .credentialRepository(credentialRepository)
      .allowOriginPort(allowOriginPort)
      .allowOriginSubdomain(allowOriginSubdomain)
      .allowUntrustedAttestation(allowUntrustedAttestation)
      .clock(clock)

    attestationTrustSource.foreach { ats =>
      builder = builder.attestationTrustSource(ats)
    }

    origins.map(_.asJava).foreach(builder.origins _)

    val fro = FinishRegistrationOptions
      .builder()
      .request(
        pubkeyCredParams
          .map(pkcp =>
            testData.request.toBuilder.pubKeyCredParams(pkcp.asJava).build()
          )
          .getOrElse(testData.request)
      )
      .response(testData.response)
      .callerTokenBindingId(callerTokenBindingId.toJava)
      .build()

    builder
      .build()
      ._finishRegistration(fro)
  }

  val emptyTrustSource = new AttestationTrustSource {
    override def findTrustRoots(
        attestationCertificateChain: util.List[X509Certificate],
        aaguid: Optional[ByteArray],
    ): TrustRootsResult =
      TrustRootsResult.builder().trustRoots(Collections.emptySet()).build()
  }
  def trustSourceWith(
      trustedCert: X509Certificate,
      crls: Option[Set[CRL]] = None,
      enableRevocationChecking: Boolean = true,
      policyTreeValidator: Option[Predicate[PolicyNode]] = None,
  ): AttestationTrustSource =
    (_: util.List[X509Certificate], _: Optional[ByteArray]) => {
      TrustRootsResult
        .builder()
        .trustRoots(Collections.singleton(trustedCert))
        .certStore(
          crls
            .map(crls =>
              CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(crls.asJava),
              )
            )
            .orNull
        )
        .enableRevocationChecking(enableRevocationChecking)
        .policyTreeValidator(policyTreeValidator.orNull)
        .build()
    }

  testWithEachProvider { it =>
    describe("§7.1. Registering a new credential") {

      describe("In order to perform a registration ceremony, the Relying Party MUST proceed as follows:") {

        describe("1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.") {
          it("Nothing to test: applicable only to client side.") {}
        }

        describe("2. Call navigator.credentials.create() and pass options as the publicKey option. Let credential be the result of the successfully resolved promise. If the promise is rejected, abort the ceremony with a user-visible error, or otherwise guide the user experience as might be determinable from the context available in the rejected promise. For example if the promise is rejected with an error code equivalent to \"InvalidStateError\", the user might be instructed to use a different authenticator. For information on different error contexts and the circumstances leading to them, see §6.3.2 The authenticatorMakeCredential Operation.") {
          it("Nothing to test: applicable only to client side.") {}
        }

        describe("3. Let response be credential.response.") {
          it("If response is not an instance of AuthenticatorAttestationResponse, abort the ceremony with a user-visible error.") {
            val testData = RegistrationTestData.Packed.BasicAttestationEdDsa
            val frob = FinishRegistrationOptions
              .builder()
              .request(testData.request)
            "frob.response(testData.response)" should compile
            "frob.response(testData.assertion.get.response)" shouldNot compile
            frob.response(testData.response).build() should not be null
          }
        }

        describe("4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().") {
          it(
            "The PublicKeyCredential class has a clientExtensionResults field"
          ) {
            val pkc = PublicKeyCredential.parseRegistrationResponseJson("""{
                "type": "public-key",
                "id": "",
                "response": {
                  "attestationObject": "o2NmbXRmcGFja2VkaGF1dGhEYXRhWQFXAU4Ai_91hLmkf2mxjxj_SJrA3qTIOjr6tw1rluqSp_5FAAAAAG1Eupv27C5JuTAMj-kgy3MAEApbxn7DR_LpWJ6yjXeHxIGkAQMDOQEAIFkBAPm_XOU-DioXdG6YXFo5gpHPNxJDimlbnXCro2D_hvzBsxoY4oEzNyRDgK_PoDedZ4tJyk12_I8qJ8g5HqbpT6YUekYegcP4ugL1Omr31gGqTwsF45fIITcSWXcoJbqPnwotbaM98Hu15mSIT8NeXDce0MVNYJ6PULRm6xiiWXHk1cxwrHd9xPCjww6CjRKDc06hP--noBbToW3xx43eh7kGlisWPeU1naIMe7CZAjIMhNlu_uxQssaPAhEXNzDENpK99ieUg290Ym4YNAGbWdW4irkeTt7h_yC-ARrJUu4ygwwGaqCTl9QIMrwZGuiQD11LC0uKraIA2YHaGa2UGKshQwEAAWdhdHRTdG10o2NhbGcmY3NpZ1hHMEUCIQDLKMt6O4aKJkl71VhyIcuI6lqyFTHMDuCO5Y4Jdq2_xQIgPm2_1GF0ivkR816opfVQMWq0s-Hx0uJjcX5l5tm9ZgFjeDVjgVkCwTCCAr0wggGloAMCAQICBCrnYmMwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDcxOTgwNzA3NTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCoDhl5gQ9meEf8QqiVUV4S_Ca-Oax47MhcpIW9VEhqM2RDTmd3HaL3-SnvH49q8YubSRp_1Z1uP-okMynSGnj-jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEG1Eupv27C5JuTAMj-kgy3MwDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAclfQPNzD4RVphJDW-A75W1MHI3PZ5kcyYysR3Nx3iuxr1ZJtB-F7nFQweI3jL05HtFh2_4xVIgKb6Th4eVcjMecncBaCinEbOcdP1sEli9Hk2eVm1XB5A0faUjXAPw_-QLFCjgXG6ReZ5HVUcWkB7riLsFeJNYitiKrTDXFPLy-sNtVNutcQnFsCerDKuM81TvEAigkIbKCGlq8M_NvBg5j83wIxbCYiyV7mIr3RwApHieShzLdJo1S6XydgQjC-_64G5r8C-8AVvNFR3zXXCpio5C3KRIj88HEEIYjf6h1fdLfqeIsq-cUUqbq5T-c4nNoZUZCysTB9v5EY4akp-A",
                  "clientDataJSON": "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogImxaMllKbUZ2YWkteGhYMElteG9fQlk1SkpVdmREa3JXd1ZGZllmcHQtNmciLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vZGVtbzMueXViaWNvLnRlc3Q6ODQ0MyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9"
                },
                "clientExtensionResults": {
                  "appidExclude": true,
                  "org.example.foo": "bar",
                  "credProps": {
                    "rk": false,
                    "authenticatorDisplayName": "My passkey",
                    "unknownProperty": ["unknown-value"]
                  }
                }
              }""")
            pkc.getClientExtensionResults.getExtensionIds should contain(
              "appidExclude"
            )
            pkc.getClientExtensionResults.getExtensionIds should contain(
              "credProps"
            )
            pkc.getClientExtensionResults.getExtensionIds should not contain ("org.example.foo")
          }
        }

        describe("5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.") {
          it("Fails if clientDataJSON is not valid UTF-8.") {
            an[IOException] should be thrownBy new CollectedClientData(
              new ByteArray(Array(-128))
            )
          }
        }

        describe("6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.") {

          it("Fails if clientDataJson is not valid JSON.") {
            an[IOException] should be thrownBy new CollectedClientData(
              new ByteArray("{".getBytes(Charset.forName("UTF-8")))
            )
            an[IOException] should be thrownBy finishRegistration(
              testData = RegistrationTestData.FidoU2f.BasicAttestation
                .copy(clientDataJson = "{")
            )
          }

          it("Succeeds if clientDataJson is valid JSON.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.FidoU2f.BasicAttestation.copy(
                clientDataJson = """{
                    "challenge": "",
                    "origin": "",
                    "type": ""
                  }""",
                overrideRequest =
                  Some(RegistrationTestData.FidoU2f.BasicAttestation.request),
              )
            )
            val step: FinishRegistrationSteps#Step6 = steps.begin

            step.validations shouldBe a[Success[_]]
            step.clientData should not be null
            step.tryNext shouldBe a[Success[_]]
          }
        }

        describe("7. Verify that the value of C.type is webauthn.create.") {
          it("The default test case succeeds.") {
            val steps = finishRegistration(testData =
              RegistrationTestData.FidoU2f.BasicAttestation
            )
            val step: FinishRegistrationSteps#Step7 = steps.begin.next

            step.validations shouldBe a[Success[_]]
          }

          def assertFails(typeString: String): Unit = {
            val steps = finishRegistration(
              testData = RegistrationTestData.FidoU2f.BasicAttestation
                .editClientData("type", typeString)
            )
            val step: FinishRegistrationSteps#Step7 = steps.begin.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
          }

          it("""Any value other than "webauthn.create" fails.""") {
            forAll { (typeString: String) =>
              whenever(typeString != "webauthn.create") {
                assertFails(typeString)
              }
            }
            forAll(Gen.alphaNumStr) { (typeString: String) =>
              whenever(typeString != "webauthn.create") {
                assertFails(typeString)
              }
            }
          }

          it("""The string "webauthn.get" fails.""") {
            assertFails("webauthn.get")
          }
        }

        it("8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.") {
          val steps = finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.copy(
              overrideRequest = Some(
                RegistrationTestData.FidoU2f.BasicAttestation.request.toBuilder
                  .challenge(new ByteArray(Array.fill(16)(0)))
                  .build()
              )
            )
          )
          val step: FinishRegistrationSteps#Step8 = steps.begin.next.next

          step.validations shouldBe a[Failure[_]]
          step.validations.failed.get shouldBe an[IllegalArgumentException]
          step.tryNext shouldBe a[Failure[_]]
        }

        describe("9. Verify that the value of C.origin matches the Relying Party's origin.") {

          def checkAccepted(
              origin: String,
              origins: Option[Set[String]] = None,
              allowOriginPort: Boolean = false,
              allowOriginSubdomain: Boolean = false,
          ): Unit = {
            val steps = finishRegistration(
              testData = RegistrationTestData.FidoU2f.BasicAttestation
                .editClientData("origin", origin),
              origins = origins,
              allowOriginPort = allowOriginPort,
              allowOriginSubdomain = allowOriginSubdomain,
            )
            val step: FinishRegistrationSteps#Step9 = steps.begin.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          def checkRejected(
              origin: String,
              origins: Option[Set[String]] = None,
              allowOriginPort: Boolean = false,
              allowOriginSubdomain: Boolean = false,
          ): Unit = {
            val steps = finishRegistration(
              testData = RegistrationTestData.FidoU2f.BasicAttestation
                .editClientData("origin", origin),
              origins = origins,
              allowOriginPort = allowOriginPort,
              allowOriginSubdomain = allowOriginSubdomain,
            )
            val step: FinishRegistrationSteps#Step9 = steps.begin.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("Fails if origin is different.") {
            checkRejected(origin = "https://root.evil")
          }

          describe("Explicit ports are") {
            val origin = "https://localhost:8080"
            it("by default not allowed.") {
              checkRejected(origin = origin)
            }

            it("allowed if RP opts in to it.") {
              checkAccepted(origin = origin, allowOriginPort = true)
            }
          }

          describe("Subdomains are") {
            val origin = "https://foo.localhost"

            it("by default not allowed.") {
              checkRejected(origin = origin)
            }

            it("allowed if RP opts in to it.") {
              checkAccepted(origin = origin, allowOriginSubdomain = true)
            }
          }

          describe("Subdomains and explicit ports at the same time are") {
            val origin = "https://foo.localhost:8080"

            it("by default not allowed.") {
              checkRejected(origin = origin)
            }

            it("not allowed if only subdomains are allowed.") {
              checkRejected(
                origin = origin,
                allowOriginPort = false,
                allowOriginSubdomain = true,
              )
            }

            it("not allowed if only explicit ports are allowed.") {
              checkRejected(
                origin = origin,
                allowOriginPort = true,
                allowOriginSubdomain = false,
              )
            }

            it("allowed if RP opts in to both.") {
              checkAccepted(
                origin = origin,
                allowOriginPort = true,
                allowOriginSubdomain = true,
              )
            }
          }

          describe("The examples in JavaDoc are correct:") {
            def check(
                origins: Set[String],
                acceptOrigins: Iterable[String],
                rejectOrigins: Iterable[String],
                allowOriginPort: Boolean = false,
                allowOriginSubdomain: Boolean = false,
            ): Unit = {
              for { origin <- acceptOrigins } {
                it(s"${origin} is accepted.") {
                  checkAccepted(
                    origin = origin,
                    origins = Some(origins),
                    allowOriginPort = allowOriginPort,
                    allowOriginSubdomain = allowOriginSubdomain,
                  )
                }
              }

              for { origin <- rejectOrigins } {
                it(s"${origin} is rejected.") {
                  checkRejected(
                    origin = origin,
                    origins = Some(origins),
                    allowOriginPort = allowOriginPort,
                    allowOriginSubdomain = allowOriginSubdomain,
                  )
                }
              }
            }

            describe("For allowOriginPort:") {
              val origins = Set(
                "https://example.org",
                "https://accounts.example.org",
                "https://acme.com:8443",
              )

              describe("false,") {
                check(
                  origins = origins,
                  acceptOrigins = List(
                    "https://example.org",
                    "https://accounts.example.org",
                    "https://acme.com:8443",
                  ),
                  rejectOrigins = List(
                    "https://example.org:8443",
                    "https://shop.example.org",
                    "https://acme.com",
                    "https://acme.com:9000",
                  ),
                  allowOriginPort = false,
                )
              }

              describe("true,") {
                check(
                  origins = origins,
                  acceptOrigins = List(
                    "https://example.org",
                    "https://example.org:8443",
                    "https://accounts.example.org",
                    "https://acme.com",
                    "https://acme.com:8443",
                    "https://acme.com:9000",
                  ),
                  rejectOrigins = List(
                    "https://shop.example.org"
                  ),
                  allowOriginPort = true,
                )
              }
            }

            describe("For allowOriginSubdomain:") {
              val origins = Set("https://example.org", "https://acme.com:8443")

              describe("false,") {
                check(
                  origins = origins,
                  acceptOrigins = List(
                    "https://example.org",
                    "https://acme.com:8443",
                  ),
                  rejectOrigins = List(
                    "https://example.org:8443",
                    "https://accounts.example.org",
                    "https://acme.com",
                    "https://shop.acme.com:8443",
                  ),
                  allowOriginSubdomain = false,
                )
              }

              describe("true,") {
                check(
                  origins = origins,
                  acceptOrigins = List(
                    "https://example.org",
                    "https://accounts.example.org",
                    "https://acme.com:8443",
                    "https://shop.acme.com:8443",
                  ),
                  rejectOrigins = List(
                    "https://example.org:8443",
                    "https://acme.com",
                  ),
                  allowOriginSubdomain = true,
                )
              }
            }
          }
        }

        describe("10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained.") {
          it("Verification succeeds if neither side uses token binding ID.") {
            val steps = finishRegistration(testData =
              RegistrationTestData.FidoU2f.BasicAttestation
            )
            val step: FinishRegistrationSteps#Step10 =
              steps.begin.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Verification succeeds if client data specifies token binding is unsupported, and RP does not use it.") {
            val steps = finishRegistration(testData =
              RegistrationTestData.FidoU2f.BasicAttestation
                .editClientData(_.without[ObjectNode]("tokenBinding"))
            )
            val step: FinishRegistrationSteps#Step10 =
              steps.begin.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Verification succeeds if client data specifies token binding is supported, and RP does not use it.") {
            val steps = finishRegistration(testData =
              RegistrationTestData.FidoU2f.BasicAttestation
                .editClientData(
                  "tokenBinding",
                  toJson(Map("status" -> "supported")),
                )
            )
            val step: FinishRegistrationSteps#Step10 =
              steps.begin.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Verification fails if client data does not specify token binding status and RP specifies token binding ID.") {
            val steps = finishRegistration(
              callerTokenBindingId =
                Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
              testData = RegistrationTestData.FidoU2f.BasicAttestation
                .editClientData(_.without[ObjectNode]("tokenBinding")),
            )
            val step: FinishRegistrationSteps#Step10 =
              steps.begin.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("Verification succeeds if client data does not specify token binding status and RP does not specify token binding ID.") {
            val steps = finishRegistration(
              callerTokenBindingId = None,
              testData = RegistrationTestData.FidoU2f.BasicAttestation
                .editClientData(_.without[ObjectNode]("tokenBinding")),
            )
            val step: FinishRegistrationSteps#Step10 =
              steps.begin.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Verification fails if client data specifies token binding ID but RP does not.") {
            val steps = finishRegistration(
              callerTokenBindingId = None,
              testData =
                RegistrationTestData.FidoU2f.BasicAttestation.editClientData(
                  "tokenBinding",
                  toJson(Map("status" -> "present", "id" -> "YELLOWSUBMARINE")),
                ),
            )
            val step: FinishRegistrationSteps#Step10 =
              steps.begin.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          describe("If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.") {
            it("Verification succeeds if both sides specify the same token binding ID.") {
              val steps = finishRegistration(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
                testData =
                  RegistrationTestData.FidoU2f.BasicAttestation.editClientData(
                    "tokenBinding",
                    toJson(
                      Map("status" -> "present", "id" -> "YELLOWSUBMARINE")
                    ),
                  ),
              )
              val step: FinishRegistrationSteps#Step10 =
                steps.begin.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }

            it("Verification fails if ID is missing from tokenBinding in client data.") {
              val steps = finishRegistration(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
                testData =
                  RegistrationTestData.FidoU2f.BasicAttestation.editClientData(
                    "tokenBinding",
                    toJson(Map("status" -> "present")),
                  ),
              )
              val step: FinishRegistrationSteps#Step10 =
                steps.begin.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Verification fails if RP specifies token binding ID but client does not support it.") {
              val steps = finishRegistration(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
                testData = RegistrationTestData.FidoU2f.BasicAttestation
                  .editClientData(_.without[ObjectNode]("tokenBinding")),
              )
              val step: FinishRegistrationSteps#Step10 =
                steps.begin.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Verification fails if RP specifies token binding ID but client does not use it.") {
              val steps = finishRegistration(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
                testData =
                  RegistrationTestData.FidoU2f.BasicAttestation.editClientData(
                    "tokenBinding",
                    toJson(Map("status" -> "supported")),
                  ),
              )
              val step: FinishRegistrationSteps#Step10 =
                steps.begin.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Verification fails if client data and RP specify different token binding IDs.") {
              val steps = finishRegistration(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("ORANGESUBMARINE")),
                testData =
                  RegistrationTestData.FidoU2f.BasicAttestation.editClientData(
                    "tokenBinding",
                    toJson(
                      Map("status" -> "supported", "id" -> "YELLOWSUBMARINE")
                    ),
                  ),
              )
              val step: FinishRegistrationSteps#Step10 =
                steps.begin.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }
          }
        }

        it("11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.") {
          val steps = finishRegistration(testData =
            RegistrationTestData.FidoU2f.BasicAttestation
          )
          val step: FinishRegistrationSteps#Step11 =
            steps.begin.next.next.next.next.next
          val digest = MessageDigest.getInstance("SHA-256")

          step.validations shouldBe a[Success[_]]
          step.tryNext shouldBe a[Success[_]]
          step.clientDataJsonHash should equal(
            new ByteArray(
              digest.digest(
                RegistrationTestData.FidoU2f.BasicAttestation.clientDataJsonBytes.getBytes
              )
            )
          )
        }

        it("12. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.") {
          val steps = finishRegistration(testData =
            RegistrationTestData.FidoU2f.BasicAttestation
          )
          val step: FinishRegistrationSteps#Step12 =
            steps.begin.next.next.next.next.next.next

          step.validations shouldBe a[Success[_]]
          step.tryNext shouldBe a[Success[_]]
          step.attestation.getFormat should equal("fido-u2f")
          step.attestation.getAuthenticatorData should not be null
          step.attestation.getAttestationStatement should not be null
        }

        describe("13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.") {
          it("Fails if RP ID is different.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.FidoU2f.BasicAttestation
                .editAuthenticatorData { authData: ByteArray =>
                  new ByteArray(
                    Array.fill[Byte](32)(0) ++ authData.getBytes.drop(32)
                  )
                }
            )
            val step: FinishRegistrationSteps#Step13 =
              steps.begin.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("Succeeds if RP ID is the same.") {
            val steps = finishRegistration(testData =
              RegistrationTestData.FidoU2f.BasicAttestation
            )
            val step: FinishRegistrationSteps#Step13 =
              steps.begin.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }
        }

        {
          val testData = RegistrationTestData.Packed.BasicAttestation

          def upOn(authData: ByteArray): ByteArray =
            new ByteArray(
              authData.getBytes
                .updated(32, (authData.getBytes()(32) | 0x01).toByte)
            )

          def upOff(authData: ByteArray): ByteArray =
            new ByteArray(
              authData.getBytes
                .updated(32, (authData.getBytes()(32) & 0xfe).toByte)
            )

          def uvOn(authData: ByteArray): ByteArray =
            new ByteArray(
              authData.getBytes
                .updated(32, (authData.getBytes()(32) | 0x04).toByte)
            )

          def uvOff(authData: ByteArray): ByteArray =
            new ByteArray(
              authData.getBytes
                .updated(32, (authData.getBytes()(32) & 0xfb).toByte)
            )

          def checks[Next <: FinishRegistrationSteps.Step[
            _
          ], Step <: FinishRegistrationSteps.Step[Next]](
              stepsToStep: FinishRegistrationSteps => Step
          ) = {
            def check[B](
                stepsToStep: FinishRegistrationSteps => Step
            )(chk: Step => B)(
                uvr: UserVerificationRequirement,
                authDataEdit: ByteArray => ByteArray,
            ): B = {
              val steps = finishRegistration(
                testData = testData
                  .copy(
                    authenticatorSelection = Some(
                      AuthenticatorSelectionCriteria
                        .builder()
                        .userVerification(uvr)
                        .build()
                    )
                  )
                  .editAuthenticatorData(authDataEdit)
              )
              chk(stepsToStep(steps))
            }

            def checkFailsWith(
                stepsToStep: FinishRegistrationSteps => Step
            ): (UserVerificationRequirement, ByteArray => ByteArray) => Unit =
              check(stepsToStep) { step =>
                step.validations shouldBe a[Failure[_]]
                step.validations.failed.get shouldBe an[
                  IllegalArgumentException
                ]
                step.tryNext shouldBe a[Failure[_]]
              }

            def checkSucceedsWith(
                stepsToStep: FinishRegistrationSteps => Step
            ): (UserVerificationRequirement, ByteArray => ByteArray) => Unit =
              check(stepsToStep) { step =>
                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]
              }

            (checkFailsWith(stepsToStep), checkSucceedsWith(stepsToStep))
          }

          describe("14. Verify that the User Present bit of the flags in authData is set.") {
            val (checkFails, checkSucceeds) = checks[
              FinishRegistrationSteps#Step15,
              FinishRegistrationSteps#Step14,
            ](_.begin.next.next.next.next.next.next.next.next)

            it("Fails if UV is discouraged and flag is not set.") {
              checkFails(UserVerificationRequirement.DISCOURAGED, upOff)
            }

            it("Succeeds if UV is discouraged and flag is set.") {
              checkSucceeds(UserVerificationRequirement.DISCOURAGED, upOn)
            }

            it("Fails if UV is preferred and flag is not set.") {
              checkFails(UserVerificationRequirement.PREFERRED, upOff)
            }

            it("Succeeds if UV is preferred and flag is set.") {
              checkSucceeds(UserVerificationRequirement.PREFERRED, upOn)
            }

            it("Fails if UV is required and flag is not set.") {
              checkFails(
                UserVerificationRequirement.REQUIRED,
                upOff _ andThen uvOn,
              )
            }

            it("Succeeds if UV is required and flag is set.") {
              checkSucceeds(
                UserVerificationRequirement.REQUIRED,
                upOn _ andThen uvOn,
              )
            }
          }

          describe("15. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.") {
            val (checkFails, checkSucceeds) = checks[
              FinishRegistrationSteps#Step16,
              FinishRegistrationSteps#Step15,
            ](_.begin.next.next.next.next.next.next.next.next.next)

            it("Succeeds if UV is discouraged and flag is not set.") {
              checkSucceeds(UserVerificationRequirement.DISCOURAGED, uvOff)
            }

            it("Succeeds if UV is discouraged and flag is set.") {
              checkSucceeds(UserVerificationRequirement.DISCOURAGED, uvOn)
            }

            it("Succeeds if UV is preferred and flag is not set.") {
              checkSucceeds(UserVerificationRequirement.PREFERRED, uvOff)
            }

            it("Succeeds if UV is preferred and flag is set.") {
              checkSucceeds(UserVerificationRequirement.PREFERRED, uvOn)
            }

            it("Fails if UV is required and flag is not set.") {
              checkFails(UserVerificationRequirement.REQUIRED, uvOff)
            }

            it("Succeeds if UV is required and flag is set.") {
              checkSucceeds(UserVerificationRequirement.REQUIRED, uvOn)
            }
          }
        }

        describe("16. Verify that the \"alg\" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.") {
          it("An ES256 key succeeds if ES256 was a requested algorithm.") {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation
            val result = finishRegistration(
              testData = testData,
              credentialRepository = Helpers.CredentialRepository.empty,
              allowUntrustedAttestation = true,
            ).run

            result should not be null
            result.getPublicKeyCose should not be null
          }

          it("An ES256 key fails if only RSA and EdDSA are allowed.") {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation
            val result = Try(
              finishRegistration(
                testData = testData.copy(
                  overrideRequest = Some(
                    testData.request.toBuilder
                      .pubKeyCredParams(
                        List(
                          PublicKeyCredentialParameters.EdDSA,
                          PublicKeyCredentialParameters.RS256,
                        ).asJava
                      )
                      .build()
                  )
                ),
                credentialRepository = Helpers.CredentialRepository.empty,
                allowUntrustedAttestation = true,
              ).run
            )

            result shouldBe a[Failure[_]]
            result.failed.get shouldBe an[IllegalArgumentException]
          }
        }

        describe("17. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          it("Succeeds if clientExtensionResults is a subset of the extensions requested by the Relying Party.") {
            forAll(Extensions.subsetRegistrationExtensions) {
              case (extensionInputs, clientExtensionOutputs, _) =>
                val steps = finishRegistration(
                  testData = RegistrationTestData.Packed.BasicAttestation.copy(
                    requestedExtensions = extensionInputs,
                    clientExtensionResults = clientExtensionOutputs,
                  )
                )
                val stepAfter: Try[FinishRegistrationSteps#Step18] =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.tryNext

                stepAfter shouldBe a[Success[_]]
            }
          }

          it("Succeeds if clientExtensionResults is not a subset of the extensions requested by the Relying Party.") {
            forAll(Extensions.unrequestedClientRegistrationExtensions) {
              case (extensionInputs, clientExtensionOutputs, _) =>
                val steps = finishRegistration(
                  testData = RegistrationTestData.Packed.BasicAttestation.copy(
                    requestedExtensions = extensionInputs,
                    clientExtensionResults = clientExtensionOutputs,
                  )
                )
                val stepAfter: Try[FinishRegistrationSteps#Step18] =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.tryNext

                stepAfter shouldBe a[Success[_]]
            }
          }

          it("Succeeds if authenticator extensions is a subset of the extensions requested by the Relying Party.") {
            forAll(Extensions.subsetRegistrationExtensions) {
              case (
                    extensionInputs: RegistrationExtensionInputs,
                    _,
                    authenticatorExtensionOutputs: CBORObject,
                  ) =>
                val steps = finishRegistration(
                  testData = RegistrationTestData.Packed.BasicAttestation
                    .copy(
                      requestedExtensions = extensionInputs
                    )
                    .editAuthenticatorData(authData =>
                      new ByteArray(
                        authData.getBytes.updated(
                          32,
                          (authData.getBytes()(32) | 0x80).toByte,
                        ) ++ authenticatorExtensionOutputs.EncodeToBytes()
                      )
                    )
                )
                val stepAfter: Try[FinishRegistrationSteps#Step18] =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.tryNext

                stepAfter shouldBe a[Success[_]]
            }
          }

          it("Succeeds if authenticator extensions is not a subset of the extensions requested by the Relying Party.") {
            forAll(
              Extensions.unrequestedAuthenticatorRegistrationExtensions
            ) {
              case (
                    extensionInputs: RegistrationExtensionInputs,
                    _,
                    authenticatorExtensionOutputs: CBORObject,
                  ) =>
                val steps = finishRegistration(
                  testData = RegistrationTestData.Packed.BasicAttestation
                    .copy(
                      requestedExtensions = extensionInputs
                    )
                    .editAuthenticatorData(authData =>
                      new ByteArray(
                        authData.getBytes.updated(
                          32,
                          (authData.getBytes()(32) | 0x80).toByte,
                        ) ++ authenticatorExtensionOutputs.EncodeToBytes()
                      )
                    )
                )
                val stepAfter: Try[FinishRegistrationSteps#Step18] =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.tryNext

                stepAfter shouldBe a[Success[_]]
            }
          }
        }

        describe("18. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA \"WebAuthn Attestation Statement Format Identifiers\" registry established by RFC8809.") {
          def setup(format: String): FinishRegistrationSteps = {
            finishRegistration(
              testData = RegistrationTestData.FidoU2f.BasicAttestation
                .setAttestationStatementFormat(format)
            )
          }

          def checkUnknown(format: String): Unit = {
            it(s"""Returns no known attestation statement verifier if fmt is "${format}".""") {
              val steps = setup(format)
              val step: FinishRegistrationSteps#Step18 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
              step.format should equal(format)
              step.attestationStatementVerifier.toScala shouldBe empty
            }
          }

          def checkKnown(format: String): Unit = {
            it(s"""Returns a known attestation statement verifier if fmt is "${format}".""") {
              val steps = setup(format)
              val step: FinishRegistrationSteps#Step18 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
              step.format should equal(format)
              step.attestationStatementVerifier.toScala should not be empty
            }
          }

          checkKnown("android-safetynet")
          checkKnown("fido-u2f")
          checkKnown("none")
          checkKnown("packed")
          checkKnown("tpm")

          checkUnknown("android-key")

          checkUnknown("FIDO-U2F")
          checkUnknown("Fido-U2F")
          checkUnknown("bleurgh")
        }

        describe("19. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.") {

          describe("If allowUntrustedAttestation is set,") {
            it("a fido-u2f attestation is still rejected if invalid.") {
              val testData = RegistrationTestData.FidoU2f.BasicAttestation
                .updateAttestationObject(
                  "attStmt",
                  { attStmtNode: JsonNode =>
                    attStmtNode
                      .asInstanceOf[ObjectNode]
                      .set[ObjectNode](
                        "sig",
                        jsonFactory.binaryNode(Array(0, 0, 0, 0)),
                      )
                  },
                )
              val steps = finishRegistration(
                testData = testData,
                allowUntrustedAttestation = true,
              )
              val step: FinishRegistrationSteps#Step19 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get.getCause shouldBe a[
                SignatureException
              ]
              step.tryNext shouldBe a[Failure[_]]
            }
          }

          describe("For the fido-u2f statement format,") {
            it("the default test case is a valid basic attestation.") {
              val steps = finishRegistration(testData =
                RegistrationTestData.FidoU2f.BasicAttestation
              )
              val step: FinishRegistrationSteps#Step19 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.attestationType should equal(AttestationType.BASIC)
              step.tryNext shouldBe a[Success[_]]
            }

            it("a test case with self attestation is valid.") {
              val steps = finishRegistration(testData =
                RegistrationTestData.FidoU2f.SelfAttestation
              )
              val step: FinishRegistrationSteps#Step19 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.attestationType should equal(
                AttestationType.SELF_ATTESTATION
              )
              step.tryNext shouldBe a[Success[_]]
            }

            it("a test case with different signed client data is not valid.") {
              val testData = RegistrationTestData.FidoU2f.SelfAttestation
              val steps = finishRegistration(testData =
                RegistrationTestData.FidoU2f.BasicAttestation
              )
              val step: FinishRegistrationSteps#Step19 = new steps.Step19(
                Crypto.sha256(
                  new ByteArray(
                    testData.clientDataJsonBytes.getBytes.updated(
                      20,
                      (testData.clientDataJsonBytes.getBytes()(20) + 1).toByte,
                    )
                  )
                ),
                new AttestationObject(testData.attestationObject),
                Optional.of(new FidoU2fAttestationStatementVerifier),
              )

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            def checkByteFlipFails(index: Int): Unit = {
              val testData = RegistrationTestData.FidoU2f.BasicAttestation
                .editAuthenticatorData {
                  flipByte(index, _)
                }

              val steps = finishRegistration(testData = testData)
              val step: FinishRegistrationSteps#Step19 = new steps.Step19(
                Crypto.sha256(testData.clientDataJsonBytes),
                new AttestationObject(testData.attestationObject),
                Optional.of(new FidoU2fAttestationStatementVerifier),
              )

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("a test case with a different signed RP ID hash is not valid.") {
              checkByteFlipFails(0)
            }

            it(
              "a test case with a different signed credential ID is not valid."
            ) {
              checkByteFlipFails(32 + 1 + 4 + 16 + 2 + 1)
            }

            it("a test case with a different signed credential public key is not valid.") {
              val testData = RegistrationTestData.FidoU2f.BasicAttestation
                .editAuthenticatorData { authenticatorData =>
                  val decoded = new AuthenticatorData(authenticatorData)
                  val L =
                    decoded.getAttestedCredentialData.get.getCredentialId.getBytes.length
                  val evilPublicKey: ByteArray =
                    WebAuthnTestCodecs.publicKeyToCose(
                      TestAuthenticator
                        .generateKeypair(
                          COSEAlgorithmIdentifier
                            .fromPublicKey(
                              decoded.getAttestedCredentialData.get.getCredentialPublicKey
                            )
                            .get
                        )
                        .getPublic
                    )

                  new ByteArray(
                    authenticatorData.getBytes.take(
                      32 + 1 + 4 + 16 + 2 + L
                    ) ++ evilPublicKey.getBytes
                  )
                }
              val steps = finishRegistration(testData = testData)
              val step: FinishRegistrationSteps#Step19 = new steps.Step19(
                Crypto.sha256(testData.clientDataJsonBytes),
                new AttestationObject(testData.attestationObject),
                Optional.of(new FidoU2fAttestationStatementVerifier),
              )

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            describe("if x5c is not a certificate for an ECDSA public key over the P-256 curve, stop verification and return an error.") {
              val testAuthenticator = TestAuthenticator

              def checkRejected(
                  attestationAlg: COSEAlgorithmIdentifier,
                  keypair: KeyPair,
              ): Unit = {
                val (credential, _, _) = testAuthenticator
                  .createBasicAttestedCredential(attestationMaker =
                    AttestationMaker.fidoU2f(
                      new AttestationCert(
                        attestationAlg,
                        testAuthenticator.generateAttestationCertificate(
                          attestationAlg,
                          Some(keypair),
                        ),
                      )
                    )
                  )

                val steps = finishRegistration(
                  testData = RegistrationTestData(
                    alg = COSEAlgorithmIdentifier.ES256,
                    attestationObject =
                      credential.getResponse.getAttestationObject,
                    clientDataJson = new String(
                      credential.getResponse.getClientDataJSON.getBytes,
                      "UTF-8",
                    ),
                  )
                )
                val step: FinishRegistrationSteps#Step19 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

                val standaloneVerification = Try {
                  new FidoU2fAttestationStatementVerifier()
                    .verifyAttestationSignature(
                      credential.getResponse.getAttestation,
                      Crypto.sha256(credential.getResponse.getClientDataJSON),
                    )
                }

                step.validations shouldBe a[Failure[_]]
                step.validations.failed.get shouldBe an[
                  IllegalArgumentException
                ]
                step.tryNext shouldBe a[Failure[_]]

                standaloneVerification shouldBe a[Failure[_]]
                standaloneVerification.failed.get shouldBe an[
                  IllegalArgumentException
                ]
              }

              def checkAccepted(
                  attestationAlg: COSEAlgorithmIdentifier,
                  keypair: KeyPair,
              ): Unit = {
                val (credential, _, _) = testAuthenticator
                  .createBasicAttestedCredential(attestationMaker =
                    AttestationMaker.fidoU2f(
                      new AttestationCert(
                        attestationAlg,
                        testAuthenticator.generateAttestationCertificate(
                          attestationAlg,
                          Some(keypair),
                        ),
                      )
                    )
                  )

                val steps = finishRegistration(
                  testData = RegistrationTestData(
                    alg = COSEAlgorithmIdentifier.ES256,
                    attestationObject =
                      credential.getResponse.getAttestationObject,
                    clientDataJson = new String(
                      credential.getResponse.getClientDataJSON.getBytes,
                      "UTF-8",
                    ),
                  )
                )
                val step: FinishRegistrationSteps#Step19 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

                val standaloneVerification = Try {
                  new FidoU2fAttestationStatementVerifier()
                    .verifyAttestationSignature(
                      credential.getResponse.getAttestation,
                      Crypto.sha256(credential.getResponse.getClientDataJSON),
                    )
                }

                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]

                standaloneVerification should equal(Success(true))
              }

              it("An RSA attestation certificate is rejected.") {
                checkRejected(
                  COSEAlgorithmIdentifier.RS256,
                  testAuthenticator.generateRsaKeypair(),
                )
              }

              it("A secp256r1 attestation certificate is accepted.") {
                checkAccepted(
                  COSEAlgorithmIdentifier.ES256,
                  testAuthenticator.generateEcKeypair(curve = "secp256r1"),
                )
              }

              it("A secp256k1 attestation certificate is rejected.") {
                checkRejected(
                  COSEAlgorithmIdentifier.ES256,
                  testAuthenticator.generateEcKeypair(curve = "secp256k1"),
                )
              }
            }
          }

          describe("For the none statement format,") {
            def flipByte(index: Int, bytes: ByteArray): ByteArray =
              new ByteArray(
                bytes.getBytes
                  .updated(index, (0xff ^ bytes.getBytes()(index)).toByte)
              )

            def checkByteFlipSucceeds(
                mutationDescription: String,
                index: Int,
            ): Unit = {
              it(s"the default test case with mutated ${mutationDescription} is accepted.") {
                val testData = RegistrationTestData.NoneAttestation.Default
                  .editAuthenticatorData {
                    flipByte(index, _)
                  }

                val steps = finishRegistration(testData = testData)
                val step: FinishRegistrationSteps#Step19 = new steps.Step19(
                  Crypto.sha256(testData.clientDataJsonBytes),
                  new AttestationObject(testData.attestationObject),
                  Optional.of(new NoneAttestationStatementVerifier),
                )

                step.validations shouldBe a[Success[_]]
                step.attestationType should equal(AttestationType.NONE)
                step.tryNext shouldBe a[Success[_]]
              }
            }

            it("the default test case is accepted.") {
              val steps = finishRegistration(testData =
                RegistrationTestData.NoneAttestation.Default
              )
              val step: FinishRegistrationSteps#Step19 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.attestationType should equal(AttestationType.NONE)
              step.tryNext shouldBe a[Success[_]]
            }

            checkByteFlipSucceeds("signature counter", 32 + 1)
            checkByteFlipSucceeds("AAGUID", 32 + 1 + 4)
            checkByteFlipSucceeds("credential ID", 32 + 1 + 4 + 16 + 2)
          }

          describe("For the packed statement format") {
            val verifier = new PackedAttestationStatementVerifier

            it("the attestation statement verifier implementation is PackedAttestationStatementVerifier.") {
              val steps = finishRegistration(testData =
                RegistrationTestData.Packed.BasicAttestation
              )
              val step: FinishRegistrationSteps#Step19 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

              step.getAttestationStatementVerifier.get shouldBe a[
                PackedAttestationStatementVerifier
              ]
            }

            describe("the verification procedure is:") {
              describe("1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.") {

                it("Fails if attStmt.sig is a text value.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation
                    .editAttestationObject(
                      "attStmt",
                      jsonFactory
                        .objectNode()
                        .set("sig", jsonFactory.textNode("foo")),
                    )

                  val result: Try[Boolean] = Try(
                    verifier.verifyAttestationSignature(
                      new AttestationObject(testData.attestationObject),
                      testData.clientDataJsonHash,
                    )
                  )

                  result shouldBe a[Failure[_]]
                  result.failed.get shouldBe an[IllegalArgumentException]
                }

                it("Fails if attStmt.sig is missing.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation
                    .editAttestationObject(
                      "attStmt",
                      jsonFactory
                        .objectNode()
                        .set("x5c", jsonFactory.arrayNode()),
                    )

                  val result: Try[Boolean] = Try(
                    verifier.verifyAttestationSignature(
                      new AttestationObject(testData.attestationObject),
                      testData.clientDataJsonHash,
                    )
                  )

                  result shouldBe a[Failure[_]]
                  result.failed.get shouldBe an[IllegalArgumentException]
                }
              }

              describe("2. If x5c is present:") {
                it("The attestation type is identified as Basic.") {
                  val steps = finishRegistration(testData =
                    RegistrationTestData.Packed.BasicAttestation
                  )
                  val step: FinishRegistrationSteps#Step19 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                  step.attestationType should be(AttestationType.BASIC)
                }

                describe("1. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.") {
                  it("Succeeds for the default test case.") {
                    val testData = RegistrationTestData.Packed.BasicAttestation
                    val result: Try[Boolean] = Try(
                      verifier.verifyAttestationSignature(
                        new AttestationObject(testData.attestationObject),
                        testData.clientDataJsonHash,
                      )
                    )
                    result should equal(Success(true))
                  }

                  it("Succeeds for an RS1 test case.") {
                    val testData =
                      RegistrationTestData.Packed.BasicAttestationRs1

                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testData.attestationObject),
                      testData.clientDataJsonHash,
                    )
                    result should equal(true)
                  }

                  it("Fail if the default test case is mutated.") {
                    val testData = RegistrationTestData.Packed.BasicAttestation

                    val result: Try[Boolean] = Try(
                      verifier.verifyAttestationSignature(
                        new AttestationObject(
                          testData
                            .editAuthenticatorData({ authData: ByteArray =>
                              new ByteArray(
                                authData.getBytes.updated(
                                  16,
                                  if (authData.getBytes()(16) == 0) 1: Byte
                                  else 0: Byte,
                                )
                              )
                            })
                            .attestationObject
                        ),
                        testData.clientDataJsonHash,
                      )
                    )
                    result should equal(Success(false))
                  }
                }

                describe("2. Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation Statement Certificate Requirements.") {
                  it("Fails for an attestation signature with an invalid country code.") {
                    val authenticator = TestAuthenticator
                    val alg = COSEAlgorithmIdentifier.ES256
                    val (badCert, key): (X509Certificate, PrivateKey) =
                      authenticator.generateAttestationCertificate(
                        alg = alg,
                        name = new X500Name(
                          "O=Yubico, C=AA, OU=Authenticator Attestation"
                        ),
                      )
                    val (credential, _, _) =
                      authenticator.createBasicAttestedCredential(
                        attestationMaker = AttestationMaker.packed(
                          new AttestationCert(alg, (badCert, key))
                        )
                      )
                    val result = Try(
                      verifier.verifyAttestationSignature(
                        credential.getResponse.getAttestation,
                        sha256(credential.getResponse.getClientDataJSON),
                      )
                    )

                    result shouldBe a[Failure[_]]
                    result.failed.get shouldBe an[IllegalArgumentException]
                  }

                  it("succeeds for the default test case.") {
                    val testData = RegistrationTestData.Packed.BasicAttestation
                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testData.attestationObject),
                      testData.clientDataJsonHash,
                    )
                    result should equal(true)
                  }
                }

                describe("3. If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.") {
                  it("Succeeds for the default test case.") {
                    val testData = RegistrationTestData.Packed.BasicAttestation
                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testData.attestationObject),
                      testData.clientDataJsonHash,
                    )

                    testData.packedAttestationCert.getNonCriticalExtensionOIDs.asScala should equal(
                      Set("1.3.6.1.4.1.45724.1.1.4")
                    )
                    result should equal(true)
                  }

                  it("Succeeds if the attestation certificate does not have the extension.") {
                    val testData =
                      RegistrationTestData.Packed.BasicAttestationWithoutAaguidExtension

                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testData.attestationObject),
                      testData.clientDataJsonHash,
                    )

                    testData.packedAttestationCert.getNonCriticalExtensionOIDs shouldBe null
                    result should equal(true)
                  }

                  it("Fails if the attestation certificate has the extension and it does not match the AAGUID.") {
                    val testData =
                      RegistrationTestData.Packed.BasicAttestationWithWrongAaguidExtension

                    val result = Try(
                      verifier.verifyAttestationSignature(
                        new AttestationObject(testData.attestationObject),
                        testData.clientDataJsonHash,
                      )
                    )

                    testData.packedAttestationCert.getNonCriticalExtensionOIDs should not be empty
                    result shouldBe a[Failure[_]]
                    result.failed.get shouldBe an[IllegalArgumentException]
                  }
                }

                describe("4. Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.") {
                  it("Nothing to test.") {}
                }

                it("5. If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation
                  val steps = finishRegistration(testData = testData)
                  val step: FinishRegistrationSteps#Step19 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                  step.attestationType should be(AttestationType.BASIC)
                  step.attestationTrustPath.toScala should not be empty
                  step.attestationTrustPath.get.asScala should be(
                    List(testData.packedAttestationCert)
                  )
                }
              }

              describe(
                "3. If x5c is not present, self attestation is in use."
              ) {
                val testDataBase = RegistrationTestData.Packed.SelfAttestation

                it("The attestation type is identified as SelfAttestation.") {
                  val steps = finishRegistration(testData = testDataBase)
                  val step: FinishRegistrationSteps#Step19 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                  step.attestationType should be(
                    AttestationType.SELF_ATTESTATION
                  )
                }

                describe("1. Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.") {
                  it("Succeeds for the default test case.") {
                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testDataBase.attestationObject),
                      testDataBase.clientDataJsonHash,
                    )

                    CBORObject
                      .DecodeFromBytes(
                        new AttestationObject(
                          testDataBase.attestationObject
                        ).getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey.getBytes
                      )
                      .get(CBORObject.FromObject(3))
                      .AsInt64Value should equal(-7)
                    new AttestationObject(
                      testDataBase.attestationObject
                    ).getAttestationStatement.get("alg").longValue should equal(
                      -7
                    )
                    result should equal(true)
                  }

                  it("Fails if the alg is a different value.") {
                    def modifyAuthdataPubkeyAlg(authDataBytes: Array[Byte])
                        : Array[Byte] = {
                      val authData =
                        new AuthenticatorData(new ByteArray(authDataBytes))
                      val key = WebAuthnCodecs
                        .importCosePublicKey(
                          authData.getAttestedCredentialData.get.getCredentialPublicKey
                        )
                        .asInstanceOf[RSAPublicKey]
                      val reencodedKey = WebAuthnTestCodecs.rsaPublicKeyToCose(
                        key,
                        COSEAlgorithmIdentifier.RS256,
                      )
                      new ByteArray(
                        java.util.Arrays.copyOfRange(
                          authDataBytes,
                          0,
                          32 + 1 + 4 + 16 + 2,
                        )
                      )
                        .concat(
                          authData.getAttestedCredentialData.get.getCredentialId
                        )
                        .concat(reencodedKey)
                        .getBytes
                    }

                    def modifyAttobjPubkeyAlg(attObjBytes: ByteArray)
                        : ByteArray = {
                      val attObj =
                        JacksonCodecs.cbor.readTree(attObjBytes.getBytes)
                      new ByteArray(
                        JacksonCodecs.cbor.writeValueAsBytes(
                          attObj
                            .asInstanceOf[ObjectNode]
                            .set(
                              "authData",
                              jsonFactory.binaryNode(
                                modifyAuthdataPubkeyAlg(
                                  attObj.get("authData").binaryValue()
                                )
                              ),
                            )
                        )
                      )
                    }

                    val testData =
                      RegistrationTestData.Packed.SelfAttestationRs1
                    val attObj = new AttestationObject(
                      modifyAttobjPubkeyAlg(
                        testData.response.getResponse.getAttestationObject
                      )
                    )

                    val result = Try(
                      verifier.verifyAttestationSignature(
                        attObj,
                        testData.clientDataJsonHash,
                      )
                    )

                    CBORObject
                      .DecodeFromBytes(
                        attObj.getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey.getBytes
                      )
                      .get(CBORObject.FromObject(3))
                      .AsInt64Value should equal(-257)
                    attObj.getAttestationStatement
                      .get("alg")
                      .longValue should equal(-65535)
                    result shouldBe a[Failure[_]]
                    result.failed.get shouldBe an[IllegalArgumentException]
                  }
                }

                describe("2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.") {
                  it("Succeeds for the default test case.") {
                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testDataBase.attestationObject),
                      testDataBase.clientDataJsonHash,
                    )
                    result should equal(true)
                  }

                  it("Succeeds for an RS1 test case.") {
                    val testData =
                      RegistrationTestData.Packed.SelfAttestationRs1
                    val alg = COSEAlgorithmIdentifier
                      .fromPublicKey(
                        testData.response.getResponse.getParsedAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
                      )
                      .get
                    alg should be(COSEAlgorithmIdentifier.RS1)

                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testData.attestationObject),
                      testData.clientDataJsonHash,
                    )
                    result should equal(true)
                  }

                  it("Fails if the attestation object is mutated.") {
                    val testData = testDataBase.editAuthenticatorData {
                      authData: ByteArray =>
                        new ByteArray(
                          authData.getBytes.updated(
                            16,
                            if (authData.getBytes()(16) == 0) 1: Byte
                            else 0: Byte,
                          )
                        )
                    }
                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testData.attestationObject),
                      testData.clientDataJsonHash,
                    )
                    result should equal(false)
                  }

                  it("Fails if the client data is mutated.") {
                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testDataBase.attestationObject),
                      sha256(
                        new ByteArray(
                          testDataBase.clientDataJson
                            .updated(4, 'ä')
                            .getBytes("UTF-8")
                        )
                      ),
                    )
                    result should equal(false)
                  }

                  it("Fails if the client data hash is mutated.") {
                    val result = verifier.verifyAttestationSignature(
                      new AttestationObject(testDataBase.attestationObject),
                      new ByteArray(
                        testDataBase.clientDataJsonHash.getBytes.updated(
                          7,
                          if (
                            testDataBase.clientDataJsonHash.getBytes()(7) == 0
                          ) 1: Byte
                          else 0: Byte,
                        )
                      ),
                    )
                    result should equal(false)
                  }
                }

                it("3. If successful, return implementation-specific values representing attestation type Self and an empty attestation trust path.") {
                  val testData = RegistrationTestData.Packed.SelfAttestation
                  val steps = finishRegistration(testData = testData)
                  val step: FinishRegistrationSteps#Step19 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                  step.attestationType should be(
                    AttestationType.SELF_ATTESTATION
                  )
                  step.attestationTrustPath.toScala shouldBe empty
                }
              }
            }

            describe(
              "8.2.1. Packed Attestation Statement Certificate Requirements"
            ) {
              val testDataBase = RegistrationTestData.Packed.BasicAttestation

              describe("The attestation certificate MUST have the following fields/extensions:") {
                it("Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).") {
                  val badCert = Mockito.mock(classOf[X509Certificate])
                  val principal = new X500Principal(
                    "O=Yubico, C=SE, OU=Authenticator Attestation"
                  )
                  Mockito.when(badCert.getVersion) thenReturn 2
                  Mockito.when(
                    badCert.getSubjectX500Principal
                  ) thenReturn principal
                  Mockito.when(badCert.getBasicConstraints) thenReturn -1
                  val result = Try(
                    verifier.verifyX5cRequirements(badCert, testDataBase.aaguid)
                  )

                  result shouldBe a[Failure[_]]
                  result.failed.get shouldBe an[IllegalArgumentException]

                  verifier.verifyX5cRequirements(
                    testDataBase.packedAttestationCert,
                    testDataBase.aaguid,
                  ) should equal(true)
                }

                describe("Subject field MUST be set to:") {
                  it("Subject-C: ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)") {
                    val badCert: X509Certificate = TestAuthenticator
                      .generateAttestationCertificate(
                        name = new X500Name(
                          "O=Yubico, C=AA, OU=Authenticator Attestation"
                        )
                      )
                      ._1
                    val result = Try(
                      verifier.verifyX5cRequirements(
                        badCert,
                        testDataBase.aaguid,
                      )
                    )

                    result shouldBe a[Failure[_]]
                    result.failed.get shouldBe an[IllegalArgumentException]

                    verifier.verifyX5cRequirements(
                      testDataBase.packedAttestationCert,
                      testDataBase.aaguid,
                    ) should equal(true)
                  }

                  it("Subject-O: Legal name of the Authenticator vendor (UTF8String)") {
                    val badCert: X509Certificate = TestAuthenticator
                      .generateAttestationCertificate(
                        name =
                          new X500Name("C=SE, OU=Authenticator Attestation")
                      )
                      ._1
                    val result = Try(
                      verifier.verifyX5cRequirements(
                        badCert,
                        testDataBase.aaguid,
                      )
                    )

                    result shouldBe a[Failure[_]]
                    result.failed.get shouldBe an[IllegalArgumentException]

                    verifier.verifyX5cRequirements(
                      testDataBase.packedAttestationCert,
                      testDataBase.aaguid,
                    ) should equal(true)
                  }

                  it("""Subject-OU: Literal string "Authenticator Attestation" (UTF8String)""") {
                    val badCert: X509Certificate = TestAuthenticator
                      .generateAttestationCertificate(
                        name = new X500Name("O=Yubico, C=SE, OU=Foo")
                      )
                      ._1
                    val result = Try(
                      verifier.verifyX5cRequirements(
                        badCert,
                        testDataBase.aaguid,
                      )
                    )

                    result shouldBe a[Failure[_]]
                    result.failed.get shouldBe an[IllegalArgumentException]

                    verifier.verifyX5cRequirements(
                      testDataBase.packedAttestationCert,
                      testDataBase.aaguid,
                    ) should equal(true)
                  }

                  describe(
                    "Subject-CN: A UTF8String of the vendor’s choosing"
                  ) {
                    it("Nothing to test") {}
                  }
                }

                it("If the related attestation root certificate is used for multiple authenticator models, the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.") {
                  val idFidoGenCeAaguid = "1.3.6.1.4.1.45724.1.1.4"

                  val badCert: X509Certificate = TestAuthenticator
                    .generateAttestationCertificate(
                      name = new X500Name(
                        "O=Yubico, C=SE, OU=Authenticator Attestation"
                      ),
                      extensions = List(
                        (
                          idFidoGenCeAaguid,
                          false,
                          new DEROctetString(Array[Byte](0, 1, 2, 3)),
                        )
                      ),
                    )
                    ._1
                  val result = Try(
                    verifier.verifyX5cRequirements(badCert, testDataBase.aaguid)
                  )

                  result shouldBe a[Failure[_]]
                  result.failed.get shouldBe an[IllegalArgumentException]

                  val badCertCritical: X509Certificate = TestAuthenticator
                    .generateAttestationCertificate(
                      name = new X500Name(
                        "O=Yubico, C=SE, OU=Authenticator Attestation"
                      ),
                      extensions = List(
                        (
                          idFidoGenCeAaguid,
                          true,
                          new DEROctetString(testDataBase.aaguid.getBytes),
                        )
                      ),
                    )
                    ._1
                  val resultCritical = Try(
                    verifier.verifyX5cRequirements(
                      badCertCritical,
                      testDataBase.aaguid,
                    )
                  )

                  resultCritical shouldBe a[Failure[_]]
                  resultCritical.failed.get shouldBe an[
                    IllegalArgumentException
                  ]

                  val goodResult = Try(
                    verifier.verifyX5cRequirements(badCert, testDataBase.aaguid)
                  )

                  goodResult shouldBe a[Failure[_]]
                  goodResult.failed.get shouldBe an[IllegalArgumentException]

                  verifier.verifyX5cRequirements(
                    testDataBase.packedAttestationCert,
                    testDataBase.aaguid,
                  ) should equal(true)
                }

                it("The Basic Constraints extension MUST have the CA component set to false.") {
                  val result = Try(
                    verifier.verifyX5cRequirements(
                      testDataBase.attestationCertChain.last._1,
                      testDataBase.aaguid,
                    )
                  )

                  result shouldBe a[Failure[_]]
                  result.failed.get shouldBe an[IllegalArgumentException]

                  verifier.verifyX5cRequirements(
                    testDataBase.packedAttestationCert,
                    testDataBase.aaguid,
                  ) should equal(true)
                }

                describe("An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through authenticator metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].") {
                  it("Nothing to test.") {}
                }
              }
            }
          }

          describe("The tpm statement format") {

            it("is supported.") {
              val testData = RealExamples.WindowsHelloTpm.asRegistrationTestData
              val steps =
                finishRegistration(
                  testData = testData,
                  origins =
                    Some(Set("https://dev.d2urpypvrhb05x.amplifyapp.com")),
                  credentialRepository = Helpers.CredentialRepository.empty,
                  attestationTrustSource = Some(
                    trustSourceWith(
                      testData.attestationRootCertificate.get,
                      enableRevocationChecking = false,
                      policyTreeValidator = Some(_ => true),
                    )
                  ),
                )
              val step: FinishRegistrationSteps#Step19 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
              step.run.getAttestationType should be(
                AttestationType.ATTESTATION_CA
              )
            }

            describe("is supported and accepts test-generated values:") {

              val emptySubject = new X500Name(Array.empty[RDN])
              val tcgAtTpmManufacturer = new AttributeTypeAndValue(
                new ASN1ObjectIdentifier("2.23.133.2.1"),
                new DERUTF8String("id:00000000"),
              )
              val tcgAtTpmModel = new AttributeTypeAndValue(
                new ASN1ObjectIdentifier("2.23.133.2.2"),
                new DERUTF8String("TEST_Yubico_java-webauthn-server"),
              )
              val tcgAtTpmVersion = new AttributeTypeAndValue(
                new ASN1ObjectIdentifier("2.23.133.2.3"),
                new DERUTF8String("id:00000000"),
              )
              val tcgKpAikCertificate = new ASN1ObjectIdentifier("2.23.133.8.3")

              def makeCred(
                  authDataAndKeypair: Option[(ByteArray, KeyPair)] = None,
                  credKeyAlgorithm: COSEAlgorithmIdentifier =
                    TestAuthenticator.Defaults.keyAlgorithm,
                  clientDataJson: Option[String] = None,
                  subject: X500Name = emptySubject,
                  rdn: Array[AttributeTypeAndValue] =
                    Array(tcgAtTpmManufacturer, tcgAtTpmModel, tcgAtTpmVersion),
                  extendedKeyUsage: Array[ASN1Encodable] =
                    Array(tcgKpAikCertificate),
                  ver: Option[String] = Some("2.0"),
                  magic: ByteArray =
                    TpmAttestationStatementVerifier.TPM_GENERATED_VALUE,
                  `type`: ByteArray =
                    TpmAttestationStatementVerifier.TPM_ST_ATTEST_CERTIFY,
                  modifyAttestedName: ByteArray => ByteArray = an => an,
                  overrideCosePubkey: Option[ByteArray] = None,
                  aaguidInCert: Option[ByteArray] = None,
                  attributes: Option[Long] = None,
                  symmetric: Option[Int] = None,
                  scheme: Option[Int] = None,
              ): (
                  PublicKeyCredential[
                    AuthenticatorAttestationResponse,
                    ClientRegistrationExtensionOutputs,
                  ],
                  KeyPair,
                  List[(X509Certificate, PrivateKey)],
              ) = {
                val (authData, credentialKeypair) =
                  authDataAndKeypair.getOrElse(
                    TestAuthenticator.createAuthenticatorData(
                      credentialKeypair = Some(
                        TestAuthenticator.Defaults.defaultKeypair(
                          credKeyAlgorithm
                        )
                      ),
                      keyAlgorithm = credKeyAlgorithm,
                    )
                  )

                TestAuthenticator.createCredential(
                  authDataBytes = authData,
                  credentialKeypair = credentialKeypair,
                  clientDataJson = clientDataJson,
                  attestationMaker = AttestationMaker.tpm(
                    cert = AttestationSigner.ca(
                      alg = COSEAlgorithmIdentifier.ES256,
                      certSubject = subject,
                      aaguid = aaguidInCert,
                      certExtensions = List(
                        (
                          Extension.subjectAlternativeName.getId,
                          true,
                          new GeneralNamesBuilder()
                            .addName(
                              new GeneralName(new X500Name(Array(new RDN(rdn))))
                            )
                            .build(),
                        ),
                        (
                          Extension.extendedKeyUsage.getId,
                          true,
                          new DERSequence(extendedKeyUsage),
                        ),
                      ),
                      validFrom = Instant.now(),
                      validTo = Instant.now().plusSeconds(600),
                    ),
                    ver = ver,
                    magic = magic,
                    `type` = `type`,
                    modifyAttestedName = modifyAttestedName,
                    overrideCosePubkey = overrideCosePubkey,
                    attributes = attributes,
                    symmetric = symmetric,
                    scheme = scheme,
                  ),
                )
              }

              def init(
                  testData: RegistrationTestData
              ): FinishRegistrationSteps#Step19 = {
                val steps =
                  finishRegistration(
                    credentialRepository = Helpers.CredentialRepository.empty,
                    testData = testData,
                    attestationTrustSource = Some(
                      trustSourceWith(
                        testData.attestationCertChain.last._1,
                        enableRevocationChecking = false,
                      )
                    ),
                  )
                steps.begin.next.next.next.next.next.next.next.next.next.next.next.next
              }

              def check(
                  testData: RegistrationTestData,
                  pubKeyCredParams: Option[
                    List[PublicKeyCredentialParameters]
                  ] = None,
              ) = {
                val steps =
                  finishRegistration(
                    testData = testData,
                    credentialRepository = Helpers.CredentialRepository.empty,
                    attestationTrustSource = Some(
                      trustSourceWith(
                        testData.attestationRootCertificate.getOrElse(
                          testData.attestationCertChain.last._1
                        ),
                        enableRevocationChecking = false,
                      )
                    ),
                    pubkeyCredParams = pubKeyCredParams,
                    clock = Clock.fixed(
                      TestAuthenticator.Defaults.certValidFrom,
                      ZoneOffset.UTC,
                    ),
                  )
                val step: FinishRegistrationSteps#Step19 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]
                step.run.getAttestationType should be(
                  AttestationType.ATTESTATION_CA
                )
              }

              it("ES256.") {
                check(RegistrationTestData.Tpm.ValidEs256)
              }
              it("ES384.") {
                check(RegistrationTestData.Tpm.ValidEs384)
              }
              it("ES512.") {
                check(RegistrationTestData.Tpm.ValidEs512)
              }
              it("RS256.") {
                check(RegistrationTestData.Tpm.ValidRs256)
              }
              it("RS1.") {
                check(
                  RegistrationTestData.Tpm.ValidRs1,
                  pubKeyCredParams =
                    Some(List(PublicKeyCredentialParameters.RS1)),
                )
              }

              it("Default cert generator settings.") {
                val testData = (RegistrationTestData.from _).tupled(makeCred())
                val step = init(testData)

                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]
                step.run.getAttestationType should be(
                  AttestationType.ATTESTATION_CA
                )
              }

              describe("Verify that the public key specified by the parameters and unique fields of pubArea is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.") {
                it("Fails when EC key is unrelated but on the same curve.") {
                  val testData = (RegistrationTestData.from _).tupled(
                    makeCred(
                      overrideCosePubkey = Some(
                        WebAuthnTestCodecs.ecPublicKeyToCose(
                          TestAuthenticator
                            .generateEcKeypair()
                            .getPublic
                            .asInstanceOf[ECPublicKey]
                        )
                      )
                    )
                  )
                  val step = init(testData)

                  step.validations shouldBe a[Failure[_]]
                  step.tryNext shouldBe a[Failure[_]]
                  step.validations.failed.get.getMessage should include(
                    "EC X coordinate differs"
                  )
                }

                it("Fails when EC key is on a different curve.") {
                  val testData = (RegistrationTestData.from _).tupled(
                    makeCred(
                      overrideCosePubkey = Some(
                        WebAuthnTestCodecs.ecPublicKeyToCose(
                          TestAuthenticator
                            .generateEcKeypair("secp384r1")
                            .getPublic
                            .asInstanceOf[ECPublicKey]
                        )
                      )
                    )
                  )
                  val step = init(testData)

                  step.validations shouldBe a[Failure[_]]
                  step.tryNext shouldBe a[Failure[_]]
                  step.validations.failed.get.getMessage should include(
                    "elliptic curve differs"
                  )
                }

                it("Fails when EC key has an inverted Y coordinate.") {
                  val (authData, keypair) =
                    TestAuthenticator.createAuthenticatorData(keyAlgorithm =
                      COSEAlgorithmIdentifier.ES256
                    )

                  val cose = CBORObject.DecodeFromBytes(
                    WebAuthnTestCodecs
                      .ecPublicKeyToCose(
                        keypair.getPublic.asInstanceOf[ECPublicKey]
                      )
                      .getBytes
                  )
                  val yneg = TestAuthenticator.Es256PrimeModulus
                    .subtract(
                      new BigInteger(1, cose.get(-3).GetByteString())
                    )
                  val ynegBytes = yneg.toByteArray.dropWhile(_ == 0)
                  cose.Set(
                    -3,
                    Array.fill[Byte](32 - ynegBytes.length)(0) ++ ynegBytes,
                  )

                  val testData = (RegistrationTestData.from _).tupled(
                    makeCred(
                      authDataAndKeypair = Some((authData, keypair)),
                      overrideCosePubkey =
                        Some(new ByteArray(cose.EncodeToBytes())),
                    )
                  )
                  val step = init(testData)

                  step.validations shouldBe a[Failure[_]]
                  step.tryNext shouldBe a[Failure[_]]
                  step.validations.failed.get.getMessage should include(
                    "EC Y coordinate differs"
                  )
                }

                it("Fails when RSA key is unrelated.") {
                  val (authData, keypair) =
                    TestAuthenticator.createAuthenticatorData(keyAlgorithm =
                      COSEAlgorithmIdentifier.RS256
                    )
                  val testData = (RegistrationTestData.from _).tupled(
                    makeCred(
                      authDataAndKeypair = Some((authData, keypair)),
                      overrideCosePubkey = Some(
                        WebAuthnTestCodecs.rsaPublicKeyToCose(
                          TestAuthenticator
                            .generateRsaKeypair()
                            .getPublic
                            .asInstanceOf[RSAPublicKey],
                          COSEAlgorithmIdentifier.RS256,
                        )
                      ),
                    )
                  )
                  val step = init(testData)

                  step.validations shouldBe a[Failure[_]]
                  step.tryNext shouldBe a[Failure[_]]
                }
              }

              it("""The "ver" property must equal "2.0".""") {
                forAll(
                  Gen.option(
                    Gen.oneOf(
                      Gen.numStr,
                      for {
                        major <- arbitrary[Int]
                        minor <- arbitrary[Int]
                      } yield s"${major}.${minor}",
                      arbitrary[String],
                    )
                  )
                ) { ver: Option[String] =>
                  whenever(!ver.contains("2.0")) {
                    val testData =
                      (RegistrationTestData.from _).tupled(makeCred(ver = ver))
                    val step = init(testData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }
              }

              it("""Verify that magic is set to TPM_GENERATED_VALUE.""") {
                forAll(byteArray(4)) { magic =>
                  whenever(
                    magic != TpmAttestationStatementVerifier.TPM_GENERATED_VALUE
                  ) {
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(magic = magic)
                    )
                    val step = init(testData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }
              }

              it("""Verify that type is set to TPM_ST_ATTEST_CERTIFY.""") {
                forAll(
                  Gen.oneOf(
                    byteArray(2),
                    flipOneBit(
                      TpmAttestationStatementVerifier.TPM_ST_ATTEST_CERTIFY
                    ),
                  )
                ) { `type` =>
                  whenever(
                    `type` != TpmAttestationStatementVerifier.TPM_ST_ATTEST_CERTIFY
                  ) {
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(`type` = `type`)
                    )
                    val step = init(testData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }
              }

              it("""Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".""") {
                val testData = (RegistrationTestData.from _).tupled(makeCred())
                val json = JacksonCodecs.json()
                val clientData = json
                  .readTree(testData.clientDataJson)
                  .asInstanceOf[ObjectNode]
                clientData.set(
                  "challenge",
                  jsonFactory.textNode(
                    Crypto
                      .sha256(
                        ByteArray.fromBase64Url(
                          clientData.get("challenge").textValue
                        )
                      )
                      .getBase64Url
                  ),
                )
                val mutatedTestData = testData.copy(clientDataJson =
                  json.writeValueAsString(clientData)
                )
                val step = init(mutatedTestData)

                step.validations shouldBe a[Failure[_]]
                step.tryNext shouldBe a[Failure[_]]
              }

              it("Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea, as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.") {
                forAll(
                  Gen.oneOf(
                    for {
                      flipBitIndex: Int <-
                        Gen.oneOf(Gen.const(0), Gen.posNum[Int])
                    } yield (an: ByteArray) =>
                      flipBit(flipBitIndex % (8 * an.size()))(an),
                    for {
                      attestedName <- arbitrary[ByteArray]
                    } yield (_: ByteArray) => attestedName,
                  )
                ) { (modifyAttestedName: ByteArray => ByteArray) =>
                  val testData = (RegistrationTestData.from _).tupled(
                    makeCred(modifyAttestedName = modifyAttestedName)
                  )
                  val step = init(testData)

                  step.validations shouldBe a[Failure[_]]
                  step.tryNext shouldBe a[Failure[_]]
                }
              }

              it("Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.") {
                val testData = (RegistrationTestData.from _).tupled(makeCred())
                forAll(
                  flipOneBit(
                    new ByteArray(
                      new AttestationObject(
                        testData.attestationObject
                      ).getAttestationStatement.get("sig").binaryValue()
                    )
                  )
                ) { sig =>
                  val mutatedTestData = testData.updateAttestationObject(
                    "attStmt",
                    attStmt =>
                      attStmt
                        .asInstanceOf[ObjectNode]
                        .set[ObjectNode](
                          "sig",
                          jsonFactory.binaryNode(sig.getBytes),
                        ),
                  )
                  val step = init(mutatedTestData)

                  step.validations shouldBe a[Failure[_]]
                  step.tryNext shouldBe a[Failure[_]]
                }
              }

              describe("Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements.") {
                it("Version MUST be set to 3.") {
                  val testData =
                    (RegistrationTestData.from _).tupled(makeCred())
                  forAll(arbitrary[Byte] suchThat { _ != 2 }) { version =>
                    val mutatedTestData = testData.updateAttestationObject(
                      "attStmt",
                      attStmt => {
                        val origAikCert = attStmt
                          .get("x5c")
                          .get(0)
                          .binaryValue

                        val x509VerOffset = 12
                        attStmt
                          .get("x5c")
                          .asInstanceOf[ArrayNode]
                          .set(0, origAikCert.updated(x509VerOffset, version))
                        attStmt
                      },
                    )
                    val step = init(mutatedTestData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }

                describe("Subject field MUST be set to empty.") {
                  it("Fails if a subject is set.") {
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(subject =
                        new X500Name(
                          Array(
                            new RDN(
                              Array(
                                tcgAtTpmManufacturer,
                                tcgAtTpmModel,
                                tcgAtTpmVersion,
                              )
                            )
                          )
                        )
                      )
                    )
                    val step = init(testData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }

                describe("The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.") {
                  it("Fails when manufacturer is absent.") {
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(rdn = Array(tcgAtTpmModel, tcgAtTpmVersion))
                    )
                    val step = init(testData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }

                  it("Fails when model is absent.") {
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(rdn =
                        Array(tcgAtTpmManufacturer, tcgAtTpmVersion)
                      )
                    )
                    val step = init(testData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }

                  it("Fails when version is absent.") {
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(rdn = Array(tcgAtTpmManufacturer, tcgAtTpmModel))
                    )
                    val step = init(testData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }

                describe("The Extended Key Usage extension MUST contain the OID 2.23.133.8.3 (\"joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)\").") {
                  it("Fails when extended key usage is empty.") {
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(extendedKeyUsage = Array.empty)
                    )
                    val step = init(testData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }

                  it("""Fails when extended key usage contains only "serverAuth".""") {
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(extendedKeyUsage =
                        Array(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.1"))
                      )
                    )
                    val step = init(testData)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }

                describe("The Basic Constraints extension MUST have the CA component set to false.") {
                  it(
                    "Fails when the attestation cert is a self-signed CA cert."
                  ) {
                    val testData = (RegistrationTestData.from _).tupled(
                      TestAuthenticator.createBasicAttestedCredential(
                        keyAlgorithm = COSEAlgorithmIdentifier.ES256,
                        attestationMaker = AttestationMaker.tpm(
                          AttestationSigner.selfsigned(
                            alg = COSEAlgorithmIdentifier.ES256,
                            certSubject = emptySubject,
                            issuerSubject =
                              Some(TestAuthenticator.Defaults.caCertSubject),
                            certExtensions = List(
                              (
                                Extension.subjectAlternativeName.getId,
                                true,
                                new GeneralNamesBuilder()
                                  .addName(
                                    new GeneralName(
                                      new X500Name(
                                        Array(
                                          new RDN(
                                            Array(
                                              tcgAtTpmManufacturer,
                                              tcgAtTpmModel,
                                              tcgAtTpmVersion,
                                            )
                                          )
                                        )
                                      )
                                    )
                                  )
                                  .build(),
                              ),
                              (
                                Extension.extendedKeyUsage.getId,
                                true,
                                new DERSequence(tcgKpAikCertificate),
                              ),
                            ),
                            validFrom = Instant.now(),
                            validTo = Instant.now().plusSeconds(600),
                            isCa = true,
                          )
                        ),
                      )
                    )
                    val step = init(testData)
                    testData.attestationCertChain.head._1.getBasicConstraints should not be (-1)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }

                describe("An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].") {
                  it("Nothing to test.") {}
                }
              }

              describe("If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.") {
                it("Succeeds if the cert does not have the extension.") {
                  val testData = (RegistrationTestData.from _).tupled(
                    makeCred(aaguidInCert = None)
                  )
                  val step = init(testData)

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                }

                it(
                  "Succeeds if the cert has the extension with the right value."
                ) {
                  forAll(byteArray(16)) { aaguid =>
                    val (authData, keypair) =
                      TestAuthenticator.createAuthenticatorData(
                        aaguid = aaguid,
                        credentialKeypair = Some(
                          TestAuthenticator.Defaults.defaultKeypair(
                            COSEAlgorithmIdentifier.ES256
                          )
                        ),
                      )
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(
                        authDataAndKeypair = Some((authData, keypair)),
                        aaguidInCert = Some(aaguid),
                      )
                    )
                    val step = init(testData)

                    step.validations shouldBe a[Success[_]]
                    step.tryNext shouldBe a[Success[_]]
                  }
                }

                it(
                  "Fails if the cert has the extension with the wrong value."
                ) {
                  forAll(byteArray(16), byteArray(16)) {
                    (aaguidInCred, aaguidInCert) =>
                      whenever(aaguidInCred != aaguidInCert) {
                        val (authData, keypair) =
                          TestAuthenticator.createAuthenticatorData(
                            aaguid = aaguidInCred,
                            credentialKeypair = Some(
                              TestAuthenticator.Defaults.defaultKeypair(
                                COSEAlgorithmIdentifier.ES256
                              )
                            ),
                          )
                        val testData = (RegistrationTestData.from _).tupled(
                          makeCred(
                            authDataAndKeypair = Some((authData, keypair)),
                            aaguidInCert = Some(aaguidInCert),
                          )
                        )
                        val step = init(testData)

                        step.validations shouldBe a[Failure[_]]
                        step.tryNext shouldBe a[Failure[_]]
                      }
                  }
                }
              }

              describe("Other requirements:") {
                it("RSA keys must have the SIGN_ENCRYPT attribute.") {
                  forAll(
                    Gen.chooseNum(0, Int.MaxValue.toLong * 2 + 1),
                    minSuccessful(5),
                  ) { attributes: Long =>
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(
                        credKeyAlgorithm = COSEAlgorithmIdentifier.RS256,
                        attributes = Some(attributes & ~Attributes.SIGN_ENCRYPT),
                      )
                    )
                    val step = init(testData)
                    testData.alg should be(COSEAlgorithmIdentifier.RS256)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }

                it("""RSA keys must have "symmetric" set to TPM_ALG_NULL""") {
                  forAll(
                    Gen.chooseNum(0, Short.MaxValue * 2 + 1),
                    minSuccessful(5),
                  ) { symmetric: Int =>
                    whenever(symmetric != TPM_ALG_NULL) {
                      val testData = (RegistrationTestData.from _).tupled(
                        makeCred(
                          credKeyAlgorithm = COSEAlgorithmIdentifier.RS256,
                          symmetric = Some(symmetric),
                        )
                      )
                      val step = init(testData)
                      testData.alg should be(COSEAlgorithmIdentifier.RS256)

                      step.validations shouldBe a[Failure[_]]
                      step.tryNext shouldBe a[Failure[_]]
                    }
                  }
                }

                it("""RSA keys must have "scheme" set to TPM_ALG_RSASSA or TPM_ALG_NULL""") {
                  forAll(
                    Gen.chooseNum(0, Short.MaxValue * 2 + 1),
                    minSuccessful(5),
                  ) { scheme: Int =>
                    whenever(
                      scheme != TpmRsaScheme.RSASSA && scheme != TPM_ALG_NULL
                    ) {
                      val testData = (RegistrationTestData.from _).tupled(
                        makeCred(
                          credKeyAlgorithm = COSEAlgorithmIdentifier.RS256,
                          scheme = Some(scheme),
                        )
                      )
                      val step = init(testData)
                      testData.alg should be(COSEAlgorithmIdentifier.RS256)

                      step.validations shouldBe a[Failure[_]]
                      step.tryNext shouldBe a[Failure[_]]
                    }
                  }
                }

                it("ECC keys must have the SIGN_ENCRYPT attribute.") {
                  forAll(
                    Gen.chooseNum(0, Int.MaxValue.toLong * 2 + 1),
                    minSuccessful(5),
                  ) { attributes: Long =>
                    val testData = (RegistrationTestData.from _).tupled(
                      makeCred(
                        credKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
                        attributes = Some(attributes & ~Attributes.SIGN_ENCRYPT),
                      )
                    )
                    val step = init(testData)
                    testData.alg should be(COSEAlgorithmIdentifier.ES256)

                    step.validations shouldBe a[Failure[_]]
                    step.tryNext shouldBe a[Failure[_]]
                  }
                }

                it("""ECC keys must have "symmetric" set to TPM_ALG_NULL""") {
                  forAll(
                    Gen.chooseNum(0, Short.MaxValue * 2 + 1),
                    minSuccessful(5),
                  ) { symmetric: Int =>
                    whenever(symmetric != TPM_ALG_NULL) {
                      val testData = (RegistrationTestData.from _).tupled(
                        makeCred(
                          credKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
                          symmetric = Some(symmetric),
                        )
                      )
                      val step = init(testData)
                      testData.alg should be(COSEAlgorithmIdentifier.ES256)

                      step.validations shouldBe a[Failure[_]]
                      step.tryNext shouldBe a[Failure[_]]
                    }
                  }
                }

                it("""ECC keys must have "scheme" set to TPM_ALG_NULL""") {
                  forAll(
                    Gen.chooseNum(0, Short.MaxValue * 2 + 1),
                    minSuccessful(5),
                  ) { scheme: Int =>
                    whenever(scheme != TPM_ALG_NULL) {
                      val testData = (RegistrationTestData.from _).tupled(
                        makeCred(
                          credKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
                          scheme = Some(scheme),
                        )
                      )
                      val step = init(testData)
                      testData.alg should be(COSEAlgorithmIdentifier.ES256)

                      step.validations shouldBe a[Failure[_]]
                      step.tryNext shouldBe a[Failure[_]]
                    }
                  }
                }
              }
            }
          }

          ignore("The android-key statement format is supported.") {
            val steps = finishRegistration(testData =
              RegistrationTestData.AndroidKey.BasicAttestation
            )
            val step: FinishRegistrationSteps#Step19 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          describe("For the android-safetynet attestation statement format") {
            val verifier = new AndroidSafetynetAttestationStatementVerifier
            val testDataContainer = RegistrationTestData.AndroidSafetynet
            val defaultTestData = testDataContainer.BasicAttestation

            it("the attestation statement verifier implementation is AndroidSafetynetAttestationStatementVerifier.") {
              val steps = finishRegistration(
                testData = defaultTestData,
                allowUntrustedAttestation = false,
              )
              val step: FinishRegistrationSteps#Step19 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

              step.getAttestationStatementVerifier.get shouldBe an[
                AndroidSafetynetAttestationStatementVerifier
              ]
            }

            describe("the verification procedure is:") {
              def checkFails(testData: RegistrationTestData): Unit = {
                val result: Try[Boolean] = Try(
                  verifier.verifyAttestationSignature(
                    new AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash,
                  )
                )

                result shouldBe a[Failure[_]]
                result.failed.get shouldBe an[IllegalArgumentException]
              }

              describe("1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.") {
                it("Fails if attStmt.ver is a number value.") {
                  val testData = defaultTestData
                    .updateAttestationObject(
                      "attStmt",
                      attStmt =>
                        attStmt
                          .asInstanceOf[ObjectNode]
                          .set[ObjectNode]("ver", jsonFactory.numberNode(123)),
                    )
                  checkFails(testData)
                }

                it("Fails if attStmt.ver is missing.") {
                  val testData = defaultTestData
                    .updateAttestationObject(
                      "attStmt",
                      attStmt =>
                        attStmt
                          .asInstanceOf[ObjectNode]
                          .without[ObjectNode]("ver"),
                    )
                  checkFails(testData)
                }

                it("Fails if attStmt.response is a text value.") {
                  val testData = defaultTestData
                    .updateAttestationObject(
                      "attStmt",
                      attStmt =>
                        attStmt
                          .asInstanceOf[ObjectNode]
                          .set[ObjectNode](
                            "response",
                            jsonFactory.textNode(
                              new ByteArray(
                                attStmt.get("response").binaryValue()
                              ).getBase64Url
                            ),
                          ),
                    )
                  checkFails(testData)
                }

                it("Fails if attStmt.response is missing.") {
                  val testData = defaultTestData
                    .updateAttestationObject(
                      "attStmt",
                      attStmt =>
                        attStmt
                          .asInstanceOf[ObjectNode]
                          .without[ObjectNode]("response"),
                    )
                  checkFails(testData)
                }
              }

              describe("2. Verify that response is a valid SafetyNet response of version ver by following the steps indicated by the SafetyNet online documentation. As of this writing, there is only one format of the SafetyNet response and ver is reserved for future use.") {
                it("Fails if there's a difference in the signature.") {
                  val testData = defaultTestData
                    .updateAttestationObject(
                      "attStmt",
                      attStmt =>
                        attStmt
                          .asInstanceOf[ObjectNode]
                          .set[ObjectNode](
                            "response",
                            jsonFactory.binaryNode(
                              editByte(
                                new ByteArray(
                                  attStmt.get("response").binaryValue()
                                ),
                                2000,
                                b => ((b + 1) % 26 + 0x41).toByte,
                              ).getBytes
                            ),
                          ),
                    )

                  val result: Try[Boolean] = Try(
                    verifier.verifyAttestationSignature(
                      new AttestationObject(testData.attestationObject),
                      testData.clientDataJsonHash,
                    )
                  )

                  result shouldBe a[Success[_]]
                  result.get should be(false)
                }
              }

              describe("3. Verify that the nonce attribute in the payload of response is identical to the Base64 encoding of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.") {
                it(
                  "Fails if an additional property is added to the client data."
                ) {
                  val testData = defaultTestData.editClientData("foo", "bar")
                  checkFails(testData)
                }
              }

              describe("4. Verify that the SafetyNet response actually came from the SafetyNet service by following the steps in the SafetyNet online documentation.") {
                it("Verify that attestationCert is issued to the hostname \"attest.android.com\".") {
                  checkFails(testDataContainer.WrongHostname)
                }

                it("Verify that the ctsProfileMatch attribute in the payload of response is true.") {
                  checkFails(testDataContainer.FalseCtsProfileMatch)
                }
              }

              describe("5. If successful, return implementation-specific values representing attestation type Basic and attestation trust path x5c.") {
                it("The real example succeeds.") {
                  val steps = finishRegistration(
                    testData = testDataContainer.RealExample
                  )
                  val step: FinishRegistrationSteps#Step19 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                  step.attestationType() should be(AttestationType.BASIC)
                  step.attestationTrustPath().get should not be empty
                  step.attestationTrustPath().get.size should be(2)
                }

                it("The default test case succeeds.") {
                  val steps = finishRegistration(testData =
                    testDataContainer.BasicAttestation
                  )
                  val step: FinishRegistrationSteps#Step19 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                  step.attestationType() should be(AttestationType.BASIC)
                  step.attestationTrustPath().get should not be empty
                  step.attestationTrustPath().get.size should be(1)
                }
              }
            }
          }

          it("The android-safetynet statement format is supported.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.AndroidSafetynet.RealExample
            )
            val step: FinishRegistrationSteps#Step19 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("The apple statement format is supported.") {
            val steps = finishRegistration(
              testData = RealExamples.AppleAttestationIos.asRegistrationTestData
            )
            val step: FinishRegistrationSteps#Step19 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Unknown attestation statement formats are identified as such.") {
            val steps = finishRegistration(testData =
              RegistrationTestData.FidoU2f.BasicAttestation
                .setAttestationStatementFormat("urgel")
            )
            val step: FinishRegistrationSteps#Step19 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
            step.attestationType should be(AttestationType.UNKNOWN)
            step.attestationTrustPath.toScala shouldBe empty
          }

          it("(Deleted) If verification of the attestation statement failed, the Relying Party MUST fail the registration ceremony.") {
            val steps = finishRegistration(testData =
              RegistrationTestData.FidoU2f.BasicAttestation
                .editClientData("foo", "bar")
            )
            val step14: FinishRegistrationSteps#Step19 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

            step14.validations shouldBe a[Failure[_]]
            Try(step14.next) shouldBe a[Failure[_]]

            Try(steps.run) shouldBe a[Failure[_]]
            Try(steps.run).failed.get shouldBe an[IllegalArgumentException]
          }
        }

        describe("20. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.") {

          val testData = RegistrationTestData.Packed.BasicAttestation
          val (attestationRootCert, _) =
            TestAuthenticator.generateAttestationCertificate()

          it("If an attestation trust source is set, it is used to get trust anchors.") {
            val attestationTrustSource = new AttestationTrustSource {
              override def findTrustRoots(
                  attestationCertificateChain: util.List[X509Certificate],
                  aaguid: Optional[ByteArray],
              ): TrustRootsResult =
                TrustRootsResult
                  .builder()
                  .trustRoots(
                    if (
                      attestationCertificateChain
                        .get(0)
                        .equals(
                          CertificateParser.parseDer(
                            new AttestationObject(
                              testData.attestationObject
                            ).getAttestationStatement
                              .get("x5c")
                              .get(0)
                              .binaryValue()
                          )
                        )
                    ) {
                      Set(attestationRootCert).asJava
                    } else {
                      Set.empty[X509Certificate].asJava
                    }
                  )
                  .build()
            }
            val steps = finishRegistration(
              testData = testData,
              attestationTrustSource = Some(attestationTrustSource),
            )
            val step: FinishRegistrationSteps#Step20 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.getTrustRoots.toScala.map(
              _.getTrustRoots.asScala
            ) should equal(
              Some(Set(attestationRootCert))
            )
            step.tryNext shouldBe a[Success[_]]
          }

          it("When the AAGUID in authenticator data is zero, the AAGUID in the attestation certificate is used instead, if possible.") {
            val example = RealExamples.SecurityKeyNfc
            val testData = example.asRegistrationTestData
            testData.aaguid should equal(
              ByteArray.fromHex("00000000000000000000000000000000")
            )
            val certAaguid = new ByteArray(
              CertificateParser
                .parseFidoAaguidExtension(
                  CertificateParser.parseDer(example.attestationCert.getBytes)
                )
                .get
            )

            val attestationTrustSource = new AttestationTrustSource {
              override def findTrustRoots(
                  attestationCertificateChain: util.List[X509Certificate],
                  aaguid: Optional[ByteArray],
              ): TrustRootsResult = {
                TrustRootsResult
                  .builder()
                  .trustRoots(
                    if (aaguid == Optional.of(certAaguid)) {
                      Set(attestationRootCert).asJava
                    } else {
                      Set.empty[X509Certificate].asJava
                    }
                  )
                  .build()
              }
            }
            val steps = finishRegistration(
              testData = testData,
              attestationTrustSource = Some(attestationTrustSource),
            )
            val step: FinishRegistrationSteps#Step20 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.getTrustRoots.toScala.map(
              _.getTrustRoots.asScala
            ) should equal(
              Some(Set(attestationRootCert))
            )
            step.tryNext shouldBe a[Success[_]]
          }

          it(
            "If an attestation trust source is not set, no trust anchors are returned."
          ) {
            val steps = finishRegistration(
              testData = testData,
              attestationTrustSource = None,
            )
            val step: FinishRegistrationSteps#Step20 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.getTrustRoots.toScala shouldBe empty
            step.tryNext shouldBe a[Success[_]]
          }
        }

        describe("21. Assess the attestation trustworthiness using the outputs of the verification procedure in step 19, as follows:") {

          describe("If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.") {
            describe("The default test case") {
              it("is rejected if untrusted attestation is not allowed.") {
                val steps = finishRegistration(
                  testData = RegistrationTestData.NoneAttestation.Default,
                  allowUntrustedAttestation = false,
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Failure[_]]
                step.validations.failed.get shouldBe an[
                  IllegalArgumentException
                ]
                step.attestationTrusted should be(false)
                step.tryNext shouldBe a[Failure[_]]
              }

              it("is accepted if untrusted attestation is allowed.") {
                val steps = finishRegistration(
                  testData = RegistrationTestData.NoneAttestation.Default,
                  allowUntrustedAttestation = true,
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.attestationTrusted should be(false)
                step.tryNext shouldBe a[Success[_]]
              }
            }
          }

          describe("(Not in spec:) If an unknown attestation statement format was used, check if no attestation is acceptable under Relying Party policy.") {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation
              .setAttestationStatementFormat("urgel")

            describe("The default test case") {
              it("is rejected if untrusted attestation is not allowed.") {
                val steps = finishRegistration(
                  testData = testData,
                  allowUntrustedAttestation = false,
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Failure[_]]
                step.validations.failed.get shouldBe an[
                  IllegalArgumentException
                ]
                step.attestationTrusted should be(false)
                step.tryNext shouldBe a[Failure[_]]
              }

              it("is accepted if untrusted attestation is allowed.") {
                val steps = finishRegistration(
                  testData = testData,
                  allowUntrustedAttestation = true,
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.attestationTrusted should be(false)
                step.tryNext shouldBe a[Success[_]]
              }
            }
          }

          describe("If self attestation was used, verify that self attestation is acceptable under Relying Party policy.") {

            describe("The default test case, with self attestation,") {
              it("is rejected if untrusted attestation is not allowed.") {
                val steps = finishRegistration(
                  testData = RegistrationTestData.FidoU2f.SelfAttestation,
                  allowUntrustedAttestation = false,
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Failure[_]]
                step.validations.failed.get shouldBe an[
                  IllegalArgumentException
                ]
                step.attestationTrusted should be(false)
                step.tryNext shouldBe a[Failure[_]]
              }

              it("is accepted if untrusted attestation is allowed.") {
                val steps = finishRegistration(
                  testData = RegistrationTestData.FidoU2f.SelfAttestation,
                  allowUntrustedAttestation = true,
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.attestationTrusted should be(false)
                step.tryNext shouldBe a[Success[_]]
              }

              it("is accepted if untrusted attestation is not allowed, but the self attestation key is a trust anchor.") {
                val testData = RegistrationTestData.FidoU2f.SelfAttestation
                val selfAttestationCert = CertificateParser.parseDer(
                  new AttestationObject(
                    testData.attestationObject
                  ).getAttestationStatement.get("x5c").get(0).binaryValue()
                )
                val steps = finishRegistration(
                  testData = testData,
                  attestationTrustSource = Some(
                    trustSourceWith(
                      selfAttestationCert,
                      crls = Some(
                        Set(
                          TestAuthenticator.buildCrl(
                            JcaX500NameUtil.getX500Name(
                              selfAttestationCert.getSubjectX500Principal
                            ),
                            WebAuthnTestCodecs.importPrivateKey(
                              testData.privateKey.get,
                              testData.alg,
                            ),
                            "SHA256withECDSA",
                            currentTime =
                              TestAuthenticator.Defaults.certValidFrom,
                            nextUpdate = TestAuthenticator.Defaults.certValidTo,
                          )
                        )
                      ),
                    )
                  ),
                  allowUntrustedAttestation = false,
                  clock = Clock.fixed(
                    TestAuthenticator.Defaults.certValidFrom,
                    ZoneOffset.UTC,
                  ),
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.attestationTrusted should be(true)
                step.tryNext shouldBe a[Success[_]]
              }
            }
          }

          describe("Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure to verify that the attestation public key either correctly chains up to an acceptable root certificate, or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step 20 may be the same).") {

            def generateTests(
                testData: RegistrationTestData,
                clock: Clock,
                trustedRootCert: Option[X509Certificate] = None,
                enableRevocationChecking: Boolean = true,
                origins: Option[Set[String]] = None,
                policyTreeValidator: Option[Predicate[PolicyNode]] = None,
            ): Unit = {
              it("is rejected if untrusted attestation is not allowed and the trust source does not trust it.") {
                val steps = finishRegistration(
                  allowUntrustedAttestation = false,
                  testData = testData,
                  attestationTrustSource = Some(emptyTrustSource),
                  clock = clock,
                  origins = origins,
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Failure[_]]
                step.attestationTrusted should be(false)
                step.tryNext shouldBe a[Failure[_]]
              }

              it("is accepted if untrusted attestation is allowed and the trust source does not trust it.") {
                val steps = finishRegistration(
                  allowUntrustedAttestation = true,
                  testData = testData,
                  attestationTrustSource = Some(emptyTrustSource),
                  clock = clock,
                  origins = origins,
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.attestationTrusted should be(false)
                step.tryNext shouldBe a[Success[_]]
              }

              it("is accepted if the trust source trusts it.") {
                val attestationTrustSource: Option[AttestationTrustSource] =
                  trustedRootCert
                    .orElse(testData.attestationCertChain.lastOption.map(_._1))
                    .map(
                      trustSourceWith(
                        _,
                        crls = testData.attestationCertChain.lastOption
                          .map({
                            case (cert, key) =>
                              Set(
                                TestAuthenticator.buildCrl(
                                  JcaX500NameUtil.getSubject(cert),
                                  key,
                                  "SHA256withECDSA",
                                  clock.instant(),
                                  clock.instant().plusSeconds(3600 * 24),
                                )
                              )
                          }),
                        enableRevocationChecking = enableRevocationChecking,
                        policyTreeValidator = policyTreeValidator,
                      )
                    )
                val steps = finishRegistration(
                  testData = testData,
                  attestationTrustSource = attestationTrustSource,
                  clock = clock,
                  origins = origins,
                )
                val step: FinishRegistrationSteps#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.attestationTrusted should be(true)
                step.tryNext shouldBe a[Success[_]]
              }

              it("is rejected if the attestation root cert appears in getCertStore but not in findTrustRoots.") {
                val rootCert = trustedRootCert.getOrElse(
                  testData.attestationCertChain.last._1
                )
                val crl: Option[CRL] =
                  testData.attestationCertChain.lastOption
                    .map({
                      case (cert, key) =>
                        TestAuthenticator.buildCrl(
                          JcaX500NameUtil.getSubject(cert),
                          key,
                          "SHA256withECDSA",
                          clock.instant(),
                          clock.instant().plusSeconds(3600 * 24),
                        )
                    })
                val certStore = CertStore.getInstance(
                  "Collection",
                  new CollectionCertStoreParameters(
                    (List(rootCert) ++ crl).asJava
                  ),
                )

                {
                  // First, check that the attestation is not trusted if the root cert appears only in getCertStore.
                  val attestationTrustSource = new AttestationTrustSource {
                    override def findTrustRoots(
                        attestationCertificateChain: util.List[X509Certificate],
                        aaguid: Optional[ByteArray],
                    ): TrustRootsResult =
                      TrustRootsResult
                        .builder()
                        .trustRoots(Collections.emptySet())
                        .certStore(certStore)
                        .enableRevocationChecking(enableRevocationChecking)
                        .policyTreeValidator(policyTreeValidator.orNull)
                        .build()
                  }
                  val steps = finishRegistration(
                    testData = testData,
                    attestationTrustSource = Some(attestationTrustSource),
                    clock = clock,
                    origins = origins,
                  )
                  val step: FinishRegistrationSteps#Step21 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Failure[_]]
                  step.attestationTrusted should be(false)
                  step.tryNext shouldBe a[Failure[_]]
                }

                {
                  // Since the above assertions would also pass if the cert chain happens to be broken, or CRL resolution fails, etc, make sure that the attestation is indeed trusted if the root cert appears in findTrustRoots.
                  val attestationTrustSource = new AttestationTrustSource {
                    override def findTrustRoots(
                        attestationCertificateChain: util.List[X509Certificate],
                        aaguid: Optional[ByteArray],
                    ): TrustRootsResult =
                      TrustRootsResult
                        .builder()
                        .trustRoots(Collections.singleton(rootCert))
                        .certStore(certStore)
                        .enableRevocationChecking(enableRevocationChecking)
                        .policyTreeValidator(policyTreeValidator.orNull)
                        .build()
                  }
                  val steps = finishRegistration(
                    testData = testData,
                    attestationTrustSource = Some(attestationTrustSource),
                    clock = clock,
                    origins = origins,
                  )
                  val step: FinishRegistrationSteps#Step21 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.attestationTrusted should be(true)
                  step.tryNext shouldBe a[Success[_]]
                }
              }
            }

            describe("An android-key basic attestation") {
              ignore("fails for now.") {
                fail("Test not implemented.")
              }
            }

            describe("An android-safetynet basic attestation") {
              generateTests(
                testData = RegistrationTestData.AndroidSafetynet.RealExample,
                Clock
                  .fixed(Instant.parse("2019-01-01T00:00:00Z"), ZoneOffset.UTC),
                trustedRootCert = Some(
                  CertificateParser.parsePem(
                    new String(
                      BinaryUtil.readAll(
                        getClass()
                          .getResourceAsStream("/globalsign-root-r2.pem")
                      ),
                      StandardCharsets.UTF_8,
                    )
                  )
                ),
                enableRevocationChecking =
                  false, // CRLs for this example are no longer available
              )
            }

            describe("A fido-u2f basic attestation") {
              generateTests(
                testData = RegistrationTestData.FidoU2f.BasicAttestation,
                Clock.fixed(
                  TestAuthenticator.Defaults.certValidFrom,
                  ZoneOffset.UTC,
                ),
              )
            }

            describe("A packed basic attestation") {
              generateTests(
                testData = RegistrationTestData.Packed.BasicAttestation,
                Clock.fixed(
                  TestAuthenticator.Defaults.certValidFrom,
                  ZoneOffset.UTC,
                ),
              )
            }

            describe("A tpm attestation") {
              val testData = RealExamples.WindowsHelloTpm.asRegistrationTestData
              generateTests(
                testData = testData,
                clock = Clock.fixed(
                  Instant.parse("2022-08-25T16:00:00Z"),
                  ZoneOffset.UTC,
                ),
                origins = Some(Set(testData.clientData.getOrigin)),
                trustedRootCert = Some(testData.attestationRootCertificate.get),
                enableRevocationChecking = false,
                policyTreeValidator = Some(_ => true),
              )
            }

            describe("Critical certificate policy extensions") {
              def init(
                  policyTreeValidator: Option[Predicate[PolicyNode]]
              ): FinishRegistrationSteps#Step21 = {
                val testData =
                  RealExamples.WindowsHelloTpm.asRegistrationTestData
                val clock = Clock.fixed(
                  Instant.parse("2022-08-25T16:00:00Z"),
                  ZoneOffset.UTC,
                )
                val steps = finishRegistration(
                  allowUntrustedAttestation = false,
                  origins = Some(Set(testData.clientData.getOrigin)),
                  testData = testData,
                  attestationTrustSource = Some(
                    trustSourceWith(
                      testData.attestationRootCertificate.get,
                      enableRevocationChecking = false,
                      policyTreeValidator = policyTreeValidator,
                    )
                  ),
                  clock = clock,
                )

                steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next
              }

              it("are rejected if no policy tree validator is set.") {
                // BouncyCastle provider does not reject critical policy extensions
                // TODO Mark test as ignored instead of just skipping (assume() and cancel() currently break pitest)
                if (
                  !Security.getProviders
                    .exists(p => p.isInstanceOf[BouncyCastleProvider])
                ) {
                  val step = init(policyTreeValidator = None)

                  step.validations shouldBe a[Failure[_]]
                  step.attestationTrusted should be(false)
                  step.tryNext shouldBe a[Failure[_]]
                }
              }

              it("are accepted if a policy tree validator is set and accepts the policy tree.") {
                val step = init(policyTreeValidator = Some(_ => true))

                step.validations shouldBe a[Success[_]]
                step.attestationTrusted should be(true)
                step.tryNext shouldBe a[Success[_]]
              }

              it("are rejected if a policy tree validator is set and does not accept the policy tree.") {
                val step = init(policyTreeValidator = Some(_ => false))

                step.validations shouldBe a[Failure[_]]
                step.attestationTrusted should be(false)
                step.tryNext shouldBe a[Failure[_]]
              }
            }
          }
        }

        describe("22. Check that the credentialId is not yet registered to any other user. If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.") {

          val testData = RegistrationTestData.FidoU2f.SelfAttestation

          it("Registration is aborted if the given credential ID is already registered.") {
            val credentialRepository =
              com.yubico.webauthn.test.Helpers.CredentialRepository.withUser(
                testData.userId,
                RegisteredCredential
                  .builder()
                  .credentialId(testData.response.getId)
                  .userHandle(testData.userId.getId)
                  .publicKeyCose(
                    testData.response.getResponse.getAttestation.getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
                  )
                  .signatureCount(1337)
                  .build(),
              )

            val steps = finishRegistration(
              allowUntrustedAttestation = true,
              testData = testData,
              credentialRepository = credentialRepository,
            )
            val step: FinishRegistrationSteps#Step22 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe an[Failure[_]]
          }

          it("Registration proceeds if the given credential ID is not already registered.") {
            val steps = finishRegistration(
              allowUntrustedAttestation = true,
              testData = testData,
              credentialRepository = Helpers.CredentialRepository.empty,
            )
            val step: FinishRegistrationSteps#Step22 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }
        }

        describe("23. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in options.user:") {
          val testData = RegistrationTestData.FidoU2f.BasicAttestation
          val steps = finishRegistration(
            testData = testData,
            attestationTrustSource = Some(
              trustSourceWith(
                testData.attestationCertChain.last._1,
                crls = Some(
                  testData.attestationCertChain.tail
                    .map({
                      case (cert, key) =>
                        TestAuthenticator.buildCrl(
                          JcaX500NameUtil.getSubject(cert),
                          key,
                          "SHA256withECDSA",
                          TestAuthenticator.Defaults.certValidFrom,
                          TestAuthenticator.Defaults.certValidTo,
                        )
                    })
                    .toSet
                ),
              )
            ),
            credentialRepository = Helpers.CredentialRepository.empty,
            clock = Clock.fixed(
              TestAuthenticator.Defaults.certValidFrom,
              ZoneOffset.UTC,
            ),
          )
          val result = steps.run()
          result.isAttestationTrusted should be(true)

          it("Associate the user’s account with the credentialId and credentialPublicKey in authData.attestedCredentialData, as appropriate for the Relying Party's system.") {
            result.getKeyId.getId should be(testData.response.getId)
            result.getPublicKeyCose should be(
              testData.response.getResponse.getAttestation.getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
            )
          }

          it("Associate the credentialId with a new stored signature counter value initialized to the value of authData.signCount.") {
            result.getSignatureCount should be(
              testData.response.getResponse.getAttestation.getAuthenticatorData.getSignatureCounter
            )
          }

          describe("It is RECOMMENDED to also:") {
            it("Associate the credentialId with the transport hints returned by calling credential.response.getTransports(). This value SHOULD NOT be modified before or after storing it. It is RECOMMENDED to use this value to populate the transports of the allowCredentials option in future get() calls to help the client know how to find a suitable authenticator.") {
              result.getKeyId.getTransports.toScala should equal(
                Some(
                  testData.response.getResponse.getTransports
                )
              )
            }
          }
        }

        describe("24. If the attestation statement attStmt successfully verified but is not trustworthy per step 21 above, the Relying Party SHOULD fail the registration ceremony.") {
          it("The test case with self attestation succeeds, but reports attestation is not trusted.") {
            val testData = RegistrationTestData.Packed.SelfAttestation
            val steps = finishRegistration(
              testData = testData,
              allowUntrustedAttestation = true,
              credentialRepository = Helpers.CredentialRepository.empty,
              attestationTrustSource = Some(emptyTrustSource),
            )
            steps.run.getKeyId.getId should be(testData.response.getId)
            steps.run.isAttestationTrusted should be(false)
          }

          describe("The test case with unknown attestation") {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation
              .setAttestationStatementFormat("urgel")

            it("passes if the RP allows untrusted attestation.") {
              val steps = finishRegistration(
                testData = testData,
                allowUntrustedAttestation = true,
                credentialRepository = Helpers.CredentialRepository.empty,
              )
              val result = Try(steps.run)
              result shouldBe a[Success[_]]
              result.get.isAttestationTrusted should be(false)
              result.get.getAttestationType should be(AttestationType.UNKNOWN)
            }

            it("fails if the RP required trusted attestation.") {
              val steps = finishRegistration(
                testData = testData,
                allowUntrustedAttestation = false,
                credentialRepository = Helpers.CredentialRepository.empty,
              )
              val result = Try(steps.run)
              result shouldBe a[Failure[_]]
              result.failed.get shouldBe an[IllegalArgumentException]
            }
          }

          def testUntrusted(testData: RegistrationTestData): Unit = {
            val fmt =
              new AttestationObject(testData.attestationObject).getFormat
            it(s"""A test case with good "${fmt}" attestation but no attestation trust source succeeds, but reports attestation as not trusted.""") {
              val testData = RegistrationTestData.FidoU2f.BasicAttestation
              val steps = finishRegistration(
                testData = testData,
                attestationTrustSource = None,
                allowUntrustedAttestation = true,
                credentialRepository = Helpers.CredentialRepository.empty,
              )
              steps.run.getKeyId.getId should be(testData.response.getId)
              steps.run.isAttestationTrusted should be(false)
            }
          }

          testUntrusted(RegistrationTestData.AndroidKey.BasicAttestation)
          testUntrusted(RegistrationTestData.AndroidSafetynet.BasicAttestation)
          testUntrusted(RegistrationTestData.FidoU2f.BasicAttestation)
          testUntrusted(RegistrationTestData.NoneAttestation.Default)
          testUntrusted(RealExamples.WindowsHelloTpm.asRegistrationTestData)
        }
      }
    }

    describe("The default RelyingParty settings") {

      val rp = RelyingParty
        .builder()
        .identity(
          RelyingPartyIdentity
            .builder()
            .id("localhost")
            .name("Test party")
            .build()
        )
        .credentialRepository(Helpers.CredentialRepository.empty)
        .build()

      val request = rp
        .startRegistration(
          StartRegistrationOptions
            .builder()
            .user(
              UserIdentity
                .builder()
                .name("test")
                .displayName("Test Testsson")
                .id(new ByteArray(Array()))
                .build()
            )
            .build()
        )
        .toBuilder()
        .challenge(
          RegistrationTestData.NoneAttestation.Default.clientData.getChallenge
        )
        .build()

      it("accept registrations with no attestation.") {
        val result = rp.finishRegistration(
          FinishRegistrationOptions
            .builder()
            .request(request)
            .response(RegistrationTestData.NoneAttestation.Default.response)
            .build()
        )

        result.isAttestationTrusted should be(false)
        result.getAttestationType should be(AttestationType.NONE)
        result.getKeyId.getId should equal(
          RegistrationTestData.NoneAttestation.Default.response.getId
        )
      }

      it(
        "accept registrations with unknown attestation statement format."
      ) {
        val testData = RegistrationTestData.FidoU2f.BasicAttestation
          .setAttestationStatementFormat("urgel")
        val result = rp.finishRegistration(
          FinishRegistrationOptions
            .builder()
            .request(request)
            .response(testData.response)
            .build()
        )

        result.isAttestationTrusted should be(false)
        result.getAttestationType should be(AttestationType.UNKNOWN)
        result.getKeyId.getId should equal(testData.response.getId)
      }

      it("accept android-key attestations but report they're untrusted.") {
        val result = rp.finishRegistration(
          FinishRegistrationOptions
            .builder()
            .request(request)
            .response(
              RegistrationTestData.AndroidKey.BasicAttestation.response
            )
            .build()
        )

        result.isAttestationTrusted should be(false)
        result.getKeyId.getId should equal(
          RegistrationTestData.AndroidKey.BasicAttestation.response.getId
        )
      }

      it("accept TPM attestations but report they're untrusted.") {
        val testData = RealExamples.WindowsHelloTpm.asRegistrationTestData
        val result = rp.toBuilder
          .identity(testData.rpId)
          .origins(Set("https://dev.d2urpypvrhb05x.amplifyapp.com").asJava)
          .build()
          .finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(
                request.toBuilder.challenge(testData.responseChallenge).build()
              )
              .response(testData.response)
              .build()
          )

        result.isAttestationTrusted should be(false)
        result.getKeyId.getId should equal(
          RealExamples.WindowsHelloTpm.asRegistrationTestData.response.getId
        )
      }

      describe("accept apple attestations but report they're untrusted:") {
        it("iOS") {
          val result = rp
            .toBuilder()
            .identity(RealExamples.AppleAttestationIos.rp)
            .origins(
              Set(
                RealExamples.AppleAttestationIos.attestation.collectedClientData.getOrigin
              ).asJava
            )
            .build()
            .finishRegistration(
              FinishRegistrationOptions
                .builder()
                .request(
                  request
                    .toBuilder()
                    .challenge(
                      RealExamples.AppleAttestationIos.attestation.collectedClientData.getChallenge
                    )
                    .build()
                )
                .response(
                  RealExamples.AppleAttestationIos.attestation.credential
                )
                .build()
            )

          result.isAttestationTrusted should be(false)
          RealExamples.AppleAttestationIos.attestation.credential.getResponse.getAttestation.getFormat should be(
            "apple"
          )
          result.getAttestationType should be(
            AttestationType.ANONYMIZATION_CA
          )
          result.getKeyId.getId should equal(
            RealExamples.AppleAttestationIos.attestation.credential.getId
          )
        }

        it("MacOS") {
          val result = rp
            .toBuilder()
            .identity(RealExamples.AppleAttestationMacos.rp)
            .origins(
              Set(
                RealExamples.AppleAttestationMacos.attestation.collectedClientData.getOrigin
              ).asJava
            )
            .build()
            .finishRegistration(
              FinishRegistrationOptions
                .builder()
                .request(
                  request
                    .toBuilder()
                    .challenge(
                      RealExamples.AppleAttestationMacos.attestation.collectedClientData.getChallenge
                    )
                    .build()
                )
                .response(
                  RealExamples.AppleAttestationMacos.attestation.credential
                )
                .build()
            )

          result.isAttestationTrusted should be(false)
          RealExamples.AppleAttestationMacos.attestation.credential.getResponse.getAttestation.getFormat should be(
            "apple"
          )
          result.getAttestationType should be(
            AttestationType.ANONYMIZATION_CA
          )
          result.getKeyId.getId should equal(
            RealExamples.AppleAttestationMacos.attestation.credential.getId
          )
        }
      }

      describe("accept all test examples in the validExamples list.") {
        RegistrationTestData.defaultSettingsValidExamples.zipWithIndex
          .foreach {
            case (testData, i) =>
              it(s"Succeeds for example index ${i} (${testData.alg}, ${testData.attestationStatementFormat}).") {
                val rp = RelyingParty
                  .builder()
                  .identity(testData.rpId)
                  .credentialRepository(
                    Helpers.CredentialRepository.empty
                  )
                  .origins(Set(testData.clientData.getOrigin).asJava)
                  .build()

                val request = rp
                  .startRegistration(
                    StartRegistrationOptions
                      .builder()
                      .user(testData.userId)
                      .build()
                  )
                  .toBuilder
                  .challenge(testData.request.getChallenge)
                  .build()

                val result = rp.finishRegistration(
                  FinishRegistrationOptions
                    .builder()
                    .request(request)
                    .response(testData.response)
                    .build()
                )

                result.getKeyId.getId should equal(testData.response.getId)
              }
          }
      }

      describe("generate pubKeyCredParams which") {
        val pkcco = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(
              UserIdentity
                .builder()
                .name("foo")
                .displayName("Foo")
                .id(ByteArray.fromHex("aabbccdd"))
                .build()
            )
            .build()
        )

        val pubKeyCredParams = pkcco.getPubKeyCredParams.asScala

        describe("include") {
          it("ES256.") {
            pubKeyCredParams should contain(
              PublicKeyCredentialParameters.ES256
            )
            pubKeyCredParams map (_.getAlg) should contain(
              COSEAlgorithmIdentifier.ES256
            )
          }

          it("ES384.") {
            pubKeyCredParams should contain(
              PublicKeyCredentialParameters.ES384
            )
            pubKeyCredParams map (_.getAlg) should contain(
              COSEAlgorithmIdentifier.ES384
            )
          }

          it("ES512.") {
            pubKeyCredParams should contain(
              PublicKeyCredentialParameters.ES512
            )
            pubKeyCredParams map (_.getAlg) should contain(
              COSEAlgorithmIdentifier.ES512
            )
          }

          it("EdDSA, when available.") {
            // The RelyingParty constructor call needs to be here inside the `it` call in order to have the right JCA provider environment
            val rp = RelyingParty
              .builder()
              .identity(
                RelyingPartyIdentity
                  .builder()
                  .id("localhost")
                  .name("Test party")
                  .build()
              )
              .credentialRepository(Helpers.CredentialRepository.empty)
              .build()

            val pkcco = rp.startRegistration(
              StartRegistrationOptions
                .builder()
                .user(
                  UserIdentity
                    .builder()
                    .name("foo")
                    .displayName("Foo")
                    .id(ByteArray.fromHex("aabbccdd"))
                    .build()
                )
                .build()
            )
            val pubKeyCredParams = pkcco.getPubKeyCredParams.asScala

            if (Try(KeyFactory.getInstance("EdDSA")).isSuccess) {
              pubKeyCredParams should contain(
                PublicKeyCredentialParameters.EdDSA
              )
              pubKeyCredParams map (_.getAlg) should contain(
                COSEAlgorithmIdentifier.EdDSA
              )
            } else {
              pubKeyCredParams should not contain (
                PublicKeyCredentialParameters.EdDSA
              )
              pubKeyCredParams map (_.getAlg) should not contain (
                COSEAlgorithmIdentifier.EdDSA
              )
            }
          }

          it("RS256.") {
            pubKeyCredParams should contain(
              PublicKeyCredentialParameters.RS256
            )
            pubKeyCredParams map (_.getAlg) should contain(
              COSEAlgorithmIdentifier.RS256
            )
          }

          it("RS384.") {
            pubKeyCredParams should contain(
              PublicKeyCredentialParameters.RS384
            )
            pubKeyCredParams map (_.getAlg) should contain(
              COSEAlgorithmIdentifier.RS384
            )
          }

          it("RS512.") {
            pubKeyCredParams should contain(
              PublicKeyCredentialParameters.RS512
            )
            pubKeyCredParams map (_.getAlg) should contain(
              COSEAlgorithmIdentifier.RS512
            )
          }
        }

        describe("do not include") {
          it("RS1.") {
            pubKeyCredParams should not contain PublicKeyCredentialParameters.RS1
            pubKeyCredParams map (_.getAlg) should not contain COSEAlgorithmIdentifier.RS1
          }
        }
      }

      describe("expose the credProps extension output as RegistrationResult.isDiscoverable()") {
        val testDataBase = RegistrationTestData.Packed.BasicAttestation
        val testData = testDataBase.copy(requestedExtensions =
          testDataBase.request.getExtensions.toBuilder.credProps().build()
        )

        it("when set to true.") {
          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(testData.request)
              .response(
                testData.response.toBuilder
                  .clientExtensionResults(
                    ClientRegistrationExtensionOutputs
                      .builder()
                      .credProps(
                        CredentialPropertiesOutput.builder().rk(true).build()
                      )
                      .build()
                  )
                  .build()
              )
              .build()
          )

          result.isDiscoverable.toScala should equal(Some(true))
        }

        it("when set to false.") {
          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(testData.request)
              .response(
                testData.response.toBuilder
                  .clientExtensionResults(
                    ClientRegistrationExtensionOutputs
                      .builder()
                      .credProps(
                        CredentialPropertiesOutput.builder().rk(false).build()
                      )
                      .build()
                  )
                  .build()
              )
              .build()
          )

          result.isDiscoverable.toScala should equal(Some(false))
        }

        it("when not available.") {
          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(testData.request)
              .response(testData.response)
              .build()
          )

          result.isDiscoverable.toScala should equal(None)
        }
      }

      describe("expose the credProps.authenticatorDisplayName extension output as RegistrationResult.getAuthenticatorDisplayName()") {
        val testDataBase = RegistrationTestData.Packed.BasicAttestation
        val testData = testDataBase.copy(requestedExtensions =
          testDataBase.request.getExtensions.toBuilder.credProps().build()
        )

        it("""when set to "hej".""") {
          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(testData.request)
              .response(
                testData.response.toBuilder
                  .clientExtensionResults(
                    ClientRegistrationExtensionOutputs
                      .builder()
                      .credProps(
                        CredentialPropertiesOutput
                          .builder()
                          .authenticatorDisplayName("hej")
                          .build()
                      )
                      .build()
                  )
                  .build()
              )
              .build()
          )

          result.getAuthenticatorDisplayName.toScala should equal(Some("hej"))
        }

        it("when not available.") {
          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(testData.request)
              .response(testData.response)
              .build()
          )

          result.getAuthenticatorDisplayName.toScala should equal(None)
        }
      }

      describe("support the largeBlob extension") {
        it("being enabled at registration time.") {
          val testData = RegistrationTestData.Packed.BasicAttestation
          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(
                testData.request.toBuilder
                  .extensions(
                    RegistrationExtensionInputs
                      .builder()
                      .largeBlob(LargeBlobSupport.REQUIRED)
                      .build()
                  )
                  .build()
              )
              .response(
                testData.response.toBuilder
                  .clientExtensionResults(
                    ClientRegistrationExtensionOutputs
                      .builder()
                      .largeBlob(
                        LargeBlobRegistrationOutput.supported(true)
                      )
                      .build()
                  )
                  .build()
              )
              .build()
          )

          result.getClientExtensionOutputs.get.getLargeBlob.get.isSupported should be(
            true
          )
        }
      }

      describe("support the uvm extension") {
        it("at registration time.") {

          // Example from spec: https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension
          // A1                     -- extension: CBOR map of one element
          //     63                 -- Key 1: CBOR text string of 3 bytes
          //         75 76 6d       -- "uvm" [=UTF-8 encoded=] string
          //     82                 -- Value 1: CBOR array of length 2 indicating two factor usage
          //         83              -- Item 1: CBOR array of length 3
          //             02           -- Subitem 1: CBOR integer for User Verification Method Fingerprint
          //             04           -- Subitem 2: CBOR short for Key Protection Type TEE
          //             02           -- Subitem 3: CBOR short for Matcher Protection Type TEE
          //         83              -- Item 2: CBOR array of length 3
          //             04           -- Subitem 1: CBOR integer for User Verification Method Passcode
          //             01           -- Subitem 2: CBOR short for Key Protection Type Software
          //             01           -- Subitem 3: CBOR short for Matcher Protection Type Software
          val uvmCborExample = ByteArray.fromHex("A16375766d828302040283040101")

          val challenge = TestAuthenticator.Defaults.challenge
          val (cred, _, _) = TestAuthenticator.createUnattestedCredential(
            authenticatorExtensions =
              Some(JacksonCodecs.cbor().readTree(uvmCborExample.getBytes)),
            challenge = challenge,
          )

          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(
                PublicKeyCredentialCreationOptions
                  .builder()
                  .rp(
                    RelyingPartyIdentity
                      .builder()
                      .id(TestAuthenticator.Defaults.rpId)
                      .name("Test RP")
                      .build()
                  )
                  .user(
                    UserIdentity
                      .builder()
                      .name("foo")
                      .displayName("Foo User")
                      .id(ByteArray.fromHex("00010203"))
                      .build()
                  )
                  .challenge(challenge)
                  .pubKeyCredParams(
                    List(PublicKeyCredentialParameters.ES256).asJava
                  )
                  .extensions(
                    RegistrationExtensionInputs
                      .builder()
                      .uvm()
                      .build()
                  )
                  .build()
              )
              .response(cred)
              .build()
          )

          result.getAuthenticatorExtensionOutputs.get.getUvm.toScala should equal(
            Some(
              List(
                new UvmEntry(
                  UserVerificationMethod.USER_VERIFY_FINGERPRINT_INTERNAL,
                  KeyProtectionType.KEY_PROTECTION_TEE,
                  MatcherProtectionType.MATCHER_PROTECTION_TEE,
                ),
                new UvmEntry(
                  UserVerificationMethod.USER_VERIFY_PASSCODE_INTERNAL,
                  KeyProtectionType.KEY_PROTECTION_SOFTWARE,
                  MatcherProtectionType.MATCHER_PROTECTION_SOFTWARE,
                ),
              ).asJava
            )
          )
        }
      }
    }

    describe("RelyingParty supports registering") {
      it("a real packed attestation with an RSA key.") {
        val rp = RelyingParty
          .builder()
          .identity(
            RelyingPartyIdentity
              .builder()
              .id("demo3.yubico.test")
              .name("Yubico WebAuthn demo")
              .build()
          )
          .credentialRepository(Helpers.CredentialRepository.empty)
          .origins(Set("https://demo3.yubico.test:8443").asJava)
          .build()

        val testData = RegistrationTestData.Packed.BasicAttestationRsaReal
        val result = rp.finishRegistration(
          FinishRegistrationOptions
            .builder()
            .request(testData.request)
            .response(testData.response)
            .build()
        )

        result.isAttestationTrusted should be(false)
        result.getKeyId.getId should equal(testData.response.getId)
      }
    }

    describe("The RegistrationResult") {
      describe("exposes getTransports() which") {

        val rp = RelyingParty
          .builder()
          .identity(
            RelyingPartyIdentity
              .builder()
              .id("example.com")
              .name("Example RP")
              .build()
          )
          .credentialRepository(Helpers.CredentialRepository.empty)
          .build()
        val user = UserIdentity.builder
          .name("foo")
          .displayName("Foo User")
          .id(new ByteArray(Array(0, 1, 2, 3)))
          .build()

        val request = PublicKeyCredentialCreationOptions
          .builder()
          .rp(rp.getIdentity)
          .user(user)
          .challenge(ByteArray.fromBase64Url("Y2hhbGxlbmdl"))
          .pubKeyCredParams(List(PublicKeyCredentialParameters.ES256).asJava)
          .build()

        it("contains the returned transports when available.") {
          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(PublicKeyCredential.parseRegistrationResponseJson("""{
                "type": "public-key",
                "id": "LbYHDfeoEJ-ItG8lq6fjNVnhg6kgbebGjYWEf32ZpyChibGv4gJU1OGM0nOQQY5G",
                "response": {
                  "clientDataJSON": "eyJ0eXBlIjogIndlYmF1dGhuLmNyZWF0ZSIsICJjbGllbnRFeHRlbnNpb25zIjoge30sICJjaGFsbGVuZ2UiOiAiWTJoaGJHeGxibWRsIiwgIm9yaWdpbiI6ICJodHRwczovL2V4YW1wbGUuY29tIn0",
                  "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAJKRPuYlfW8dZZlsJrJiwA-BvAyOvIe1TScv5qlek1SQAiAnglgs-nRjA7kpc61PewQ4VULjdlzLmReI7-MJT1TLrGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEMAIspTANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgODA1NDQ4ODY5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-66HSEytO3plXno3zPhH1k-zFwWxESIdrTbQp4HSEuzFum1Mwpy8itoOosBQksnIrefLHkTRNUtV8jIrFKAvbaNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBlZXnJy-X3fJfNdlIdIQlFpO5-A5uM41jJ2XgdRag_8rSxXCz98t_jyoWth5FQF9As96Ags3p-Lyaqb1bpEc9RfmkxiiqwDzDI56Sj4HKlANF2tddm-ew29H9yaNbpU5y6aleCeH2rR4t1cFgcBRAV84IndIH0cYASRnyrFbHjI80vlPNR0z4j-_W9vYEWBpLeS_wrdKPVW7C7wyuc4bobauCyhElBPZUwblR_Ll0iovmfazD17VLCBMA4p_SVVTwSXpKyZjMiCotj8mDhQ1ymhvCepkK82EwnrBMJIzCi_joxAXqxLPMs6yJrz_hFUkZaloa1ZS6f7aGAmAKhRNO2aGF1dGhEYXRhWMSjeab27q-5pV43jBGANOJ1Hmgvq58tMKsT0hJVhs4ZR0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAJT086Ym5LhLsK6MRwYRSdjVn9jVYVtwiGwgq_bDPpVuI3aaOW7UQfqGWdos-kVwHnQccbDRnQDvQmCDqy6QdSaUBAgMmIAEhWCCRGd2Bo0vIj-suQxM-cOCXovv1Ag6azqHn8PE31Fcu4iJYIOiLha_PR9JwOhCw4SC2Xq7cOackGAMsq4UUJ_IRCCcq",
                  "transports": ["nfc", "usb"]
                },
                "clientExtensionResults": {}
              }"""))
              .build()
          )

          result.getKeyId.getTransports.toScala.map(_.asScala) should equal(
            Some(Set(AuthenticatorTransport.USB, AuthenticatorTransport.NFC))
          )
        }

        it(
          "returns present but empty when transport hints are not available."
        ) {
          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(PublicKeyCredential.parseRegistrationResponseJson("""{
                "type": "public-key",
                "id": "LbYHDfeoEJ-ItG8lq6fjNVnhg6kgbebGjYWEf32ZpyChibGv4gJU1OGM0nOQQY5G",
                "response": {
                  "clientDataJSON": "eyJ0eXBlIjogIndlYmF1dGhuLmNyZWF0ZSIsICJjbGllbnRFeHRlbnNpb25zIjoge30sICJjaGFsbGVuZ2UiOiAiWTJoaGJHeGxibWRsIiwgIm9yaWdpbiI6ICJodHRwczovL2V4YW1wbGUuY29tIn0",
                  "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAJKRPuYlfW8dZZlsJrJiwA-BvAyOvIe1TScv5qlek1SQAiAnglgs-nRjA7kpc61PewQ4VULjdlzLmReI7-MJT1TLrGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEMAIspTANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgODA1NDQ4ODY5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-66HSEytO3plXno3zPhH1k-zFwWxESIdrTbQp4HSEuzFum1Mwpy8itoOosBQksnIrefLHkTRNUtV8jIrFKAvbaNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBlZXnJy-X3fJfNdlIdIQlFpO5-A5uM41jJ2XgdRag_8rSxXCz98t_jyoWth5FQF9As96Ags3p-Lyaqb1bpEc9RfmkxiiqwDzDI56Sj4HKlANF2tddm-ew29H9yaNbpU5y6aleCeH2rR4t1cFgcBRAV84IndIH0cYASRnyrFbHjI80vlPNR0z4j-_W9vYEWBpLeS_wrdKPVW7C7wyuc4bobauCyhElBPZUwblR_Ll0iovmfazD17VLCBMA4p_SVVTwSXpKyZjMiCotj8mDhQ1ymhvCepkK82EwnrBMJIzCi_joxAXqxLPMs6yJrz_hFUkZaloa1ZS6f7aGAmAKhRNO2aGF1dGhEYXRhWMSjeab27q-5pV43jBGANOJ1Hmgvq58tMKsT0hJVhs4ZR0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAJT086Ym5LhLsK6MRwYRSdjVn9jVYVtwiGwgq_bDPpVuI3aaOW7UQfqGWdos-kVwHnQccbDRnQDvQmCDqy6QdSaUBAgMmIAEhWCCRGd2Bo0vIj-suQxM-cOCXovv1Ag6azqHn8PE31Fcu4iJYIOiLha_PR9JwOhCw4SC2Xq7cOackGAMsq4UUJ_IRCCcq"
                },
                "clientExtensionResults": {}
              }"""))
              .build()
          )

          result.getKeyId.getTransports.toScala.map(_.asScala) should equal(
            Some(Set.empty)
          )
        }

        it("returns present but empty when transport hints are empty.") {
          val result = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(PublicKeyCredential.parseRegistrationResponseJson("""{
                "type": "public-key",
                "id": "LbYHDfeoEJ-ItG8lq6fjNVnhg6kgbebGjYWEf32ZpyChibGv4gJU1OGM0nOQQY5G",
                "response": {
                  "clientDataJSON": "eyJ0eXBlIjogIndlYmF1dGhuLmNyZWF0ZSIsICJjbGllbnRFeHRlbnNpb25zIjoge30sICJjaGFsbGVuZ2UiOiAiWTJoaGJHeGxibWRsIiwgIm9yaWdpbiI6ICJodHRwczovL2V4YW1wbGUuY29tIn0",
                  "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAJKRPuYlfW8dZZlsJrJiwA-BvAyOvIe1TScv5qlek1SQAiAnglgs-nRjA7kpc61PewQ4VULjdlzLmReI7-MJT1TLrGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEMAIspTANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgODA1NDQ4ODY5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-66HSEytO3plXno3zPhH1k-zFwWxESIdrTbQp4HSEuzFum1Mwpy8itoOosBQksnIrefLHkTRNUtV8jIrFKAvbaNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBlZXnJy-X3fJfNdlIdIQlFpO5-A5uM41jJ2XgdRag_8rSxXCz98t_jyoWth5FQF9As96Ags3p-Lyaqb1bpEc9RfmkxiiqwDzDI56Sj4HKlANF2tddm-ew29H9yaNbpU5y6aleCeH2rR4t1cFgcBRAV84IndIH0cYASRnyrFbHjI80vlPNR0z4j-_W9vYEWBpLeS_wrdKPVW7C7wyuc4bobauCyhElBPZUwblR_Ll0iovmfazD17VLCBMA4p_SVVTwSXpKyZjMiCotj8mDhQ1ymhvCepkK82EwnrBMJIzCi_joxAXqxLPMs6yJrz_hFUkZaloa1ZS6f7aGAmAKhRNO2aGF1dGhEYXRhWMSjeab27q-5pV43jBGANOJ1Hmgvq58tMKsT0hJVhs4ZR0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAJT086Ym5LhLsK6MRwYRSdjVn9jVYVtwiGwgq_bDPpVuI3aaOW7UQfqGWdos-kVwHnQccbDRnQDvQmCDqy6QdSaUBAgMmIAEhWCCRGd2Bo0vIj-suQxM-cOCXovv1Ag6azqHn8PE31Fcu4iJYIOiLha_PR9JwOhCw4SC2Xq7cOackGAMsq4UUJ_IRCCcq",
                  "transports": []
                },
                "clientExtensionResults": {}
              }"""))
              .build()
          )

          result.getKeyId.getTransports.toScala.map(_.asScala) should equal(
            Some(Set.empty)
          )
        }
      }

      describe(
        "exposes getAttestationTrustPath() with the attestation trust path"
      ) {
        it("for a fido-u2f attestation.") {
          val testData = RegistrationTestData.FidoU2f.BasicAttestation
          val steps = finishRegistration(
            testData = testData,
            attestationTrustSource = Some(
              trustSourceWith(
                testData.attestationCertChain.last._1,
                crls = Some(
                  testData.attestationCertChain
                    .map({
                      case (cert, key) =>
                        TestAuthenticator.buildCrl(
                          JcaX500NameUtil.getSubject(cert),
                          key,
                          "SHA256withECDSA",
                          TestAuthenticator.Defaults.certValidFrom,
                          TestAuthenticator.Defaults.certValidTo,
                        )
                    })
                    .toSet
                ),
              )
            ),
            credentialRepository = Helpers.CredentialRepository.empty,
            clock = Clock.fixed(
              TestAuthenticator.Defaults.certValidFrom,
              ZoneOffset.UTC,
            ),
          )
          val result = steps.run()
          result.isAttestationTrusted should be(true)
          result.getAttestationTrustPath.toScala.map(_.asScala) should equal(
            Some(testData.attestationCertChain.init.map(_._1))
          )
        }

        it("for a tpm attestation.") {
          val testData = RealExamples.WindowsHelloTpm.asRegistrationTestData
          val steps = finishRegistration(
            testData = testData,
            origins = Some(Set("https://dev.d2urpypvrhb05x.amplifyapp.com")),
            attestationTrustSource = Some(
              trustSourceWith(
                testData.attestationRootCertificate.get,
                enableRevocationChecking = false,
                policyTreeValidator = Some(_ => true),
              )
            ),
            credentialRepository = Helpers.CredentialRepository.empty,
            clock = Clock.fixed(
              Instant.parse("2022-05-11T12:34:50Z"),
              ZoneOffset.UTC,
            ),
          )
          val result = steps.run()
          result.isAttestationTrusted should be(true)
        }
      }

      it("exposes getAaguid() with the authenticator AAGUID.") {
        val testData = RegistrationTestData.Packed.BasicAttestation
        val steps = finishRegistration(
          testData = testData,
          credentialRepository = Helpers.CredentialRepository.empty,
          allowUntrustedAttestation = true,
        )
        val result = steps.run()
        result.getAaguid should equal(
          testData.response.getResponse.getAttestation.getAuthenticatorData.getAttestedCredentialData.get.getAaguid
        )
      }

      {
        val rp = RelyingParty
          .builder()
          .identity(
            RelyingPartyIdentity
              .builder()
              .id("localhost")
              .name("Example RP")
              .build()
          )
          .credentialRepository(Helpers.CredentialRepository.empty)
          .build()
        val user = UserIdentity.builder
          .name("foo")
          .displayName("Foo User")
          .id(new ByteArray(Array(0, 1, 2, 3)))
          .build()

        val request = PublicKeyCredentialCreationOptions
          .builder()
          .rp(rp.getIdentity)
          .user(user)
          .challenge(ByteArray.fromBase64Url("Y2hhbGxlbmdl"))
          .pubKeyCredParams(List(PublicKeyCredentialParameters.ES256).asJava)
          .build()

        it("exposes isUserVerified() with the UV flag value in authenticator data.") {
          val (pkcWithoutUv, _, _) =
            TestAuthenticator.createUnattestedCredential(
              flags = Some(new AuthenticatorDataFlags(0x00.toByte)),
              challenge = request.getChallenge,
            )
          val (pkcWithUv, _, _) =
            TestAuthenticator.createUnattestedCredential(
              flags = Some(new AuthenticatorDataFlags(0x04.toByte)),
              challenge = request.getChallenge,
            )

          val resultWithoutUv = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(pkcWithoutUv)
              .build()
          )
          val resultWithUv = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(pkcWithUv)
              .build()
          )

          resultWithoutUv.isUserVerified should be(false)
          resultWithUv.isUserVerified should be(true)
        }

        it("exposes isBackupEligible() with the BE flag value in authenticator data.") {
          val (pkcWithoutBackup, _, _) =
            TestAuthenticator.createUnattestedCredential(
              flags = Some(new AuthenticatorDataFlags(0x00.toByte)),
              challenge = request.getChallenge,
            )
          val (pkcWithBackup, _, _) =
            TestAuthenticator.createUnattestedCredential(
              flags = Some(new AuthenticatorDataFlags(0x08.toByte)),
              challenge = request.getChallenge,
            )

          val resultWithoutBackup = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(pkcWithoutBackup)
              .build()
          )
          val resultWithBackup = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(pkcWithBackup)
              .build()
          )

          resultWithoutBackup.isBackupEligible should be(false)
          resultWithBackup.isBackupEligible should be(true)
        }

        it(
          "exposes isBackedUp() with the BS flag value in authenticator data."
        ) {
          val (pkcWithoutBackup, _, _) =
            TestAuthenticator.createUnattestedCredential(
              flags = Some(new AuthenticatorDataFlags(0x00.toByte)),
              challenge = request.getChallenge,
            )
          val (pkcWithBeOnly, _, _) =
            TestAuthenticator.createUnattestedCredential(
              flags = Some(new AuthenticatorDataFlags(0x08.toByte)),
              challenge = request.getChallenge,
            )
          val (pkcWithBackup, _, _) =
            TestAuthenticator.createUnattestedCredential(
              flags = Some(new AuthenticatorDataFlags(0x18.toByte)),
              challenge = request.getChallenge,
            )

          val resultWithBackup = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(pkcWithBackup)
              .build()
          )
          val resultWithBeOnly = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(pkcWithBeOnly)
              .build()
          )
          val resultWithoutBackup = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(request)
              .response(pkcWithoutBackup)
              .build()
          )

          resultWithoutBackup.isBackedUp should be(false)
          resultWithBeOnly.isBackedUp should be(false)
          resultWithBackup.isBackedUp should be(true)
        }

        it(
          "exposes getAuthenticatorAttachment() with the authenticatorAttachment value from the PublicKeyCredential."
        ) {
          val (pkcTemplate, _, _) =
            TestAuthenticator.createUnattestedCredential(challenge =
              request.getChallenge
            )

          forAll { authenticatorAttachment: Option[AuthenticatorAttachment] =>
            val pkc = pkcTemplate.toBuilder
              .authenticatorAttachment(authenticatorAttachment.orNull)
              .build()

            val result = rp.finishRegistration(
              FinishRegistrationOptions
                .builder()
                .request(request)
                .response(pkc)
                .build()
            )

            result.getAuthenticatorAttachment should equal(
              pkc.getAuthenticatorAttachment
            )
          }
        }
      }
    }

  }

  describe("RelyingParty.finishRegistration") {
    it("supports 1023 bytes long credential IDs.") {
      val rp = RelyingParty
        .builder()
        .identity(
          RelyingPartyIdentity
            .builder()
            .id("localhost")
            .name("Test party")
            .build()
        )
        .credentialRepository(Helpers.CredentialRepository.empty)
        .build()

      val pkcco = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("test")
              .displayName("Test Testsson")
              .id(new ByteArray(Array()))
              .build()
          )
          .build()
      )

      forAll(byteArray(1023)) { credId =>
        val credential = TestAuthenticator
          .createUnattestedCredential(challenge = pkcco.getChallenge)
          ._1
          .toBuilder()
          .id(credId)
          .build()

        val result = Try(
          rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(pkcco)
              .response(credential)
              .build()
          )
        )
        result shouldBe a[Success[_]]
        result.get.getKeyId.getId should equal(credId)
        result.get.getKeyId.getId.size should be(1023)
      }
    }

    it("throws RegistrationFailedException in case of errors.") {
      val rp = RelyingParty
        .builder()
        .identity(
          RelyingPartyIdentity
            .builder()
            .id("localhost")
            .name("Test party")
            .build()
        )
        .credentialRepository(Helpers.CredentialRepository.empty)
        .build()

      val pkcco = rp.startRegistration(
        StartRegistrationOptions
          .builder()
          .user(
            UserIdentity
              .builder()
              .name("test")
              .displayName("Test Testsson")
              .id(new ByteArray(Array()))
              .build()
          )
          .build()
      )

      val result = Try(
        rp.finishRegistration(
          FinishRegistrationOptions
            .builder()
            .request(pkcco)
            .response(RegistrationTestData.NoneAttestation.Default.response)
            .build()
        )
      )
      result shouldBe a[Failure[_]]
      result.failed.get shouldBe a[RegistrationFailedException]
      result.failed.get.getMessage should include("Incorrect challenge")
    }
  }

}
