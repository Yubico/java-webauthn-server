package com.yubico.webauthn.rp

import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner


@RunWith(classOf[JUnitRunner])
class RpOperationsSpec extends FunSpec with Matchers {

  describe("§6. Relying Party Operations") {

    describe("§6.1. Registering a new credential") {

      describe("When registering a new credential, represented by a AuthenticatorAttestationResponse structure, as part of a registration ceremony, a Relying Party MUST proceed as follows:") {

        it("1. Perform JSON deserialization on the clientDataJSON field of the AuthenticatorAttestationResponse object to extract the client data C claimed as collected during the credential creation.") {
          fail("Not implemented.")
        }

        it("2. Verify that the challenge in C matches the challenge that was sent to the authenticator in the create() call.") {
          fail("Not implemented.")
        }

        it("3. Verify that the origin in C matches the Relying Party's origin.") {
          fail("Not implemented.")
        }

        it("4. Verify that the tokenBindingId in C matches the Token Binding ID for the TLS connection over which the attestation was obtained.") {
          fail("Not implemented.")
        }

        it("5. Verify that the clientExtensions in C is a proper subset of the extensions requested by the RP and that the authenticatorExtensions in C is also a proper subset of the extensions requested by the RP.") {
          fail("Not implemented.")
        }

        it("6. Compute the hash of clientDataJSON using the algorithm identified by C.hashAlgorithm.") {
          fail("Not implemented.")
        }

        it("7. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.") {
          fail("Not implemented.")
        }

        it("8. Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.") {
          fail("Not implemented.")
        }

        it("9. Determine the attestation statement format by performing an USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].") {
          fail("Not implemented.")
        }

        it("10. Verify that attStmt is a correct, validly-signed attestation statement, using the attestation statement format fmt’s verification procedure given authenticator data authData and the hash of the serialized client data computed in step 6.") {
          fail("Not implemented.")
        }

        it("11. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the AAGUID in the attestation data contained in authData.") {
          fail("Not implemented.")
        }

        describe("12. Assess the attestation trustworthiness using the outputs of the verification procedure in step 10, as follows:") {

          it("If self attestation was used, check if self attestation is acceptable under Relying Party policy.") {
            fail("Not implemented.")
          }

          it("If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 11.") {
            fail("Not implemented.")
          }

          it("Otherwise, use the X.509 certificates returned by the verification procedure to verify that the attestation public key correctly chains up to an acceptable root certificate.") {
            fail("Not implemented.")
          }

        }

        it("13. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credential ID and credential public key contained in authData’s attestation data, as appropriate for the Relying Party's systems.") {
          fail("Not implemented.")
        }

        it("14. If the attestation statement attStmt successfully verified but is not trustworthy per step 12 above, the Relying Party SHOULD fail the registration ceremony.") {
          fail("Not implemented.")
        }

        it("15. NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §5.3.3 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.") {
          fail("Not implemented.")
        }

        it("16. If verification of the attestation statement failed, the Relying Party MUST fail the registration ceremony.") {
          fail("Not implemented.")
        }

      }

    }

  }

}
