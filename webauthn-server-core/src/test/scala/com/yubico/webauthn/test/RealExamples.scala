package com.yubico.webauthn.test

import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.AssertionTestData
import com.yubico.webauthn.RegistrationTestData
import com.yubico.webauthn.WebAuthnTestCodecs
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity

import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate

sealed trait HasClientData {
  def clientData: String
  def clientDataJSON: ByteArray =
    new ByteArray(clientData.getBytes(StandardCharsets.UTF_8))
  def clientDataJSONHash: ByteArray = WebAuthnTestCodecs.sha256(clientDataJSON)
  def collectedClientData: CollectedClientData =
    new CollectedClientData(clientDataJSON)
  def challenge: ByteArray =
    ByteArray.fromBase64Url(
      JacksonCodecs.json().readTree(clientData).get("challenge").textValue()
    )
}

object RealExamples {

  private def base64UrlToString(b64: String): String =
    new String(ByteArray.fromBase64Url(b64).getBytes, StandardCharsets.UTF_8)

  case class AttestationExample(
      clientData: String,
      attestationObjectBytes: ByteArray,
      clientExtensionResultsJson: String = "{}",
      attestationRootCertificate: Option[X509Certificate] = None,
  ) extends HasClientData {
    def attestationObject: AttestationObject =
      new AttestationObject(attestationObjectBytes)
    def authenticatorData: AuthenticatorData =
      attestationObject.getAuthenticatorData
    def credential: PublicKeyCredential[
      AuthenticatorAttestationResponse,
      ClientRegistrationExtensionOutputs,
    ] =
      PublicKeyCredential.parseRegistrationResponseJson(s"""{
        "type": "public-key",
        "id": "${authenticatorData.getAttestedCredentialData.get.getCredentialId.getBase64Url}",
        "response": {
          "clientDataJSON": "${clientDataJSON.getBase64Url}",
          "attestationObject": "${attestationObjectBytes.getBase64Url}"
        },
        "clientExtensionResults": ${clientExtensionResultsJson}
      }""")
  }

  case class AssertionExample(
      id: ByteArray,
      `type`: String = "public-key",
      clientData: String,
      authDataBytes: ByteArray,
      sig: ByteArray,
      clientExtensionResultsJson: String = "{}",
  ) extends HasClientData {
    def authenticatorData: AuthenticatorData =
      new AuthenticatorData(authDataBytes)
    def credential: PublicKeyCredential[
      AuthenticatorAssertionResponse,
      ClientAssertionExtensionOutputs,
    ] =
      PublicKeyCredential.parseAssertionResponseJson(s"""{
        "type": "public-key",
        "id": "${id.getBase64Url}",
        "response": {
          "clientDataJSON": "${clientDataJSON.getBase64Url}",
          "authenticatorData": "${authDataBytes.getBase64Url}",
          "signature": "${sig.getBase64Url}"
        },
        "clientExtensionResults": ${clientExtensionResultsJson}
      }""")
  }

  case class Example(
      rp: RelyingPartyIdentity,
      user: UserIdentity,
      attestation: AttestationExample,
      assertion: Option[AssertionExample] = None,
  ) {
    def this(
        rp: RelyingPartyIdentity,
        user: UserIdentity,
        attestation: AttestationExample,
        assertion: AssertionExample,
    ) = this(rp, user, attestation, Some(assertion))

    def attestationCert: ByteArray =
      new ByteArray(
        attestation.attestationObject.getAttestationStatement
          .get("x5c")
          .get(0)
          .binaryValue()
      )

    def asRegistrationTestData: RegistrationTestData =
      RegistrationTestData(
        alg = COSEAlgorithmIdentifier
          .fromPublicKey(
            attestation.attestationObject.getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
          )
          .get,
        attestationObject = attestation.attestationObjectBytes,
        clientDataJson = attestation.clientData,
        privateKey = None,
        rpId = rp,
        userId = user,
        assertion = assertion.map({ assertion =>
          AssertionTestData(
            request = AssertionRequest
              .builder()
              .publicKeyCredentialRequestOptions(
                PublicKeyCredentialRequestOptions
                  .builder()
                  .challenge(assertion.collectedClientData.getChallenge)
                  .build()
              )
              .username(user.getName)
              .build(),
            response = assertion.credential,
          )
        }),
        attestationRootCertificate = attestation.attestationRootCertificate,
      )
  }

  val YubiKeyNeo = new Example(
    RelyingPartyIdentity.builder().id("example.com").name("Example RP").build(),
    UserIdentity
      .builder()
      .name("test@example.org")
      .displayName("A. User")
      .id(ByteArray.fromBase64Url("dXNlcl9pZA=="))
      .build(),
    AttestationExample(
      """{"type": "webauthn.create", "clientExtensions": {}, "challenge": "Y2hhbGxlbmdl", "origin": "https://example.com"}""",
      ByteArray.fromBase64Url("o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgZAIktn1uQmeCpXkStM74_oaFdb0MH0-J0k4ZXmIXM18CIQDZgPvwVDPBsTfreHAqoWa6n7v5bRS3cn0rcthSLAmDaGN4NWOBWQJTMIICTzCCATegAwIBAgIEWzpHQjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowMTEvMC0GA1UEAwwmWXViaWNvIFUyRiBFRSBTZXJpYWwgMjM5MjU3MzUzMjgyMDQ2MTAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR-OFbId0OQrrorm-5x_bGglxHhfuEK-vP9tO3JRNO_gvmSTfgvjtZPYIlQ4Cr6gRt_Hfn6WDjT-Xt0Q14pfb20ozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMjATBgsrBgEEAYLlHAIBAQQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAQEAa27ZcXkZ-pa1ywtQqWf1MeHFNxSGUDwpKBAUC7zCfgd8pINbK_1VHhbp3Q6tDiH-PO0wZnqE-oDQGi4KxFUFYyDjJszYL4HoVwUSORHeu8zCpO_zVoqUOR8OSeuDwZgububzfPu3NlaWDBkgUhhYoZDyCtFdGPyqT2foxk3iDpjzlG8zfU-t2pYIIAF9Q_LJv-XEkYqNGsAEZMxKMeNoB3n6p5mWxULriqoJPiajFYInzu9Kk7OiznJJ01-xovAGvtVeiFOZZljUkLCVa5eX7INYzdaa9L3LAHW81IdsoE7yFL2OPNcPR0kOiqsMoiJ6sgYy4MRTuxIu2ke-lIH5UWhhdXRoRGF0YVjEo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQBeSCzJvnCNSyal5T2DPO0ypt2760sLlwynV_0Id2WiXWiq-Rv0MY1BfwD4QFJpryrRUHDgKt-T8ztr-DQfIKT2lAQIDJiABIVggOclPu93GlKkl5vhlfGaRbP6EzQIi7fzygbIfXNw0eSMiWCDWsNICHP4XJKb-geNWjE_64zkpghajCvwYwLl18uKokQ=="),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("F5ILMm-cI1LJqXlPYM87TKm3bvrSwuXDKdX_Qh3ZaJdaKr5G_QxjUF_APhAUmmvKtFQcOAq35PzO2v4NB8gpPQ=="),
      clientData = """{"type": "webauthn.get", "clientExtensions": {}, "challenge": "Q0hBTExFTkdF", "origin": "https://example.com"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcBAAAAAQ=="
      ),
      sig =
        ByteArray.fromBase64Url("MEUCIFEYoFCb4DZmBWm_5ho_0RpLQfZIvS3sU-HQi5O85BiuAiEAmj7_8Kr--lGm7YhM6-4FvFEIGzKlzFt7F6SxHVhmNfo="),
    ),
  )

  val YubiKey4 = new Example(
    RelyingPartyIdentity.builder().id("example.com").name("Example RP").build(),
    UserIdentity
      .builder()
      .name("test@example.org")
      .displayName("A. User")
      .id(ByteArray.fromBase64Url("dXNlcl9pZA=="))
      .build(),
    AttestationExample(
      """{"type": "webauthn.create", "clientExtensions": {}, "challenge": "Y2hhbGxlbmdl", "origin": "https://example.com"}""",
      ByteArray.fromBase64Url("o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgMMS3Sk-YpRfKh7lGev4vNApGpQD0Md6l2bwWGsQIXWUCIQD9Krgg7JQVL5jLZhqHE-n7auwBcDdQvqpQ4VddgKR9S2N4NWOBWQJTMIICTzCCATegAwIBAgIEPGgpTTANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowMTEvMC0GA1UEAwwmWXViaWNvIFUyRiBFRSBTZXJpYWwgMjM5MjU3MzQ4MTExMTc5MDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS932eT23eUw1Axce0sTUVK2XNmdRpIuqXZ-bVqOiCBeWtO3yvNe5J6FJMQ-8RoR2_8V5KpfbYvoChrxqMgAg5jozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNTATBgsrBgEEAYLlHAIBAQQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAQEAqsANUQl-7BWkhrN5vMSDQPhn05cuzmpn-6Rw42DGRFnwrThC0_8IHnHqiVOXGyP5JcCtAMJHMRhSBvCzqRkp-5G3ZrU_4TNSKoNYuNEgtKv7f-jvJHtk_8amIUrB2b5zNv3g86gYP5NLUhh19eP3iYCvlwpbHgQqOHbXS6i-7-kt0uNzzGRByJStfNmk9H2tPaT-r0eRmEdT41oInOTL49PINurQoqfOpWFa1-RIEIbDd7NmRNL7mWu84pshrbiV95OC7sVJPk7BM8IWfwdx9ZkxcxIP8o1T6IGol0DBMs88NGgsu89OXb3B4IAiH4dSmYFB3RSW1w86sD8sW8B_rWhhdXRoRGF0YVjEo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEZ3ZpSx4x3b5ta9SnTMyCNtIAkzgZwfRff5n251aUcLfadvNqYhCylFC1FdfljBSHxcibx2oD45K2HSE3sCGfSlAQIDJiABIVggREuYlwMvN1mWVAPf8QrgB-cUNJYyS8vwZtr2tAWnoCQiWCAFm1_ct7jy-C_IQr73ChoiLZKkEAOnCJ_F5rf3wlOT5Q=="),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("RndmlLHjHdvm1r1KdMzII20gCTOBnB9F9_mfbnVpRwt9p282piELKUULUV1-WMFIfFyJvHagPjkrYdITewIZ9A=="),
      clientData = """{"type": "webauthn.get", "clientExtensions": {}, "challenge": "Q0hBTExFTkdF", "origin": "https://example.com"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcBAAAAAA=="
      ),
      sig =
        ByteArray.fromBase64Url("MEQCIDniM0szLdfVU1CtXMjUmbYmAU3cL5F8umwXbIhqmTFfAiBHxk-ZOxTzXIMd0ghIFVpaJBWG-6lNJP6DOrkufJVx_Q=="),
    ),
  )

  val YubiKey5 = new Example(
    RelyingPartyIdentity.builder().id("example.com").name("Example RP").build(),
    UserIdentity
      .builder()
      .name("test@example.org")
      .displayName("A. User")
      .id(ByteArray.fromBase64Url("dXNlcl9pZA=="))
      .build(),
    AttestationExample(
      """{"type": "webauthn.create", "clientExtensions": {}, "challenge": "Y2hhbGxlbmdl", "origin": "https://example.com"}""",
      ByteArray.fromBase64Url("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgCrcg9FJhbV35puNRlN36gSO9_YNWweirVdB2n3Ojez0CIQDOvSCusMldIS57ittkKJ9cne9RYQS6a--ivsKFYWrAIWN4NWOBWQLAMIICvDCCAaSgAwIBAgIEA63wEjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbTELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgNjE3MzA4MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZnoecFi233DnuSkKgRhalswn-ygkvdr4JSPltbpXK5MxlzVSgWc-9x8mzGysdbBhEecLAYfQYqpVLWWosHPoXo2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBD6K5ncnjlCV4-SSjDSPEEYMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBACjrs2f-0djw4onryp_22AdXxg6a5XyxcoybHDjKu72E2SN9qDGsIZSfDy38DDFr_bF1s25joiu7WA6tylKA0HmEDloeJXJiWjv7h2Az2_siqWnJOLic4XE1lAChJS2XAqkSk9VFGelg3SLOiifrBet-ebdQwAL-2QFrcR7JrXRQG9kUy76O2VcSgbdPROsHfOYeywarhalyVSZ-6OOYK_Q_DLIaOC0jXrnkzm2ymMQFQlBAIysrYeEM1wxiFbwDt-lAcbcOEtHEf5ZlWi75nUzlWn8bSx_5FO4TbZ5hIEcUiGRpiIBEMRZlOIm4ZIbZycn_vJOFRTVps0V0S4ygtDdoYXV0aERhdGFYxKN5pvbur7mlXjeMEYA04nUeaC-rny0wqxPSElWGzhlHQQAAAAv6K5ncnjlCV4-SSjDSPEEYAED94RxjDuKGTpu5usg0Vcee9gqqhDVGw1__eyvx3YUhH7gba6zYjbwI1e1CZa78jZq8167iUIHbM_kNbyXIHSNhpQECAyYgASFYIIIyZu4ct876xj7sKSV90mbX0PpGLuRIRGu6IxnWUhD9Ilggw2qT1jtmMhn-X9raOZxqjWkzfdF8aJqFpvp3QXI-vNY="),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("_eEcYw7ihk6bubrINFXHnvYKqoQ1RsNf_3sr8d2FIR-4G2us2I28CNXtQmWu_I2avNeu4lCB2zP5DW8lyB0jYQ=="),
      clientData = """{"type": "webauthn.get", "clientExtensions": {}, "challenge": "Q0hBTExFTkdF", "origin": "https://example.com"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcBAAAADA=="
      ),
      sig =
        ByteArray.fromBase64Url("MEQCIE5k9IsMKGNpn6l29eIuoXkkuyZmSTePbQRKrWUaF5IxAiA-3veAkhDgW06BA-L_TLNw8KZDzHzU5zaw6Guqk-_J5Q=="),
    ),
  )

  val YubiKey5Nfc = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("dfgfdfgf")
      .displayName("dfgfdfgf")
      .id(
        ByteArray.fromBase64Url("FBUasomeAb_g7CUQf_Ub6PtpXNJ8843IOgsnE50JLP0")
      )
      .build(),
    AttestationExample(
      """{"type":"webauthn.create","challenge":"0b-5-z3_EvP6pqaBj6Fu7A4M5SdefgZ_jcAoFa6_miU","origin":"https://demo.yubico.com","crossOrigin":false}""",
      ByteArray.fromBase64Url("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgZUEF7FMB8dEzallsJvUFVhHRU8xdWDkDwQQI-ZU8XRMCIQCqzI3-lWRlSEBLGk2XVqkp72q2QzbhdOzZyWOrke4jsmN4NWOBWQLAMIICvDCCAaSgAwIBAgIEA63wEjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbTELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgNjE3MzA4MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZnoecFi233DnuSkKgRhalswn-ygkvdr4JSPltbpXK5MxlzVSgWc-9x8mzGysdbBhEecLAYfQYqpVLWWosHPoXo2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBD6K5ncnjlCV4-SSjDSPEEYMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBACjrs2f-0djw4onryp_22AdXxg6a5XyxcoybHDjKu72E2SN9qDGsIZSfDy38DDFr_bF1s25joiu7WA6tylKA0HmEDloeJXJiWjv7h2Az2_siqWnJOLic4XE1lAChJS2XAqkSk9VFGelg3SLOiifrBet-ebdQwAL-2QFrcR7JrXRQG9kUy76O2VcSgbdPROsHfOYeywarhalyVSZ-6OOYK_Q_DLIaOC0jXrnkzm2ymMQFQlBAIysrYeEM1wxiFbwDt-lAcbcOEtHEf5ZlWi75nUzlWn8bSx_5FO4TbZ5hIEcUiGRpiIBEMRZlOIm4ZIbZycn_vJOFRTVps0V0S4ygtDdoYXV0aERhdGFYxMRs74KtG1Rkd1kdAIsIdZ7D5tLstPOUdL_qaWmSXQO3QQAAADn6K5ncnjlCV4-SSjDSPEEYAECSDhJoaRjVyhU9DO24CFhDHIm8rwh5dHFRVONEpTj2eXiqpzRs5xNoNlEq5cotavl1nTbQ6DhXaOYm_ulT16RMpQECAyYgASFYIJbLqy9JV7ETZUEdPtNzlfl6fBTDZNgioYpDIxIVhRGOIlggS8YE-ZzHh63D4jN3vShnN3F7heKxyJuAApMeRvTJuc8"),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("kg4SaGkY1coVPQztuAhYQxyJvK8IeXRxUVTjRKU49nl4qqc0bOcTaDZRKuXKLWr5dZ020Og4V2jmJv7pU9ekTA"),
      clientData = """{"type":"webauthn.get","challenge":"AK6EVGBeT_DvQQk3hoUCocO8k3WVvnQnwL5Kd2oFWzM","origin":"https://demo.yubico.com","crossOrigin":false,"extra_keys_may_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v-ppaZJdA7cBAAAAOg"
      ),
      sig =
        ByteArray.fromBase64Url("MEUCIDkZa6d7HwRxGCZdAldFuTo4qUZvaV8j7IYGjO74liKcAiEAj_PLArWm-VylAUsKgWoj50NQSpnn_qhZEgasgfWmG1Y"),
    ),
  )

  val YubiKey5NfcPost5cNfc = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(
        ByteArray.fromBase64Url("a9n4HpAeWRGIKzLWEkgia_yeBm_VGLgNj5uND9wyuOg")
      )
      .build(),
    AttestationExample(
      """{"challenge":"q17naevQpc84vHK9Ge6hwCXnLt3LmlFqwVJ-YETQHwk","clientExtensions":{},"hashAlgorithm":"SHA-256","origin":"https://demo.yubico.com","type":"webauthn.create"}""",
      ByteArray.fromBase64Url("o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhALT8jIrN8OmV77OopLGKHXLupu_2yEHVEk9eaMmVlqGPAiBfgBugvPNvhED79Dbom5yBUxh47IqHZlIyiZGujZMb-GN4NWOBWQLBMIICvTCCAaWgAwIBAgIEHo-HNDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNTEyNzIyNzQwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqHn4IzjtFJS6wHBLzH_GY9GycXFZdiQxAcdgURXXwVKeKBwcZzItOEtc1V3T6YGNX9hcIq8ybgxk_CCv4z8jZqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQL8BXn4ETR-qxFrtajbkgKjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCGk_9i3w1XedR0jX_I0QInMYqOWA5qOlfBCOlOA8OFaLNmiU_OViS-Sj79fzQRiz2ZN0P3kqGYkWDI_JrgsE49-e4V4-iMBPyCqNy_WBjhCNzCloV3rnn_ZiuUc0497EWXMF1z5uVe4r65zZZ4ygk15TPrY4-OJvq7gXzaRB--mDGDKuX24q2ZL56720xiI4uPjXq0gdbTJjvNv55KV1UDcJiK1YE0QPoDLK22cjyt2PjXuoCfdbQ8_6Clua3RQjLvnZ4UgSY4IzxMpKhzufismOMroZFnYG4VkJ_N20ot_72uRiAkn5pmRqyB5IMtERn-v6pzGogtolp3gn1G0ZAXaGF1dGhEYXRhWMTEbO-CrRtUZHdZHQCLCHWew-bS7LTzlHS_6mlpkl0Dt0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAYiZiFWXtspQv_5_ZmKPIsSIV6yqQb1evWuRAfdipNhRgUWo2lUefvU8q7y6MtbjgYhoVA-5pGTIZv-r7oNi1YKUBAgMmIAEhWCDMHeuArInpowl_rB8S9AFGO-G_VmhM-0tM2ggV1SB7NSJYIPvfLUW8-Aoiqd4eQF649w1u274AFkg7fAvXya_G6dP9"),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("YiZiFWXtspQv_5_ZmKPIsSIV6yqQb1evWuRAfdipNhRgUWo2lUefvU8q7y6MtbjgYhoVA-5pGTIZv-r7oNi1YA"),
      clientData = """{"challenge":"YM-QmlCkDwETwz4XOfqgZTv6pG8NMFtIRkoNaDaY5jw","clientExtensions":{},"hashAlgorithm":"SHA-256","origin":"https://demo.yubico.com","type":"webauthn.get"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v-ppaZJdA7cBAAAAAw"
      ),
      sig =
        ByteArray.fromBase64Url("MEYCIQCaLSBboXlSI5uff61mlXG_S9OXRRT5kx-0KuHBu8Fm0QIhAIeNMEJkH1wzaKi2NZy5u8aJm4lOj9vsFdSkNiMhcVjw"),
    ),
  )

  val YubiKey5cNfc = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(
        ByteArray.fromBase64Url("a9n4HpAeWRGIKzLWEkgia_yeBm_VGLgNj5uND9wyuOg")
      )
      .build(),
    AttestationExample(
      """{"challenge":"TYD4p7LaPJjcQRlvZmXaEryYznCbS8farrjvBTPIaMc","clientExtensions":{},"hashAlgorithm":"SHA-256","origin":"https://demo.yubico.com","type":"webauthn.create"}""",
      ByteArray.fromBase64Url("o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhALIMxk1lmndZxLUHPct8ggYZGAXKiYEzsj5SECYGa6WbAiBt4a_4vDP-lYjvm344LxoXfEAyjEiqPIBsYsSuzidPrGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEHo-HNDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNTEyNzIyNzQwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqHn4IzjtFJS6wHBLzH_GY9GycXFZdiQxAcdgURXXwVKeKBwcZzItOEtc1V3T6YGNX9hcIq8ybgxk_CCv4z8jZqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQL8BXn4ETR-qxFrtajbkgKjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCGk_9i3w1XedR0jX_I0QInMYqOWA5qOlfBCOlOA8OFaLNmiU_OViS-Sj79fzQRiz2ZN0P3kqGYkWDI_JrgsE49-e4V4-iMBPyCqNy_WBjhCNzCloV3rnn_ZiuUc0497EWXMF1z5uVe4r65zZZ4ygk15TPrY4-OJvq7gXzaRB--mDGDKuX24q2ZL56720xiI4uPjXq0gdbTJjvNv55KV1UDcJiK1YE0QPoDLK22cjyt2PjXuoCfdbQ8_6Clua3RQjLvnZ4UgSY4IzxMpKhzufismOMroZFnYG4VkJ_N20ot_72uRiAkn5pmRqyB5IMtERn-v6pzGogtolp3gn1G0ZAXaGF1dGhEYXRhWMTEbO-CrRtUZHdZHQCLCHWew-bS7LTzlHS_6mlpkl0Dt0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAwNqAJZnNrdJI3M00vcUGRnsJ8jaIdmw6h0vN-otjgHKMcL4ymacqevxbk2Rb6gBAl7Zun9MwzYXBVrs5aZMPq6UBAgMmIAEhWCBJr3rb8dowo8mLlcq6vqIntuJG8KO7C4idTE1NzvUkgyJYIE7fArHgQIuZQt__H-5ujH6ZH515OqgQKSTZD9PfzXpp"),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("wNqAJZnNrdJI3M00vcUGRnsJ8jaIdmw6h0vN-otjgHKMcL4ymacqevxbk2Rb6gBAl7Zun9MwzYXBVrs5aZMPqw"),
      clientData = """{"challenge":"uF0u0XJg7NyFuvBVHrtBPKYBC5h-1_P9Dn9lmerQCBQ","clientExtensions":{},"hashAlgorithm":"SHA-256","origin":"https://demo.yubico.com","type":"webauthn.get"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v-ppaZJdA7cBAAAAAQ"
      ),
      sig =
        ByteArray.fromBase64Url("MEYCIQCVio9swx3DxzBUr4eexfpKP2wmoeEQR0nYp_QxB_rFowIhAOIRFy-7-CP41Q65l5eJIZH49wnj-rrdPklWlBkHcoHG"),
    ),
  )

  val YubiKey5Nano = new Example(
    RelyingPartyIdentity.builder().id("example.com").name("Example RP").build(),
    UserIdentity
      .builder()
      .name("test@example.org")
      .displayName("A. User")
      .id(ByteArray.fromBase64Url("dXNlcl9pZA=="))
      .build(),
    AttestationExample(
      """{"type": "webauthn.create", "clientExtensions": {}, "challenge": "Y2hhbGxlbmdl", "origin": "https://example.com"}""",
      ByteArray.fromBase64Url("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAMw3heLnLh7oOq4gwxQRviDPT0_VDxys8Kq2MFOfTZBzAiEAtL3D6ZqtiupoAMqntqi07OrEl5RJGJkoZ7bLwepVJQBjeDVjgVkCwTCCAr0wggGloAMCAQICBBisRsAwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDQxMzk0MzQ4ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHnqOyx8SXAQYiMM0j_rYOUpMXHUg_EAvoWdaw-DlwMBtUbN1G7PyuPj8w-B6e1ivSaNTB69N7O8vpKowq7rTjqjbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEMtpSB6P90A5k-wKJymhVKgwDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAl50Dl9hg-C7hXTEceW66-yL6p-CE2bq0xhu7V_PmtMGKSDe4XDxO2-SDQ_TWpdmxztqK4f7UkSkhcwWOXuHL3WvawHVXxqDo02gluhWef7WtjNr4BIaM-Q6PH4rqF8AWtVwqetSXyJT7cddT15uaSEtsN21yO5mNLh1DBr8QM7Wu-Myly7JWi2kkIm0io1irfYfkrF8uCRqnFXnzpWkJSX1y9U4GusHDtEE7ul6vlMO2TzT566Qay2rig3dtNkZTeEj-6IS93fWxuleYVM_9zrrDRAWVJ-Vt1Zj49WZxWr5DAd0ZETDmufDGQDkSU-IpgD867ydL7b_eP8u9QurWeWhhdXRoRGF0YVjEo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdFAAAAyMtpSB6P90A5k-wKJymhVKgAQApDelLpYd9AP-NbX7v8lJelMv5xVvJq1u4va8qaLTf2e4Tf7QL7F4nkZZnfTVBv74xF0i8794sPbpK--e0N8-SlAQIDJiABIVggXaCve37FWbdyNEXiSmuDUdsc0K-UDHnYEQ-Sc3PHxcAiWCD7VMEBw6F_IOsfg7DISuN8aT70W14W1NQCX0xjQSUnsw=="),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("CkN6Uulh30A_41tfu_yUl6Uy_nFW8mrW7i9rypotN_Z7hN_tAvsXieRlmd9NUG_vjEXSLzv3iw9ukr757Q3z5A=="),
      clientData = """{"type": "webauthn.get", "clientExtensions": {}, "challenge": "Q0hBTExFTkdF", "origin": "https://example.com"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcFAAAAyQ=="
      ),
      sig =
        ByteArray.fromBase64Url("MEYCIQCUeExQH6ZbZxoyiYEqFdmMyIeu-klCkyREiB1ekfBItgIhAKcsV2cK-PXubj96AYk5DWU_qE-M6ZmH8AQBYW9RF56P"),
    ),
  )

  val YubiKey5Ci = new Example(
    RelyingPartyIdentity.builder().id("example.com").name("Example RP").build(),
    UserIdentity
      .builder()
      .name("test@example.org")
      .displayName("A. User")
      .id(ByteArray.fromBase64Url("dXNlcl9pZA=="))
      .build(),
    AttestationExample(
      """{"type": "webauthn.create", "clientExtensions": {}, "challenge": "Y2hhbGxlbmdl", "origin": "https://example.com"}""",
      ByteArray.fromBase64Url("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgXOZEuIaBrKT5VYJu9_D410HgJRm1SenwlKiXtcQxe0ICIG1_ycPCKHPjEsgRFVr4WdK5IY8K7aCyAc03c1-wnBJCY3g1Y4FZAsEwggK9MIIBpaADAgECAgQr8Xx4MA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBuMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMScwJQYDVQQDDB5ZdWJpY28gVTJGIEVFIFNlcmlhbCA3MzcyNDYzMjgwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR0wseEI8hxLptI8llYZvxwQK5M3wfXd9WFrwSTme36kjy-tJ-XFvn1WnhsNCUfyPNePehbVnBQOMcLoScZYHmLo2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwICJDAhBgsrBgEEAYLlHAEBBAQSBBDF71X_rZpLn7WAreuv4CbQMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBAItuk3adeE1u6dkA0nECf8J35Lgm5mw5udSIucstLQU9ZrTVNjwXugnxsT5oVriRN7o1BB-Lz7KJmtDw34kvh_uA11A9Ksf6veIV3hK-ugN7WNok7gn0t6IWOZF1xVr7lyo0XgbV88Kh-_D1biUqc5u49qSvTH-Jx1WrUxeFh1S1CTpmvmYGdzgWE32qLsNeoscPkbtkVSYbB8hwPb7SbV_WbBBLzJEPn79oMJ_e-63B12iLdyu2K_PKuibBsqSVHioe6cnvksZktkDykn-ZedRDpNOyBGo-89eBA9tLIYx_bP8Mg9tCoIP8GZzh2P2joujOF4F0O1xkICNI9MB3-6JoYXV0aERhdGFYxKN5pvbur7mlXjeMEYA04nUeaC-rny0wqxPSElWGzhlHQQAAAATF71X_rZpLn7WAreuv4CbQAEDDAvEvv-vY_dFxV_gwT7mhKUN9M6PatW8FqDSEjXAaJL4EjL5exyo-FIaoqgH4lfmw-19_6ao6j9zPlFGHBmUOpQECAyYgASFYILUgImoYph7H0FqX_aKS3A4Ph1Aki_Edg9YB6oxw7nrIIlgghBKeVu0Z4cV6-Cya1H2ZTeeWdisBlK6QWDM89ne6794="),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("wwLxL7_r2P3RcVf4ME-5oSlDfTOj2rVvBag0hI1wGiS-BIy-XscqPhSGqKoB-JX5sPtff-mqOo_cz5RRhwZlDg=="),
      clientData = """{"type": "webauthn.get", "clientExtensions": {}, "challenge": "Q0hBTExFTkdF", "origin": "https://example.com"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcBAAAABw=="
      ),
      sig =
        ByteArray.fromBase64Url("MEQCIHqWh09siRtXwUCVOnTrWUTfJfe9zv0_-WYd376qUcBqAiBMdsCPp-LpUEhgSbOz8y6hS1YTKFgpN-nIrpYDTxQhiA=="),
    ),
  )

  val SecurityKey = new Example(
    RelyingPartyIdentity.builder().id("example.com").name("Example RP").build(),
    UserIdentity
      .builder()
      .name("test@example.org")
      .displayName("A. User")
      .id(ByteArray.fromBase64Url("dXNlcl9pZA=="))
      .build(),
    AttestationExample(
      """{"type": "webauthn.create", "clientExtensions": {}, "challenge": "Y2hhbGxlbmdl", "origin": "https://example.com"}""",
      ByteArray.fromBase64Url("o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAM_R8LLPIBxj07Cimg1QVoFD2Y3xqQvbEYEdkbJLsQgiAiAEVIoe5lvTKHK9vCJBHJXS1uWBxFNEFv7im0cs2CjhcWN4NWOBWQIgMIICHDCCAQagAwIBAgIEOGbfdTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCsxKTAnBgNVBAMMIFl1YmljbyBVMkYgRUUgU2VyaWFsIDEzODMxMTY3ODYxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN438dAxzm5RyTtPVI7m4doEGVsE96G-vrs842Q9V4sgKG_4LMNxTs13n0EW5bcuPK_lPqOC5AxY8f27cLkh7caMSMBAwDgYKKwYBBAGCxAoBAQQAMAsGCSqGSIb3DQEBCwOCAQECGkdkygCJz5KtuH-oSFOOcsw-_bs0eSlDBHuCFqk5uvTBE1YqNFthR1l5aXlHvOZxqmp8Bnlu1OuxuP1gJxm3Hes89kLpjbHZZm_wHm23T0WveWfARtbm_0tOCaMUGDS2mvFkZczezzoKgJwKpJp7GUP1vU49rjvcz95qcTpJJp6s-z-c7eC6eca7-6deYRjiDw-VfqYe7VJogibKtC33kQN-l-2l4t9gKdK7f8Mn50Xn-fWGK-0psGjLlyo2yGUi3rLHGWUzM13frri2-g21AmrKhFQZBhqk0XwHDpj6L9Zx1KzQwpDkdKG0eD7CRuD4mpiHwKTXqFxmKRm6JOp7nGhhdXRoRGF0YVjEo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQCdfKS1ueJ9oKJVudbjt1UiNbDssecI5S-KjmJiG0i5OGGd4oF9xDvrXC4wfLalyG8CZyOC0yWGRdxOHY2zlreylAQIDJiABIVggZ2eg0SmeEp6vayyOWFQIsY8WaYPde8QgyNVLRcHVWmoiWCBxXpYVrCowr7PGNQlz7iFTUWQ1z8R1cPxRfHlm6DvZRw=="),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("J18pLW54n2golW51uO3VSI1sOyx5wjlL4qOYmIbSLk4YZ3igX3EO-tcLjB8tqXIbwJnI4LTJYZF3E4djbOWt7A=="),
      clientData = """{"type": "webauthn.get", "clientExtensions": {}, "challenge": "Q0hBTExFTkdF", "origin": "https://example.com"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcBAAAAtw=="
      ),
      sig =
        ByteArray.fromBase64Url("MEUCIHgLEzmn8hKOXC0qBXDFBZ7a2GLrwho8uqyd1ZqwV9YCAiEA-3Y8g4ifwTxT1ROtA4uBmVzzfzlh9o0ijY9eEhGJEkg="),
    ),
  )

  val SecurityKey2 = new Example(
    RelyingPartyIdentity.builder().id("example.com").name("Example RP").build(),
    UserIdentity
      .builder()
      .name("test@example.org")
      .displayName("A. User")
      .id(ByteArray.fromBase64Url("dXNlcl9pZA=="))
      .build(),
    AttestationExample(
      """{"type": "webauthn.create", "clientExtensions": {}, "challenge": "Y2hhbGxlbmdl", "origin": "https://example.com"}""",
      ByteArray.fromBase64Url("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgMPJLGsBqS-rEdPOtwv50McRd8TLeMUBdqCdN9BQlqjoCICh5colw68TfL2QTa9OXPkpobZrePGqlfOzv4bzY9fffY3g1Y4FZAsIwggK-MIIBpqADAgECAgR0hv3CMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBvMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxOTU1MDAzODQyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElV3zrfckfTF17_2cxPMaToeOuuGBCVZhUPs4iy5fZSe_V0CapYGlDQrFLxhEXAoTVIoTU8ik5ZpwTlI7wE3r7aNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQ-KAR84wKTRWABhcRH57cfTAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAxXEiA5ppSfjhmib1p_Qqob0nrnk6FRUFVb6rQCzoAih3cAflsdvZoNhqR4jLIEKecYwdMm256RusdtdhcREifhop2Q9IqXIYuwD8D5YSL44B9es1V-OGuHuITrHOrSyDj-9UmjLB7h4AnHR9L4OXdrHNNOliXvU1zun81fqIIyZ2KTSkC5gl6AFxNyQTcChgSDgr30Az8lpoohuWxsWHz7cvGd6Z41_tTA5zNoYa-NLpTMZUjQ51_2Upw8jBiG5PEzkJo0xdNlDvGrj_JN8LeQ9a0TiEVPfhQkl-VkGIuvEbg6xjGQfD-fm8qCamykHcZ9i5hNaGQMqITwJi3KDzuaGF1dGhEYXRhWMSjeab27q-5pV43jBGANOJ1Hmgvq58tMKsT0hJVhs4ZR0EAAAAA-KAR84wKTRWABhcRH57cfQBAc17o2YwQc1hkrTX_Plsl34A6_rK5Fa6pJGIgkkTgVx3lEF_fnOa-M13COp5hgPrVVuDIGv5HI9gJH9JbOoxJS6UBAgMmIAEhWCDNva3Ohd7wYRZlfmu6V0J8Iy8sdGOLTG_dAlDxvRdSjyJYILal-lroy3ltDP4McgzBN5hKd9OSVn6dMgRBVjDWBtsN"),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("c17o2YwQc1hkrTX_Plsl34A6_rK5Fa6pJGIgkkTgVx3lEF_fnOa-M13COp5hgPrVVuDIGv5HI9gJH9JbOoxJSw=="),
      clientData = """{"type": "webauthn.get", "clientExtensions": {}, "challenge": "Q0hBTExFTkdF", "origin": "https://example.com"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcBAAAAAQ=="
      ),
      sig =
        ByteArray.fromBase64Url("MEUCIQC68JtgAd_DEc6UZYjn3eskqVGpIu64yQlXKx25HDXniwIgDQH8uK-md90SHKWbjj8qvqmgdmc4M7ZanCFLmQZRTCI="),
    ),
  )

  val SecurityKeyNfc = new Example(
    RelyingPartyIdentity.builder().id("example.com").name("Example RP").build(),
    UserIdentity
      .builder()
      .name("test@example.org")
      .displayName("A. User")
      .id(ByteArray.fromBase64Url("dXNlcl9pZA=="))
      .build(),
    AttestationExample(
      """{"type": "webauthn.create", "clientExtensions": {}, "challenge": "Y2hhbGxlbmdl", "origin": "https://example.com"}""",
      ByteArray.fromBase64Url("o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAJKRPuYlfW8dZZlsJrJiwA-BvAyOvIe1TScv5qlek1SQAiAnglgs-nRjA7kpc61PewQ4VULjdlzLmReI7-MJT1TLrGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEMAIspTANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgODA1NDQ4ODY5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-66HSEytO3plXno3zPhH1k-zFwWxESIdrTbQp4HSEuzFum1Mwpy8itoOosBQksnIrefLHkTRNUtV8jIrFKAvbaNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBlZXnJy-X3fJfNdlIdIQlFpO5-A5uM41jJ2XgdRag_8rSxXCz98t_jyoWth5FQF9As96Ags3p-Lyaqb1bpEc9RfmkxiiqwDzDI56Sj4HKlANF2tddm-ew29H9yaNbpU5y6aleCeH2rR4t1cFgcBRAV84IndIH0cYASRnyrFbHjI80vlPNR0z4j-_W9vYEWBpLeS_wrdKPVW7C7wyuc4bobauCyhElBPZUwblR_Ll0iovmfazD17VLCBMA4p_SVVTwSXpKyZjMiCotj8mDhQ1ymhvCepkK82EwnrBMJIzCi_joxAXqxLPMs6yJrz_hFUkZaloa1ZS6f7aGAmAKhRNO2aGF1dGhEYXRhWMSjeab27q-5pV43jBGANOJ1Hmgvq58tMKsT0hJVhs4ZR0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAJT086Ym5LhLsK6MRwYRSdjVn9jVYVtwiGwgq_bDPpVuI3aaOW7UQfqGWdos-kVwHnQccbDRnQDvQmCDqy6QdSaUBAgMmIAEhWCCRGd2Bo0vIj-suQxM-cOCXovv1Ag6azqHn8PE31Fcu4iJYIOiLha_PR9JwOhCw4SC2Xq7cOackGAMsq4UUJ_IRCCcq"),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("JT086Ym5LhLsK6MRwYRSdjVn9jVYVtwiGwgq_bDPpVuI3aaOW7UQfqGWdos-kVwHnQccbDRnQDvQmCDqy6QdSQ=="),
      clientData = """{"type": "webauthn.get", "clientExtensions": {}, "challenge": "Q0hBTExFTkdF", "origin": "https://example.com"}""",
      authDataBytes = ByteArray.fromBase64Url(
        "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcBAAAADA=="
      ),
      sig =
        ByteArray.fromBase64Url("MEYCIQD8tVtVU-esAvCSNVR4JLfW0MKf2C_Rb1Xn4UBBS4jbmwIhAM5AfKuhVrHcMfcNwVDYQ4q7qU_a6avSWgdydnunVaq7"),
    ),
  )

  val AppleAttestationIos = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(
        ByteArray.fromBase64Url("Fe0QmfU9xebikAVYRtOyGfI5ulgxbVVf7VNaON8edmU=")
      )
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUUs2c25Jak40MGNNZG9oNlUtR3NEZnlFYzlQY3pKdEgtSTczM3daSDRIZyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIn0="),
      ByteArray.fromBase64("o2NmbXRlYXBwbGVnYXR0U3RtdKFjeDVjglkCRjCCAkIwggHJoAMCAQICBgF4xhYQszAKBggqhkjOPQQDAjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIxMDQxMTEyMzcxOFoXDTIxMDQxNDEyMzcxOFowgZExSTBHBgNVBAMMQDMxYzRlOTM2YzgwZjY1Y2VjNzcxZWZkOGNhNWMxNDdlZTgxZjY4ZjVhODE5YTUzNDFiMDU5NmJkYmU4YWI0OTExGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYc87v7q19IYjqS3vizLAet/NcW0NVpYRvzvZFfCT00nBR0rzITI4iuuBupVtSRFhZfHa3GhYUu/w3Mo2h3s/+qNVMFMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBPAwMwYJKoZIhvdjZAgCBCYwJKEiBCC+B6u5EUpszNBikhFRpOuBolX7jPReSqGkIvBr0orEZDAKBggqhkjOPQQDAgNnADBkAjAZpK9Vw3hR3uCca+kUAorfR4Sj/HkCcmydzm/KuewaYC5lmIwRTw9SKEVmAAITRlUCMEC9P/ksVc5DUHtKt+rQ9mXHeobdGymHSM7xZtYMNOfze8hPo5HLnwtWCB5qF8MQRVkCODCCAjQwggG6oAMCAQICEFYlU5XHp/tA6+Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz/LBFvHNZk0df1UkETfm/4ZIRdlxpod2gULONRQg0AaQ0+yTREtVsPhz7/LmJH+wGlggb75bLx3yI3dr0alruHdUVta+quTvpwLJpGjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT/oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl+tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz+Wbw00pMMFIeFHZYO1qdfHrSsq+OM0luJfQyAW+8Mf3iwelccboDgdoYXV0aERhdGFYmMRs74KtG1Rkd1kdAIsIdZ7D5tLstPOUdL/qaWmSXQO3RQAAAAAAAAAAAAAAAAAAAAAAAAAAABRK0rg7vzmd/BAatDNkXX6aBhPZSaUBAgMmIAEhWCBhzzu/urX0hiOpLe+LMsB6381xbQ1WlhG/O9kV8JPTSSJYIMFHSvMhMjiK64G6lW1JEWFl8drcaFhS7/DcyjaHez/6"),
    ),
    AssertionExample(
      id = ByteArray.fromBase64Url("StK4O785nfwQGrQzZF1-mgYT2Uk"),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoid2V5TG9keXVzUl96SWtPWUg3bTVUYjBreGViQnEtV2QzYVJreUhMeHl0SSIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIn0="),
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cFAAAAAA=="
      ),
      sig =
        ByteArray.fromBase64("MEUCIQDv9Sye6lyu6nonnsI9bSjkBXyhPRmei4LGRhfuOGc0AwIgPEQFsGHZDMIeSVDmgB85otg1Ba0XNl7S/Bgj6diIIoo="),
    ),
  )

  val AppleAttestationMacos = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(ByteArray.fromBase64("+8eKyPo9MGrhWx8Y7ZeoczjaS5mbRr2kqF7/zllIgZ8="))
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicWszNE1GRVA4dWxXaHVpOEpncmt0ZVE5RXhIV2NKYndJcjNDUm1lVGtqZyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIn0="),
      ByteArray.fromBase64("o2NmbXRlYXBwbGVnYXR0U3RtdKFjeDVjglkCRjCCAkIwggHJoAMCAQICBgF4xjGSqDAKBggqhkjOPQQDAjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIxMDQxMTEzMDcyMFoXDTIxMDQxNDEzMDcyMFowgZExSTBHBgNVBAMMQDYxYmQ5NzY4M2JlMTk0NTVjOGJjOWVhNDZhMjY4NzU0MzVjMmIwNmVlMTI4YzY4ZDFiMGE4NDczODkwNTgzMjYxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdrvYDb+UbAjcbbommtRqw+2Lm1fvHG6ll1dOgeEM25H8ThQ0yj4R3hVbc/ean1I5eqc/RXDFm/jJI/Lmp1uEFqNVMFMwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBPAwMwYJKoZIhvdjZAgCBCYwJKEiBCAQ6ifyo7KWlR86ueS0JMAuIi66gYkJsX+VxAcvbtEEcTAKBggqhkjOPQQDAgNnADBkAjAIu8Vx1tdGHSarO63RF7QaUo3/Iuk1CXA2Z0YIbDG4mLS15JQ/AUwctOpePcZoDngCMFMfnXi6jlhNBmppj5/8VQz2Kbz5eNxg+dqALz59ctCqXkdCVLMhUOpHWgMhhOadj1kCODCCAjQwggG6oAMCAQICEFYlU5XHp/tA6+Io2CYIU7YwCgYIKoZIzj0EAwMwSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM4MDFaFw0zMDAzMTMwMDAwMDBaMEgxHDAaBgNVBAMME0FwcGxlIFdlYkF1dGhuIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASDLocvJhSRgQIlufX81rtjeLX1Xz/LBFvHNZk0df1UkETfm/4ZIRdlxpod2gULONRQg0AaQ0+yTREtVsPhz7/LmJH+wGlggb75bLx3yI3dr0alruHdUVta+quTvpwLJpGjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUJtdk2cV4wlpn0afeaxLQG2PxxtcwHQYDVR0OBBYEFOuugsT/oaxbUdTPJGEFAL5jvXeIMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA3YsaNIGl+tnbtOdle4QeFEwnt1uHakGGwrFHV1Azcifv5VRFfvZIlQxjLlxIPnDBAjAsimBE3CAfz+Wbw00pMMFIeFHZYO1qdfHrSsq+OM0luJfQyAW+8Mf3iwelccboDgdoYXV0aERhdGFYmMRs74KtG1Rkd1kdAIsIdZ7D5tLstPOUdL/qaWmSXQO3RQAAAAAAAAAAAAAAAAAAAAAAAAAAABRhYCgh40b6Uj1WdjckwPAdCwd4fKUBAgMmIAEhWCB2u9gNv5RsCNxtuiaa1GrD7YubV+8cbqWXV06B4QzbkSJYIPxOFDTKPhHeFVtz95qfUjl6pz9FcMWb+Mkj8uanW4QW"),
    ),
    AssertionExample(
      id = ByteArray.fromBase64Url("YWAoIeNG-lI9VnY3JMDwHQsHeHw"),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVVdobmx5VTdlVzZBTEw1M1VPcENnU1N3ckEzNm92R3VpQUV6ZE91OFdTYyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIn0="),
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cFAAAAAA=="
      ),
      sig =
        ByteArray.fromBase64("MEUCIQDkspL//pE98spvRtyTAZqPjmpd6/G+KmNsjMUfX7pKkAIgcld+Y3j0yt95CMqKmR99SKuoiitIL8SBElZw/qFEX5s="),
    ),
  )

  val YubikeyFips5Nfc = new Example(
    RelyingPartyIdentity.builder().id("demo.yubico.com").name("").build(),
    UserIdentity
      .builder()
      .name("6vTZo5MBEbaH")
      .displayName("6vTZo5MBEbaH")
      .id(ByteArray.fromBase64("tabbiLeU61rCtgcNOC+9J6doMN8DQnm2IEaa4Ps+gqU="))
      .build(),
    AttestationExample(
      """{"type":"webauthn.create","challenge":"BkRnXYHVbiUEJYPPcVAOig","origin":"https://demo.yubico.com","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}""",
      ByteArray.fromBase64("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAMrVMrCPZDK3RNFKKdDOYoSPsEqgSecbvfUIuPk84nIwAiA6VbneoEArKqgrwWnDcQi03kyWQrPmr3JqHtPUXNGitWN4NWOBWQLwMIIC7DCCAdSgAwIBAgIJAN1TJeaFJ6cVMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBvMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxNzEzNzIyMzMzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDeoY3vFmcuLvf1SL2oqIV5WaVs9VGyB4GPmtxdHY84v/+R2wtLKvAfjIH9eTIq3+Ev3+UQLipTY0Bb9Xn9Sp3KOBlDCBkTATBgorBgEEAYLECg0BBAUEAwUEAjAQBgkrBgEEAYLECgwEAwIBBDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBDB+aC8HdJASrJ/jikEekP9MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAGl5dmZIe5GOHFOAvVUaWFWyet89UCHWKmLBTXXfuoPwYqatxGhVqIeiV4nAuFF127294SzJcMgzycToui5/g8OUonTvs9xWF9yH23fXjGcBWoGErlF7DqkycOz2NtjPhGwEfBnE++0/KRc/IN6bu7u/XPXNwNmCLcg0reERI23NO/ZftcWebjRBCwY3p6l0ahalKmrgqOi7bhU1AjbHmiEvJgeBcpZphS87eikierMO5PmwvdbV3okNseEoaeoHDDQ7Av6RwCtKCXwYupRs6sULgUwo0fz2znURA+zSuTzK4iZ/hmQvRVJtQBPtfpwBEmNEdwwZ1A+VxfspsYzA7AVoYXV0aERhdGFYn8Rs74KtG1Rkd1kdAIsIdZ7D5tLstPOUdL/qaWmSXQO3xQAAAALB+aC8HdJASrJ/jikEekP9ADCoKvXSwuTSIXADOmvBwyJiDqQ6hh3epKxT2gFcv7/fe7KF6ZidYuy5hytIti+jyUSkAQEDJyAGIVggqCr10sLk0iFwAzprwb1UlYO/I5e1odNDyARvWzyHZkuha2NyZWRQcm90ZWN0Ag=="),
    ),
    AssertionExample(
      id = ByteArray.fromBase64Url(
        "qCr10sLk0iFwAzprwcMiYg6kOoYd3qSsU9oBXL-_33uyhemYnWLsuYcrSLYvo8lE"
      ),
      clientData = """{"type":"webauthn.get","challenge":"P0MvFaK3Bz-YYVYfCXfBig","origin":"https://demo.yubico.com","crossOrigin":false}""",
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cFAAAAAw=="
      ),
      sig =
        ByteArray.fromBase64("Q0omzU9kPFnxd9njE5+fWLDDFxPIXRrPJ3fSGniU2+UHp1NUZJtMwc4iddbXiYNZ2GN5frrG3tf72oAoI+i3BQ=="),
    ),
  )

  val Yubikey5ciFips = new Example(
    RelyingPartyIdentity.builder().id("demo.yubico.com").name("").build(),
    UserIdentity
      .builder()
      .name("6J8bPm5pgZxx")
      .displayName("6J8bPm5pgZxx")
      .id(ByteArray.fromBase64("cj5f7W52d8rucMRXw+F+k/tMcMjRZbWNmmayWQ/s1hY="))
      .build(),
    AttestationExample(
      """{"type":"webauthn.create","challenge":"hnZ_h1C2W1hIvTv-TczSDQ","origin":"https://demo.yubico.com","crossOrigin":false}""",
      ByteArray.fromBase64("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgNjV3981oAhwpWDaw0VT7o/KK/OZ4MJF1Gx3p68dfgSkCIQClgMNxOuNeWlX3OEekplBvZyEdnjrgXHPK4+qxbgb6yWN4NWOBWQLwMIIC7DCCAdSgAwIBAgIJAJt5F3hRiVnmMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBvMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAyMDE0ODA0Mzc5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETAZOKKrzwwAt0vCs9bDGCjmvATlCgCkn53Sp13iiRNQHa2HepLsy8Dm+h5K4wqkoKGuo16K1omdeUHSs8syPraOBlDCBkTATBgorBgEEAYLECg0BBAUEAwUEAjAQBgkrBgEEAYLECgwEAwIBBDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwICJDAhBgsrBgEEAYLlHAEBBAQSBBCFIDQhSPlDVZvIilOEblCDMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAFybB6BcC0kstjohJiA8Aczi2MQqkVWOUaLTtdrWyPcbSHfiqjjtn2J4lDxrCossqvmwrpAJ6vZ4rvHpv8dcJAFCA8Q02SaMWU/HgBjf3EZsowaxJqTPYsq86UmQG0+Y9BGuLZ1higWE1Pptpgumwkimo7q/H6Hvv0Da2FReEzAHYpwwrDfak+O+s3HEiKRRoqAprheNSunp1YXCnq6PCMho+gFbM1ULgx7D3eN/AQfMlhwa7vN7SoDRA93o6Gojdh54Mm2M5KuxX5NmNgfcfn7csvhXuDEw3J6YUE1Nd79bOBFAdSc1ZcQLBGaggIYQwy7p0R8gWh0T4AZEk+GHsMdoYXV0aERhdGFYxMRs74KtG1Rkd1kdAIsIdZ7D5tLstPOUdL/qaWmSXQO3QQAAAAKFIDQhSPlDVZvIilOEblCDAECp43L1YZ3opECrhpd//EKA6uCMmhEftV7woLtQndymMNoWu/l6CvmQnuYGWsaIeVnQ6QP9e2x36VBO79iavVyupQECAyYgASFYIMMwT+xzGRGxDx68988LHQ2WBrHQ0/ikpBffxxPtyQ92Ilggq9B/tvF9OQzKJddRibjoYmYfZtVk20wt7OKpz/a4FLU="),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("qeNy9WGd6KRAq4aXf_xCgOrgjJoRH7Ve8KC7UJ3cpjDaFrv5egr5kJ7mBlrGiHlZ0OkD_Xtsd-lQTu_Ymr1crg"),
      clientData = """{"type":"webauthn.get","challenge":"gJQG3mUBQv5rR7mwUuHbxQ","origin":"https://demo.yubico.com","crossOrigin":false}""",
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cBAAAABQ=="
      ),
      sig =
        ByteArray.fromBase64("MEQCIEZeZWSy5CfVPMIGnU1Fi3+K+8ID6YTDxdckc9174ICeAiA1qRNIbPoo2tMSR1wFi5PTb6s+nZ2q9apv9NhnDbNZig=="),
    ),
  )

  val YubikeyBio_5_5_4 = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(ByteArray.fromBase64("n5iF3+LH/w9yfgIgEWdFL99YAD8PMpG41PEPzzV1RSc="))
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicnJIQmg3Q01yZElYTE0zMFBkOFZ1Ulg3TV9xVXl5VEpCWDRUN2xONUVRRSIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="),
      ByteArray.fromBase64("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgGSqwfT67zXQVsgBU/TvN1MGbZkR5KEyzzMMbS9cJQJsCIDZJ90wxLjNnpzNZ+Ns64cmgwixb0CJcXdfVM35EBgm0Y3g1Y4FZAt0wggLZMIIBwaADAgECAgkAtcaOPpfL6PYwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDEwNDk1NDQzNzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQXmY7aJqXBb5wsBbCAeJFdFa3Fzz8VU1qdJxUCgPf2MNcoMnikaKg0yp/bakKjCNIqmsb75RhUzS5UQHwVOAe0o4GBMH8wEwYKKwYBBAGCxAoNAQQFBAMFBQQwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjkwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQ2FItn1dbSGaIqbqZ+gLzWzAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQB9yNliBCNlTGBrhYTTqHJm73KjMszL24buZcvifix+GRYk7D8I0/BQ20mQ/CITqqGTr5cvxjIKVw/2ed+326hITlhaWiwwEnwuI5afqwd72ObWczklHNvoV+uWtM9YVfk9H7VZqtQTMb3m8O+UWmkCGxLdqTprgTUSF/Tmk6KPyF1S6es6RJvk9vxyJ0T/EFkr9yAPlDzqtc9hEAUEPP5xpzEWRYon6T12AUW6wQwlkiA8q4gFIQfTGks1JX6ob/1nTvigO3EYB4wP3EIAJ+0HkpprKKDl4mRv/7b/BPuANq4jMr/9YkYs8XrmuUHdF0PwRzYPN4KtovuG0YdFA0ObaGF1dGhEYXRhWMTEbO+CrRtUZHdZHQCLCHWew+bS7LTzlHS/6mlpkl0Dt0UAAAAB2FItn1dbSGaIqbqZ+gLzWwBAvPVBBCgvthNO8DNbim45zueAndDzuMAQDBXL/bVsH9uXfKkrza7ya2DM/xka1hYW+K2d97qNRJmoAeetc5haaKUBAgMmIAEhWCDqr+a3QuoQk4VqspgOfHlkS2Rk+NpsHL5Rs4rbxE2DQiJYICjaw5BRuZKz5CPZRjiDJFOq51wbOrUggICGmC88+ZXq"),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("vPVBBCgvthNO8DNbim45zueAndDzuMAQDBXL_bVsH9uXfKkrza7ya2DM_xka1hYW-K2d97qNRJmoAeetc5haaA"),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiOVVHcG1JOXdkM004dF9yUGFZMVRyWXd1LVVranRUdHV1N2RGcHlyNGtDOCIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="),
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cFAAAABA=="
      ),
      sig =
        ByteArray.fromBase64("MEUCIGM9xK+AHlLTv3mJLagZuNlLijI86T2SzkyAy3NidembAiEA6Y3I5GPYnRoHKil4R8yCSHUFZdgc59GO1KfsoHYhA3o="),
    ),
  )

  val YubikeyBio_5_5_5 = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(ByteArray.fromBase64("vATtCjg/L2+3DSWW/qY6KtUxmkzV7ZfXgoIT9kmeSUk="))
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNFVQRC0wYkJpb0tmVjNXRFZRUDVGZyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0="),
      ByteArray.fromBase64("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhALYxNNPzOaTC7MbbvP5J/E5LIqRpCVq2EnAzw9GnZAYyAiEAmRFEEjahZ3hKiYeAERihkZG3VakKMHs/dvQHN5qtikJjeDVjgVkC3DCCAtgwggHAoAMCAQICCQCxoTUeHREkCDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNTA2ODMxMjgxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5GAqSUnnESzgip5QSiwjXE9P/d5a4B87EB/2eTZZsG+n3Vfuhw7wTxdIl25WbFo/w7P8b6IcnvUXSK3cEXobYqOBgTB/MBMGCisGAQQBgsQKDQEEBQQDBQUFMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS45MBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEENhSLZ9XW0hmiKm6mfoC81swDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAKS2rlRz6RxEXSXMFqmtO9BYs0XlLVSK8tkXtEbWCDYrq0tPHlmj6KSZtiN3ApTGpL4+TwprQkqdjCfyjzB7zhyTg5+6XNawDsTK1ffNfvT1xY2dvmj0D+bftA8I9KMVSOTtORKjbAqsyrmrvoTws3X6h/LPuC29Giwc54e3dYQFeEtdrmblLZmJfhF78L0ZdbJNcgOK1ZZdDxglfZ6yD/WoCL0Rnve/Wnss//50RLNw4KMgX+MLP2aGlZjoCWbR4fLPQz0uG7S5NKdzWWdU7ScMYsG+K4s5I+bU8sDj8WIfAQ1iQibC62yxuPcVvGtsiNd+hVWgvS7xsL/YwtvncTWhhdXRoRGF0YVjExGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7dFAAAAA9hSLZ9XW0hmiKm6mfoC81sAQL+vEPt35mA9WSpQo6I8Asxtm03+E3+RjpFYV1q0xei8HKXpJmWMkfkPccpWKZP0pqjUt8tP6Fi7nDY32d2ywnmlAQIDJiABIVggYBMva++1OGaFbYJ3lAPWB4gRFP3960V1p9HqU846nLgiWCAo7Yy9ttW/torJq5/a/MZ0klVCepSrxIkjw2NE528Y1w=="),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("v68Q-3fmYD1ZKlCjojwCzG2bTf4Tf5GOkVhXWrTF6LwcpekmZYyR-Q9xylYpk_SmqNS3y0_oWLucNjfZ3bLCeQ"),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicm1hVXh6aUJhcHdsM1VhYjYzdmJBUSIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="),
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cFAAAABw=="
      ),
      sig =
        ByteArray.fromBase64("MEUCIEhKvwf685swe2Gm0UrbcbYtB/6mg2/i2SXq9IsO/knxAiEA2CpfycB1/mcdDcCxP2Pp6zfFanVuwFhRBsy9NJmjxbg="),
    ),
  )

  val YubikeyBio_5_5_6 = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(ByteArray.fromBase64("KYljhyutCbO7mu5TI9Zt9ra11ScQvC+ArBpdYoAiEvg="))
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQnhoWTY4ZGczeHNNVmFRaWRqaW1BdyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="),
      ByteArray.fromBase64("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAMSgpu1ru29YJex9vN8Zmt7RJkvOj/DmD2Cnfz8nhVmLAiEA8qnz6llKsjWfZ1OYrR4AIS3JTIXsQgbmeK61pzuesYJjeDVjgVkC3DCCAtgwggHAoAMCAQICCQD/h2wtr3N5yDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzYyMDg3NDIzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJfEjoEgoP8V5bM+IfZlIn9k1wkGYxLXY1bLCv9fdXRWv5FtwcHdlZ9W1sLI+BFYLW+p3tIOx9kkeU6PyvuajmqOBgTB/MBMGCisGAQQBgsQKDQEEBQQDBQUGMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS45MBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEENhSLZ9XW0hmiKm6mfoC81swDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAUrBpSduq0aZMG6nrwZizF+wx+aNzY7pRYbNC46ScrVBPNOdCi7iW6c/SjQOtEM4yWgaDjptsTssXrUDQkKFsnnw0SYMy/4U7YnR+j83wDa5idW5XvUCxbWd5B6g1wENaLrzpsLkGnKEiv52WSnMgavdP88ABROv/PefHdY0xR8jC+f6HwS8qlnWiBGsBB2NhqZchhx+nj7DeKUW1efkWbEitL9UMPOVsgiGnUIP2VhGTlDaP8X0skgxjoJ8B7SUBFGt98as5cKKjKTj6mlF69HEIXhYLPKeXZCMXRrpqu6aODRPOJZeWvNKgOtg8dOFTMTKOq0OOakGXyxLsb9HjiGhhdXRoRGF0YVifxGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7fFAAAABNhSLZ9XW0hmiKm6mfoC81sAMIg/92bCZgLh2oUu6QF2XrSYZKh+qP1J3wf1SgOOkcMnF499E7JiLPi5YhY/308TfKQBAQMnIAYhWCCIP/dmwmYC4dqFLukBggD0oYvvkNUWXNzokKlsiK0/vaFrY3JlZFByb3RlY3QC"),
    ),
    AssertionExample(
      id = ByteArray.fromBase64Url(
        "iD_3ZsJmAuHahS7pAXZetJhkqH6o_UnfB_VKA46RwycXj30TsmIs-LliFj_fTxN8"
      ),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiX3RoYmVudXo3amZBcWJMZUxYVlFWQSIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="),
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cFAAAACA=="
      ),
      sig =
        ByteArray.fromBase64("ZeXxnNYjBwh5Irn+W6VzRna/3XQrsvYhKVa+T8tv2eEw/UuALFoLHlBRkFQr73wgmLZ4ma2gEXocOnuUjVBZAw=="),
    ),
  )

  val Mldsa44 = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(ByteArray.fromBase64("b6/TaU6EhXElrX6MYQGm2lu/gb/sg39VHflwN64b4YI="))
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOFlEZ05aV283SGxzcVpFQUZTUVgtdyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"),
      ByteArray.fromBase64("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"),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("V1R8dplu0bP5y7EXN6O2n-DB4xL8d1cVdU5mXbrtvaTZKAA0uA5Knk0QXJmSmH4zbKwEIyyYZfYEuuHYoyAfOvk"),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiU3k1cmxPTnE4ZmdNQVQ3RE9YR00yUSIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"),
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cBAAAABQ=="
      ),
      sig =
        ByteArray.fromBase64("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"),
    ),
  )

  val Mldsa65 = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(ByteArray.fromBase64("b6/TaU6EhXElrX6MYQGm2lu/gb/sg39VHflwN64b4YI="))
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMnBscVhFMHl3TDZISDlXMno0NkhrZyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"),
      ByteArray.fromBase64("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"),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("dHhMny0pw0enl97p-tgsapT2FfVMcBMYWcI8u9PWqS8In13jgkzJO6JaB0F1lzkIRdHyOAnIzbgTiyIEC809qsE"),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTHFlSEE0aFVieEdMNXZNLU5EM1JpUSIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"),
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cBAAAABA=="
      ),
      sig =
        ByteArray.fromBase64("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"),
    ),
  )

  val Mldsa87 = new Example(
    RelyingPartyIdentity
      .builder()
      .id("demo.yubico.com")
      .name("YubicoDemo")
      .build(),
    UserIdentity
      .builder()
      .name("Yubico demo user")
      .displayName("Yubico demo user")
      .id(ByteArray.fromBase64("b6/TaU6EhXElrX6MYQGm2lu/gb/sg39VHflwN64b4YI="))
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiemgyZVRUS2dpZVo3ZV9fRm5Ma1d3USIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"),
      ByteArray.fromBase64("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"),
    ),
    AssertionExample(
      id =
        ByteArray.fromBase64Url("ZOM1l7BQ9UDAVZUZaMh4FhGm34lWsChUjNwdPm6Og1t9Z34g4ye_axL9SKbFzbqkQzZyM9huNAop1s37DyJsvzo"),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVFVRYmhiWmk4clM3SjA2OV9iWUxaUSIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"),
      authDataBytes = ByteArray.fromBase64(
        "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cBAAAABA=="
      ),
      sig =
        ByteArray.fromBase64("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"),
    ),
  )

  val CredPropsEmpty = AttestationExample(
    base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYlZjNWxvY3dnV0ZvdlJ6M2RzWGkzcFc1cHgxZ3pGOFFIaFJmLU90REhuVSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ"),
    ByteArray.fromBase64Url("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgCTFl9y9YBafBiKkOnj59Cgypvz9hhPwpdsiFAmE8utcCIQC8bsfMEcI5-Di3Xj9CIWZ1PAGMjvxEiD1L2csJcgjoBmN4NWOBWQLwMIIC7DCCAdSgAwIBAgIJAN1TJeaFJ6cVMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBvMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxNzEzNzIyMzMzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDeoY3vFmcuLvf1SL2oqIV5WaVs9VGyB4GPmtxdHY84v_-R2wtLKvAfjIH9eTIq3-Ev3-UQLipTY0Bb9Xn9Sp3KOBlDCBkTATBgorBgEEAYLECg0BBAUEAwUEAjAQBgkrBgEEAYLECgwEAwIBBDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBDB-aC8HdJASrJ_jikEekP9MAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBAGl5dmZIe5GOHFOAvVUaWFWyet89UCHWKmLBTXXfuoPwYqatxGhVqIeiV4nAuFF127294SzJcMgzycToui5_g8OUonTvs9xWF9yH23fXjGcBWoGErlF7DqkycOz2NtjPhGwEfBnE--0_KRc_IN6bu7u_XPXNwNmCLcg0reERI23NO_ZftcWebjRBCwY3p6l0ahalKmrgqOi7bhU1AjbHmiEvJgeBcpZphS87eikierMO5PmwvdbV3okNseEoaeoHDDQ7Av6RwCtKCXwYupRs6sULgUwo0fz2znURA-zSuTzK4iZ_hmQvRVJtQBPtfpwBEmNEdwwZ1A-VxfspsYzA7AVoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAATB-aC8HdJASrJ_jikEekP9AEAJSmR-h-HuKqKK2uvaDSjTQrjbfukR_-71-SoVyEFkfLEc09nidnTryBiqZGARKeDhwvtog3_c3f8C3REXcI4spQECAyYgASFYIDUR5e5GusKylrCRkKq1U3jnp-fJ_l_CeykL_-5tj4juIlgg72ksmbxNptIfwrG1hiwbViIoWIphEt2819hHdziqSsc"),
    clientExtensionResultsJson = """{"credProps":{}}""",
  )

  val CredPropsRkTrue = AttestationExample(
    base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWFltUW9lWlMtWVNTSjdYN2JJSUxTbzBSTDExbV9Kd01PNXFRZmNUQU1xayIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ"),
    ByteArray.fromBase64Url("o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAPw2vAQV-2EGVlL4RXzh_Z2iLr7JXCnBpm8prPEeu3KjAiEA8WhW4GPZUiWpTX9p4EK5QE-ZE7G20_sraQ6_APG9-OBjeDVjgVkC8DCCAuwwggHUoAMCAQICCQDdUyXmhSenFTANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTcxMzcyMjMzMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA3qGN7xZnLi739Ui9qKiFeVmlbPVRsgeBj5rcXR2POL__kdsLSyrwH4yB_XkyKt_hL9_lEC4qU2NAW_V5_UqdyjgZQwgZEwEwYKKwYBBAGCxAoNAQQFBAMFBAIwEAYJKwYBBAGCxAoMBAMCAQQwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQwfmgvB3SQEqyf44pBHpD_TAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBpeXZmSHuRjhxTgL1VGlhVsnrfPVAh1ipiwU1137qD8GKmrcRoVaiHoleJwLhRddu9veEsyXDIM8nE6Louf4PDlKJ077PcVhfch9t314xnAVqBhK5Rew6pMnDs9jbYz4RsBHwZxPvtPykXPyDem7u7v1z1zcDZgi3INK3hESNtzTv2X7XFnm40QQsGN6epdGoWpSpq4Kjou24VNQI2x5ohLyYHgXKWaYUvO3opInqzDuT5sL3W1d6JDbHhKGnqBww0OwL-kcArSgl8GLqUbOrFC4FMKNH89s51EQPs0rk8yuImf4ZkL0VSbUAT7X6cARJjRHcMGdQPlcX7KbGMwOwFaGF1dGhEYXRhWMJJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY8UAAAABwfmgvB3SQEqyf44pBHpD_QAw0nM1d52DYdt7cv_6mdvhsFl12msHv6Pt-izLFuncSmRGSaCsAWizk70SqdKPuXyPpQECAyYgASFYINJzNXedg2Hbe3L_-pnZU8KE6ZmMGizk0KqHq5AA8YogIlgg9tCtr3schMR0jJUREKjqOW4cMxTzotkYvBI3iTwj62qha2NyZWRQcm90ZWN0Ag"),
    clientExtensionResultsJson = """{"credProps":{"rk":true}}""",
  )

  val LargeBlobWrite = new Example(
    RelyingPartyIdentity.builder().id("localhost").name("").build(),
    UserIdentity
      .builder()
      .name("asdfa")
      .displayName("asdfa")
      .id(
        ByteArray.fromBase64Url("-MR-ER2Nujmv3fWNlpb1mwcisVh6D962ZAxGz4W7XUQ")
      )
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUkpkSmt3UF9JejcyRHF3Y2xha0JYR3FuX2NqZy1ObEtQVDFOSEFvMDR2RSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"),
      ByteArray.fromBase64Url("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjCSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PFAAAABAAAAAAAAAAAAAAAAAAAAAAAMC22Bw33qBCfiLRvJaun4zVZ4YOpIG3mxo2FhH99macgoYmxr-ICVNThjNJzkEGORqUBAgMmIAEhWCAttgcN96gQn4i0byWrpUb-jQhSjE9J49n5D_krK_f8byJYIFxGgNN7UDpueNRz_FgXoO7Pg5qIFA-LT9y3S7_JdPjboWtjcmVkUHJvdGVjdAI"),
      clientExtensionResultsJson = """{"largeBlob":{"supported":true}}""",
    ),
    AssertionExample(
      id = ByteArray.fromBase64Url(
        "LbYHDfeoEJ-ItG8lq6fjNVnhg6kgbebGjYWEf32ZpyChibGv4gJU1OGM0nOQQY5G"
      ),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWUZVZGY5SFI3UVY5a216R1ZicU5sVk1Ja2x5QXJEY2lISVM0TFdsQWhtUSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"),
      authDataBytes = ByteArray.fromBase64Url(
        "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAACA"
      ),
      sig =
        ByteArray.fromBase64Url("MEQCIAgTCWKcpQ-kLkKc18UJlwRWx2WYmRWMxvndHXHgWmzzAiAC-my1SfSnO0fr4iRYxMkbw1k7e6HxrFY22nJ7e3Z3jw"),
      clientExtensionResultsJson =
        """{"appid":false,"largeBlob":{"written":true}}""",
    ),
  )

  val LargeBlobRead = new Example(
    RelyingPartyIdentity.builder().id("localhost").name("").build(),
    UserIdentity
      .builder()
      .name("asdfa")
      .displayName("asdfa")
      .id(
        ByteArray.fromBase64Url("-MR-ER2Nujmv3fWNlpb1mwcisVh6D962ZAxGz4W7XUQ")
      )
      .build(),
    AttestationExample(
      base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUkpkSmt3UF9JejcyRHF3Y2xha0JYR3FuX2NqZy1ObEtQVDFOSEFvMDR2RSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"),
      ByteArray.fromBase64Url("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjCSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2PFAAAABAAAAAAAAAAAAAAAAAAAAAAAMC22Bw33qBCfiLRvJaun4zVZ4YOpIG3mxo2FhH99macgoYmxr-ICVNThjNJzkEGORqUBAgMmIAEhWCAttgcN96gQn4i0byWrpUb-jQhSjE9J49n5D_krK_f8byJYIFxGgNN7UDpueNRz_FgXoO7Pg5qIFA-LT9y3S7_JdPjboWtjcmVkUHJvdGVjdAI"),
      clientExtensionResultsJson = """{"largeBlob":{"supported":true}}""",
    ),
    AssertionExample(
      id = ByteArray.fromBase64Url(
        "LbYHDfeoEJ-ItG8lq6fjNVnhg6kgbebGjYWEf32ZpyChibGv4gJU1OGM0nOQQY5G"
      ),
      clientData =
        base64UrlToString("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSjNlNjRnZThBamtOSl81aE5jaUo5NldrT3VQZzYycnJHTDc2d3AzTHRCQSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"),
      authDataBytes = ByteArray.fromBase64Url(
        "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAADQ"
      ),
      sig =
        ByteArray.fromBase64Url("MEYCIQCJMxhKIBAvno05cjt7IeFrWLwPtWeDGS_yH9fOX-DQXAIhAIzU7uC4DM6oO_A0JNm90LUr0l158aacA4XH5auxqSqB"),
      clientExtensionResultsJson =
        """{"appid":false,"largeBlob":{"blob":"SGVsbG8sIFdvcmxkIQ"}}""",
    ),
  )

  val WindowsHelloTpm =
    Example(
      RelyingPartyIdentity
        .builder()
        .id("d2urpypvrhb05x.amplifyapp.com")
        .name("")
        .build(),
      UserIdentity
        .builder()
        .name("foo")
        .displayName("Foo Bar")
        .id(
          ByteArray.fromBase64Url("AAAA")
        )
        .build(),
      AttestationExample(
        base64UrlToString(
          "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoia0lnZElRbWFBbXM1NlVOencwREg4dU96M0JERjJVSllhSlA2eklRWDFhOCIsIm9yaWdpbiI6Imh0dHBzOi8vZGV2LmQydXJweXB2cmhiMDV4LmFtcGxpZnlhcHAuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
        ),
        ByteArray.fromBase64Url("o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQBFEaTe-uZvbZBNsIMtJa26eigMUxEM1mBtddR7gdEBH5Hyeo9hFCqiJwYVKUq_iP9hvFaiLzoGbAWDgiG-fa3F-S71c8w83756dyRBMXNHYEvYjfv0TqGyky73V4xyKpf1iHiO_g4t31UjQiyTfypdP_rRcm42KVKgVyRPZzx_AKweN9XKEFfT2Ym3fmqD_scaIeKSyGs9qwH1MbILLUVnRK6fKK6sAA4ZaDVz4gUiSUoK9ZycCC2hfLBq5GjiTLgQF_Q2O3gRTqmU8VfwVsmtN5OMaGOyaFrUk97-RvZVrARXhNzrUAJT7KjTLDZeIA96F3pB_F_q3xd_dgvwVpWHY3ZlcmMyLjBjeDVjglkFuzCCBbcwggOfoAMCAQICEHHcna7VCE3QpRyKgi2uvXYwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLU5UQy1LRVlJRC04ODJGMDQ3Qjg3MTIxQ0Y5ODg1RjMxMTYwQkM3QkI1NTg2QUY0NzFCMB4XDTIyMDEyMDE5NTQxNloXDTI3MDYwMzE3NTE0OFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtT5frDB-WUq6N0VYnlYEalJzSut0JQx3vP29_ub-kZ7csJrm8uGXQGUkPlf4EFehFTnQ1jX_oZ8jNPw1m3rV5ijcuCe3r5GICFD6gpbuErmGS2mDVfe3fl_p0gPvhtulqatb1uYkWfW5SIKix1XWRvm92s3lRQvd-6vX_ExPIP-pEf0tkeINpBNNWgdtx3VdW4KVFTcv-q2FKhqfqXiAdOMHmwmWyXYulppYqW2XC7Pw9QmHZR_C5Urpc5UMmABz4zWSAYOyBMkKsX8koAsk8RgLtus07wW3FhJqi-BYczIe0IxG0q9UL295lkaxreTkfWYZHMMcU4M-Tm1w7QvKsCAwEAAaOCAeowggHmMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMT4wEAYFZ4EFAgIMB05QQ1Q3NXgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMBQGBWeBBQIDDAtpZDowMDA3MDAwMjAfBgNVHSMEGDAWgBSMmnF_AA0xD8rW7i0pqjSXJYwSHjAdBgNVHQ4EFgQUFmUMIda76eb7Whi8CweaWhe7yNMwgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1udGMta2V5aWQtODgyZjA0N2I4NzEyMWNmOTg4NWYzMTE2MGJjN2JiNTU4NmFmNDcxYi84ODIzMGNhMi0yN2U1LTQxNTEtOWJhMi01OWI1ODJjMzlhYWEuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQCxsTbR5V8qnw6H6HEWJvrqcRy8fkY_vFUSjUq27hRl0t9D6LuS20l65FFm48yLwCkQbIf-aOBjwWafAbSVnEMig3KP-2Ml8IFtH63Msq9lwDlnXx2PNi7ISOemHNzBNeOG7pd_Zs69XUTq9zCriw9gAILCVCYllBluycdT7wZdjf0Bb5QJtTMuhwNXnOWmjv0VBOfsclWo-SEnnufaIDi0Vcf_TzbgmNn408Ej7R4Njy4qLnhPk64ruuWNJt3xlLMjbJXe_VKdO3lhM7JVFWSNAn8zfvEIwrrgCPhp1k2mFUGxJEvpSTnuZtNF35z4_54K6cEqZiqO-qd4FKt4KYs1GYJDyxttuUySGtnYyZg2aYB6hamg3asRDjBMPqoURsdVJcWQh3dFnD88cbs7Qt4_ytqAY61qfPE7bJ6E33o0X7OtxmECPd3aBJk6nsyXEXNF2vIww1UCrRC0OEr1HsTqA4bQU8KCWV6kduUnvkUWPT8CF0d2ER4wnszb053Tlcf2ebcytTMf_Nd95g520Hhqb2FZALCErijBi04Bu6SNeND1NQ3nxDSKC-CamOYW0ODch05Xzi1V0_sq0zmdKTxMSpg1jOZ1Q9924D4lJkruCB3zcsIBTUxV0EgAM1zGuoqwWjwYXr_8tO4_kEO1Lw8DckZIrk1s3ySsMVC89TRrIVkG7zCCBuswggTToAMCAQICEzMAAAQI5W53M7IUDf4AAAAABAgwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMTA2MDMxNzUxNDhaFw0yNzA2MDMxNzUxNDhaMEExPzA9BgNVBAMTNkVVUy1OVEMtS0VZSUQtODgyRjA0N0I4NzEyMUNGOTg4NUYzMTE2MEJDN0JCNTU4NkFGNDcxQjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMEye3QdCUOGeseHj_QjLMJVbHBEJKkRbXFsmZi6Mob_3IsVfxO-mQQC-xfY9tDyB1jhxfFAG-rjUfRVBwYYPfaVo2W58Q09Kcpf-43Iw9SRxx2ThP-KPFJPFBofZroloNaTNz3DRaWZ2ha-_PUG2nwTXR7LoIpqMVW1PDzGxb47SNpRmKJxVZhQ2_wRhZZvHRHJpZmrCmHRpTRqWSzQT1jn7Zo9VuMYvp_OFj7-LFpkqi4BYyhi0kTBPDQTpYrBi7RtmF1MhZBmm1HGDhoXHcPSZkN5vq5at4g03R15KWyRDgBcckCAgtewd6Dtd_Zwaejlm57xyGqP6T-AE-N8udh1NPv_PZVlSc4CnCayUTPORuaJ7N-v7Y4wpNSIdipq29hw19WVuO_z7q6GpQbn17arYf6LSoDZfwO8GHXPrtBOYYSZCNKuZ_IK8nomBLJPtN5AzwEZNyLCZIkg0U0sJ-oVr2UEYxlwwZQm5RSDxProaKU-OXq4f_j_0pEu5_DbJx9syR3Nsv6Lt9Zkf3JSJTVtWXoM0-R_82vAJ669PX0LLr603PKWBZbW7zQvtGojT_Pc1FDGfwhcdckxd3MGpEjZwh_1D8elYcxj3Ndw5jClWosZKr33pUcjqeFtSZSur0lbm6vyCfS16XzSMn8IkHmbbXcpgGKHumUCFD8CHJIBAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBSMmnF_AA0xD8rW7i0pqjSXJYwSHjAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAHG-1grb-6xpObMtxfFScl8PRLd_GjLFaeAd0kVPls0jzKplG2Am4O87Qg0OUY0VhQ-uD39590gGrWEWnOmdrVJ-R1lJc1yrIZFEASBEedJSvxw9YTNknD59uXtznIP_4Glk-4NpqpcYov2OkBdV59V4dTL5oWFH0vzkZQfvGFxEHwtB9O6Bh0Lk142zXAh5_vf_-hSw3t9adloBAnA0AtPUVkzmgNRGeTpfPm-Iud-MAoUXaccFn2EChjKb9ApbS1ww8ZvX4x2kFU6qctu32g7Vf6CgACc1i-UYDT_E-h6c1O4n7JK2OxVS-DVwybps-cALU0gj-ZMauNMej0_x_NerzvDuQ77eFMTDMY4ZTzYOzlg4Nj0K8y1Bx_KqeTBO0N9CdEG3dBxWCUUFQzAx-i38xJL-dtYTCCFATVhc9FFJ0CQgU07JAGAeuNm_GL8kN46bMXd_ApQYFzDQUWYYXvRIt9mCw0Zd45lpAMuiDKT9TgjUVDNu8LQ8FPK0KeiQVrGHFMhHgg2pbVH9Pvc1jNEeRpCo0BLpZQwuIgEt90mepkt6Va-C9krHsU4y2oalG2LUu-jOC3NWNK8LssYVUCFWtaKh5d-xdTQmjx4uO-1sq9GFntVJ94QnEDhldz0XMopQ8srTGLMqR3MT-GkSNb5X1UFC-X1udXI8YvB3ADr_Z3B1YkFyZWFZATYAAQALAAYEcgAgnf_L82w4OuaZ-5ho3G3LidcVOIS-KAOSLBJBWL-tIq4AEAAQCAAAAAAAAQC6zY02JuN_qf28iVCISa6d6aUM5sS2PsKvZMO0P_-28lLX_9-xbmbEcTPvCj5aIEqVUfCb07U4qCBBUdaWygAbhAckvzYrACm5I8hjMoGkxMkZLw5kX0SjtHx6VfgksElxnu4DcC2g9pqL_McgddZV0zNGrYNj1iamzoxTyOcYyvZjQv_4gU-t9mEc0uqHHv-H6k23p4mensyaGAhkGTV8odyBxsNpdnR8IPnXWPO7tBDTbk4mg3VtclqLhS0-TCh_QnZ6lcEl27wTE8FjwqVdQG9F1Ouyn-eNAAq0EufbzwjSNpuDrlj-Kj5xY_lS5BMEjQUXqP-U5nzW22TehX8VaGNlcnRJbmZvWKH_VENHgBcAIgALt-OVET9fzihC1dzyG5xG70MVdRkPpSEkWQ0nns4zaYkAFGo6XjXu3JY-wup-EHJYWEuLpb45AAAACMgZxo6-OwT1-cIZwQGjXsp0dUws1gAiAAvzCsernlTAewF0QwNOA-iWpyhGxC-k_xBRjTtGNz9m6gAiAAs54tyczU1aCAh_N3Vy3qcAnC9zGeOxtQQKCe8CAanbbGhhdXRoRGF0YVkBZ-MWwK8fdtoeGn4DEn0TAUu4IUP_PMiBiJd4lDRznbBDRQAAAAAImHBYytxLgbbhMN5Q3L6WACBxLUIzn9ngKAM11_UwWG7kCiAvVyO1mYGSsEhfWeyhDaQBAwM5AQAgWQEAus2NNibjf6n9vIlQiEmunemlDObEtj7Cr2TDtD__tvJS1__fsW5mxHEz7wo-WiBKlVHwm9O1OKggQVHWlsoAG4QHJL82KwApuSPIYzKBpMTJGS8OZF9Eo7R8elX4JLBJcZ7uA3AtoPaai_zHIHXWVdMzRq2DY9Ymps6MU8jnGMr2Y0L_-IFPrfZhHNLqhx7_h-pNt6eJnp7MmhgIZBk1fKHcgcbDaXZ0fCD511jzu7QQ025OJoN1bXJai4UtPkwof0J2epXBJdu8ExPBY8KlXUBvRdTrsp_njQAKtBLn288I0jabg65Y_io-cWP5UuQTBI0FF6j_lOZ81ttk3oV_FSFDAQAB"),
        attestationRootCertificate = Some(
          CertificateParser.parsePem("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")
        ),
      ),
    )

  val ThinkpadTpm =
    Example(
      RelyingPartyIdentity
        .builder()
        .id("localhost")
        .name("")
        .build(),
      UserIdentity
        .builder()
        .name("")
        .displayName("")
        .id(ByteArray.fromHex(""))
        .build(),
      AttestationExample(
        base64UrlToString(
          "eyJjaGFsbGVuZ2UiOiJfMFdGM2x4SkJrMGt2MWVPRm9fTVBvR2lxN2FJQ1FuZE9LNnZUTHIzdGlJIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
        ),
        ByteArray.fromBase64Url("o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCEKQ2G_8imGnAGz6sMJt83YeXVvNbFUbp0N8h6wc9QYAOenccuhi4J7mnNZc135wLXALq8vNTWDDD67sKxhilDrHJVjmfW6kqfqqpWLd690axr1f5kKkKoX39tlzgdYIUkP_j4V9shw8MDzg4suydM4aHV-8_Jpj5uetKD3fQAc5-_hViQWxnVia4y6mCJX1zsWeJzSyHSj2iCXcGPXKDjKT0Tp8PIEhxAnwHydeeVJROXX81FeMtIHH-uyZGHLbtd7fFQGzh7EkylpKq1-AgqdHg31yyTLwlBFbMJZI4J2EbiVVcOwhnwlVDxmLxGrOYrR3IhSfbxbVUeDB9BxeFBY3ZlcmMyLjBjeDVjglkFxDCCBcAwggOooAMCAQICEGu14PkkxknAkZ5WlOoLzc4wDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLVNUTS1LRVlJRC1GQjE3RDcwRDczNDg3MEU5MTlDNEU4RTYwMzk3NUU2NjRFMEU0M0RFMB4XDTIxMDkxNTA1NTAxNloXDTI3MDYwMzE5NDAyNFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMUTu2yJJlcZ4UC-MpEfquQzRMLN6Yx3xUiatq9UFepWfW1bEywIQ9kR5Ik8ySdMyfDSMkb3291kmu-Xe0zV6Mtc6RoL1OTZ1hxiaZnmbggSK2A8r4loZQVkaqe4xq3r9LRuJRLhq22Wv3Rbif5mjy4YEX8VbsfLDyHJdgBrHVkcbsvhFgcrMbbtsKhYVRs8M8Q1eHWecpwiNYt8DDKL2qsXsKDeGmAad6Rs4_018SydeRLU9jA6dNLgzT3h2627jTRzIEWv5wcCNzPrK67bOeD8LLTzMtJ4gm0VAqZD1gwzac-57IhLi0lgnCtoKbJNvPANlcuWv7uFguNp-BlEld0CAwEAAaOCAfMwggHvMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFkGA1UdEQEB_wRPME2kSzBJMRYwFAYFZ4EFAgEMC2lkOjUzNTQ0RDIwMRcwFQYFZ4EFAgIMDFNUMzNIVFBIQUhEODEWMBQGBWeBBQIDDAtpZDowMDAxMDEwMjAfBgNVHSMEGDAWgBQ4pJZObjM-jRpJDnX8A7aFbZT8iDAdBgNVHQ4EFgQU9ck5AaWROjPDxg5CPMawzb8wh44wgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1zdG0ta2V5aWQtZmIxN2Q3MGQ3MzQ4NzBlOTE5YzRlOGU2MDM5NzVlNjY0ZTBlNDNkZS84ZTJjZjI5NS1kMjIzLTQ5NmEtOTdlYy0yNTc2OTVjNmMyZmMuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAJp9S81uZwhRbZYZGU_Egb-HliV2pABUAFp28ikpBZ2WVFIWYiegNliH9z3zkhxg-Txg8rwIeeWQQNHfCAE0f1gcfHocoA8xNJSdXhtF-Q_VFGVNf0gEnN_rVvpXKciVbwud359iz8p6BFtkzxTQayKcjZdvVGIdyGElUWN5J7pSKHJFtx7C-zdHN9e-c4I00mf2wjXT1SLxeQplEQyYXOSQjqVN-jkK9SX5xaa32aSh04vkQL-_NtyzcWmrRBFUvq_wQro7S-tJJIAa_eZk9HWQ3zdHpUzt-ZaHqt-r26TH3aeNLMxlYsNmEnj_GJZt6tKoJPA1aShS0Phs_TCzNpvrSJf0eAOY-fL02OPlsPJNh6fKmlePIb-7_Wd8-cwFExw0ditlCKBmh6ff2zX-A5VcaRL-EB-yNdNvErrKHCQLFDX90wTZRy9jLuxo_PuJj7uWDvmv5LPVH_rEh1nNhWQ6ZFAcbiz0VflrIvfXDrDPuxzgA47k6obaA43S-8QhvNUYh2Bj0WCx9ntg4Ou5s7GcLrvOHMWNWqS3ZweXAYPFkKubo2nl9dIy8QzJBSvI9PxO4iuCWJyoLtEVF_QyP1JLaK1NmN6IJxGlPp5f7hbxJIV-VQc_SYtHimYtiu3sIrMDaduju5bCsui4e1Yg9jjGBaSs0kNxJhql-6Mn61lFkG7zCCBuswggTToAMCAQICEzMAAAUtM4db5_ICoa8AAAAABS0wDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMTA2MDMxOTQwMjRaFw0yNzA2MDMxOTQwMjRaMEExPzA9BgNVBAMTNkVVUy1TVE0tS0VZSUQtRkIxN0Q3MEQ3MzQ4NzBFOTE5QzRFOEU2MDM5NzVFNjY0RTBFNDNERTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvu5BtXmmeYhA9MHXP9BXKRWLoSn352DZWpcmSxtASbp2evJt5EiGuyHX637koanGphUUmKk26USKD19nyamCCQy6Wh4_U01DICR3gcaR7nsKE-_uL3ratdR0xwpx_lO6WZw6bvuqsDSVFebZeOYBk310utv4kiMtDYC91-0_JdjSGQtaYvNZJz7NfhNxtOvmLsNl9gjZOQOsF45SjNcRh_0S62qF4g4dM7q1_HuFlWLlDwNzAjn07nE2gNHjJ2zCxCZkh0PoLakKJZZRe1O0CfyQP9cCoPKk7nGfMpKn8wy-RisMzaBopjl7NiyManoUT51qsFzbPNN3vUnqNeRPl9u_PteYMM7Agx73MVX5_76qA49mqrnP_XNpHUD_B6k9Ti2vtV5rnYNFtedbxDwEqdNcMNk068jBhecuFdPdKdatwWDz7oczxt5YyJTGMSuDPRZGHtAgl6Y5lHsFSaozpz_QmlRmlSni5MYyy0Kol7qrcLjgzAr-wG1QHTlRRAyeaUAU0Op1c9yPVYSpwzmOsyI3swQKIZIAhHj8MVBUDsvBotf7GULUKJppfw5B43khwpNZVoUT6wKyYXSKekxPTsxdz7azBCPXWt9qJO4ZIzLzhOFq8eyXySFk92zuTb2gmwWXNLXsjMOm6hqk3sPm9DL_Rn9aSAi7SKJem4ibgNAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBQ4pJZObjM-jRpJDnX8A7aFbZT8iDAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBABjK2-9pxH4S-6fyCAKHHgROS5UvqzLkSZNd0F-3bPJ9q1-kAdUmk0-F6lXpJcGTXG2tcX0VpOoxHYeuugPTYE2YsmVSd4l-_sKPdDKPs5ZoJBYemEUsYjp0I2NUrSjQqSM7OTLUe_wdSEUaD1QIfQ1QmSSoGg8WqR23yswykOrkRomLRJqIQrI4Iyd1pSMhRVkizM_6asjyy_xCi3J29BnNAZFFUnH0fcfR9R6t2MSxo84aYvV8n0cdyFyM_L654kdUZcyqn4R0lfnemOxej4e9_pQLyP0qY1mfJ4TRiCTJ-eG7VmC5tdH9Ol5QhiVsqWYBX6rF8hd7RSLDBr4HF8ve1IF1Nsg0qRtfPjAiax8q6TE_rpe0YMROHRcanBufX7U16idX_l_y6aOyvnezoCqEK1IM8YAE8_GF7RQJN6xNXB171vVudlet-3gIoSp_flCgtIo81V6wRl-CKtaNTNGX0frRaDp-E7I3ullpJqhK5KtQE7AKGUeh8nc9LAKVW0FAnlrs96eDHbB_F53EBFc-UtbYtSpXzx10RvqtctsWOtl5w5dEn6Pl1FugG-KZ_fMWrDAk54WqyojOethgS1SbZb1dwzEixAZeUn7hjPqmI0IE0JJ13HJLPYLgpjWjf29n6NQ4rG7n134zNw1WjKseyCaUnN8AJ8aKDKwGBqTzZ3B1YkFyZWFYdgAjAAsABAByACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAAAwAQACBpJdaeRsAGWM8J7Ggzrz6UfaxqVvCPp7i2WMnpET3wPAAgVexpi_3gtvAFUkDfmn7nClUo4Frlll5SXqF4_pHsRZ5oY2VydEluZm9Yof9UQ0eAFwAiAAu6EyJS-fHebCdmSqrKRgty6cxLOlhTWDEEcQrliLm4RAAULgzA70CJPDT6MArh8TUcdOQzy7cAAAAAOm5LSFsGTXREUtvEAVxGJ1vw24yqACIAC--sVlcrGSUsANgjoHWWzZ4BW-hX-Kh_JDZf73RzdU9oACIAC2StFET4fAgbNWZIjrq6c7H2sX6SR7eYP5ULEZO0Y-_AaGF1dGhEYXRhWKRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAACJhwWMrcS4G24TDeUNy-lgAgGlXlpW7ubQT_I8ECfcY3nh4ih8OawAb51lf-8xSzReqlAQIDJiABIVggaSXWnkbABljPCexoM68-lH2salbwj6e4tljJ6RE98DwiWCBV7GmL_eC28AVSQN-afucKVSjgWuWWXlJeoXj-kexFng"),
      ),
    )

}
