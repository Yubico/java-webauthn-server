package com.yubico.webauthn.test

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
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity

import java.nio.charset.StandardCharsets

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
      assertion: AssertionExample,
  ) {
    def attestationCert: ByteArray =
      new ByteArray(
        attestation.attestationObject.getAttestationStatement
          .get("x5c")
          .get(0)
          .binaryValue()
      )

    def asRegistrationTestData: RegistrationTestData =
      RegistrationTestData(
        alg = WebAuthnTestCodecs.getCoseAlgId(
          attestation.attestationObject.getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
        ),
        attestationObject = attestation.attestationObjectBytes,
        clientDataJson = attestation.clientData,
        privateKey = None,
        assertion = Some(
          AssertionTestData(
            request = AssertionRequest
              .builder()
              .publicKeyCredentialRequestOptions(
                PublicKeyCredentialRequestOptions
                  .builder()
                  .challenge(assertion.collectedClientData.getChallenge)
                  .build()
              )
              .build(),
            response = assertion.credential,
          )
        ),
      )
  }

  val YubiKeyNeo = Example(
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

  val YubiKey4 = Example(
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

  val YubiKey5 = Example(
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

  val YubiKey5Nfc = Example(
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

  val YubiKey5NfcPost5cNfc = Example(
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

  val YubiKey5cNfc = Example(
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

  val YubiKey5Nano = Example(
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

  val YubiKey5Ci = Example(
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

  val SecurityKey = Example(
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

  val SecurityKey2 = Example(
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

  val SecurityKeyNfc = Example(
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

  val AppleAttestationIos = Example(
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

  val AppleAttestationMacos = Example(
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

  val YubikeyFips5Nfc = Example(
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

  val Yubikey5ciFips = Example(
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

  val YubikeyBio_5_5_4 = Example(
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

  val YubikeyBio_5_5_5 = Example(
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

  val LargeBlobWrite = Example(
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

  val LargeBlobRead = Example(
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

}
