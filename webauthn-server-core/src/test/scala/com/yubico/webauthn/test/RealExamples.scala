package com.yubico.webauthn.test

import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity

import java.nio.charset.StandardCharsets

sealed trait HasClientData {
  def clientData: String
  def clientDataJSON: ByteArray =
    new ByteArray(clientData.getBytes(StandardCharsets.UTF_8))
  def challenge: ByteArray =
    ByteArray.fromBase64Url(
      JacksonCodecs.json().readTree(clientData).get("challenge").textValue()
    )
}

object RealExamples {

  case class AttestationExample(
      clientData: String,
      attestationObjectBytes: ByteArray,
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
        "clientExtensionResults": {}
      }""")
  }

  case class AssertionExample(
      id: ByteArray,
      `type`: String = "public-key",
      clientData: String,
      authDataBytes: ByteArray,
      sig: ByteArray,
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
        "clientExtensionResults": {}
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

}
