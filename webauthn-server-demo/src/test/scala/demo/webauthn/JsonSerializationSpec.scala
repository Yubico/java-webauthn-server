package demo.webauthn

import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.rp.RegistrationTestData
import demo.webauthn.data.RegistrationResponse
import demo.webauthn.json.ScalaJackson
import org.scalatest.FunSpec
import org.scalatest.Matchers


class JsonSerializationSpec extends FunSpec with Matchers {

  private val jsonMapper = new ScalaJackson().get

  val authenticationAttestationResponseJson = """{"attestationObject":"v2hhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAFOQABAgMEBQYHCAkKCwwNDg8AIIjjhj6nH3qL2QF3tkUogilFykuaXjJTw35O4m-0NSX0pSJYIA5Nt8eYkLco-NQfKPXaA6dD9UfX_SHaYo-L-YQb78HsAyYBAiFYIOuzRl1o1Hem2jVRYhjkbSeIydhqLln9iltAgsDYjXRTIAFjZm10aGZpZG8tdTJmZ2F0dFN0bXS_Y3g1Y59ZAekwggHlMIIBjKADAgECAgIFOTAKBggqhkjOPQQDAjBqMSYwJAYDVQQDDB1ZdWJpY28gV2ViQXV0aG4gdW5pdCB0ZXN0cyBDQTEPMA0GA1UECgwGWXViaWNvMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJTRTAeFw0xODA5MDYxNzQyMDBaFw0xODA5MDYxNzQyMDBaMGcxIzAhBgNVBAMMGll1YmljbyBXZWJBdXRobiB1bml0IHRlc3RzMQ8wDQYDVQQKDAZZdWJpY28xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlNFMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ-8bFED9TnFhaArujgB0foNaV4gQIulP1mC5DO1wvSByw4eOyXujpPHkTw9y5e5J2J3N9coSReZJgBRpvFzYD6MlMCMwIQYLKwYBBAGC5RwBAQQEEgQQAAECAwQFBgcICQoLDA0ODzAKBggqhkjOPQQDAgNHADBEAiB4bL25EH06vPBOVnReObXrS910ARVOLJPPnKNoZbe64gIgX1Rg5oydH45zEMEVDjNPStwv6Z3nE_isMeY-szlQhv3_Y3NpZ1hHMEUCIQDBs1nbSuuKQ6yoHMQoRp8eCT_HZvR45F_aVP6qFX_wKgIgMCL58bv-crkLwTwiEL9ibCV4nDYM-DZuW5_BFCJbcxn__w","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJBQUVCQWdNRkNBMFZJamRaRUdsNVlscyIsIm9yaWdpbiI6ImxvY2FsaG9zdCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUiLCJ0b2tlbkJpbmRpbmciOnsic3RhdHVzIjoic3VwcG9ydGVkIn19"}"""
  val publicKeyCredentialJson = s"""{"id":"iOOGPqcfeovZAXe2RSiCKUXKS5peMlPDfk7ib7Q1JfQ","response":${authenticationAttestationResponseJson},"clientExtensionResults":{}}"""
  val registrationResponseJson = s"""{"requestId":"request1","credential":${publicKeyCredentialJson}}"""

  it("RegistrationResponse can be deserialized from JSON.") {
    val parsed = jsonMapper.readValue(registrationResponseJson, classOf[RegistrationResponse])
    parsed.getCredential should equal (RegistrationTestData.FidoU2f.BasicAttestation.response)
  }

  it("AuthenticatorAttestationResponse can be deserialized from JSON.") {
    val parsed = jsonMapper.readValue(authenticationAttestationResponseJson, classOf[AuthenticatorAttestationResponse])
    parsed should not be null
  }

}
