package com.yubico.webauthn.rp

import java.security.cert.X509Certificate

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.data
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AuthenticationExtensionsClientInputs
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKey
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.test.TestAuthenticator
import com.yubico.webauthn.util.BinaryUtil
import com.yubico.webauthn.util.WebAuthnCodecs

import scala.collection.JavaConverters._


object RegistrationTestDataGenerator extends App {
  regenerateTestData()

  def printTestDataCode(
    credential: data.PublicKeyCredential[data.AuthenticatorAttestationResponse],
    caCert: Option[X509Certificate]
  ): Unit = {
    for { caCert <- caCert } {
      println(s"""attestationCaCert = Some(CertificateParser.parseDer(BinaryUtil.fromHex("${BinaryUtil.toHex(caCert.getEncoded)}").get.toArray)),""")
    }
    println(s"""attestationObject = BinaryUtil.fromHex("${BinaryUtil.toHex(credential.response.attestationObject)}").get,
               |clientDataJson = \"\"\"${new String(credential.response.clientDataJSON.toArray, "UTF-8")}\"\"\"
               |
               |
               """.stripMargin)
  }

  def regenerateTestData(): Unit = {
    val td = RegistrationTestData
    for { testData <- List(
      td.FidoU2f.BasicAttestation,
      td.FidoU2f.SelfAttestation,
      td.NoneAttestation.Default,
      td.Packed.BasicAttestation,
      td.Packed.BasicAttestationWithoutAaguidExtension,
      td.Packed.BasicAttestationWithWrongAaguidExtension,
      td.Packed.SelfAttestation,
      td.Packed.SelfAttestationWithWrongAlgValue
    ) } {
      val (cred, cert) = testData.regenerate()
      printTestDataCode(cred, cert)
    }
  }
}

object RegistrationTestData {
  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  object AndroidKey {
    val BasicAttestation: RegistrationTestData = Packed.SelfAttestation.editAttestationObject("fmt", "android-key")
  }
  object AndroidSafetynet {
    val BasicAttestation: RegistrationTestData = Packed.SelfAttestation.editAttestationObject("fmt", "android-safetynet")
  }
  object FidoU2f {

    val BasicAttestation: RegistrationTestData = new RegistrationTestData(
      attestationCaCert = Some(CertificateParser.parseDer(BinaryUtil.fromHex("308201d83082017da00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004cfe9bbc171191c5d3f5237d9ccea472297c97372be0e6559ea4f229f799019889d0ac8a94b21b03db7726486e9ca7df9c913cd4597550aff452004371551e42ca3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203490030460221008c6f70a3f00ce2ea5936cccedfc39edcda300fdf0a2b218be5f1e78bcd1c09c3022100ffb9a8e3f91362df6289b5f7376fd626d7a2c7fe94bb9e5fefb42ea8a1d4cd33").get.toArray)),
      attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f002088e3863ea71f7a8bd90177b64528822945ca4b9a5e3253c37e4ee26fb43525f4a52258200e4db7c79890b728f8d41f28f5da03a743f547d7fd21da628f8bf9841befc1ec03260102215820ebb3465d68d477a6da35516218e46d2788c9d86a2e59fd8a5b4082c0d88d7453200163666d74686669646f2d7532666761747453746d74bf637835639f5901e9308201e53082018ca00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d0301070342000427ef1b1440fd4e7161680aee8e00747e835a57881022e94fd660b90ced70bd2072c3878ec97ba3a4f1e44f0f72e5ee49d89dcdf5ca1245e649801469bc5cd80fa32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d04030203470030440220786cbdb9107d3abcf04e56745e39b5eb4bdd7401154e2c93cf9ca36865b7bae202205f5460e68c9d1f8e7310c1150e334f4adc2fe99de713f8ac31e63eb3395086fdff6373696758473045022100c1b359db4aeb8a43aca81cc428469f1e093fc766f478e45fda54feaa157ff02a02203022f9f1bbfe72b90bc13c2210bf626c25789c360cf8366e5b9fc114225b7319ffff").get,
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
    ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(attestationStatementFormat = "fido-u2f") }

    val SelfAttestation: RegistrationTestData = new RegistrationTestData(
      attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f00206df43eaa938b658c53fa71eeb6e89459530e1c7243d17c5a24f98f0e9a523784a5225820c2bdd306fa7bf28dd7b5d3cff0dbc64765f5270df99afc97100927a5a714832a032601022158207216bab0f8646f5fc2b247e203e991e51873fc6ad4d582a07108cb36ba812498200163666d74686669646f2d7532666761747453746d74bf637835639f5901e5308201e130820187a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d030107034200047216bab0f8646f5fc2b247e203e991e51873fc6ad4d582a07108cb36ba812498c2bdd306fa7bf28dd7b5d3cff0dbc64765f5270df99afc97100927a5a714832aa3233021301f060b2b0601040182e51c0101040410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d0403020348003045022100c63552850e2515899dfeda270a4c90212e99f103717d775b411153a3ce23d65e022036710be80f3914b62334beaf834cabceeedf273295d09e42472bd558767f3e9aff637369675847304502207d63e85990c2b2c1768b7fc17a46e32a90535699435ecc8b877da2678e42a73d0221009b17cd3c06dcc846a2f1bb83008ded7be4cf79a04f527a797ce1755cdad9c9e8ffff").get,
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
    ) { override def regenerate() = TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "fido-u2f") }

  }
  object NoneAttestation {
    val Default = new RegistrationTestData(
      attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020f7c49900dc6073fb5fd1c10ebcd53904c581f7fc989080dc87a30e5701488a79a5225820d5fe91bb518f13b9c484a9d81a14fc400cc1a2ce0151bd415f3190e620a30a85032601022158205e3057e50fb81f4f6a887c94fb9148d2f7e4c688d9c9a54d89465f5618c6cf0a200163666d74646e6f6e656761747453746d74bfffff").get,
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
    ) { override def regenerate() = TestAuthenticator.createUnattestedCredential() }
  }
  object Packed {

    val BasicAttestation: RegistrationTestData = new RegistrationTestData(
      attestationCaCert = Some(CertificateParser.parseDer(BinaryUtil.fromHex("308201d83082017da00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d030107034200040394c5fa42d59c832d6c8e4783eaac8971fdac20105f046a773da02f4d460a9be64df86e87a45124d21c30bf3361ae96840a598a2f2b019ec25b3f8004623b79a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020349003046022100af8544c2c6b656513b5074ba1fc90d0b78b7710501e75fc3f3531d15103f3843022100b8ef7dac90e9168e012be191e0c210de79aec3a4584f0de2f8c6a3e645658cc0").get.toArray)),
      attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020cd51f2253872fad05f2b5307b0df89d47cadb2ace87e518916545900ad5f4eada522582089d3e7e7f696e009be5471fd85378e0072bf61fd5b33de6a6b6880256793148703260102215820925956d46552e8366d2acd2a57a2ed17b3e5f663cd194c56e6554c2f2b8f26de200163666d74667061636b65646761747453746d74bf637369675846304402201c564842e0415dcb4fe08874ea4e05e0f48309cc8ded393c5455e6fe2bd1375302202bb4762e4a4c49fd82f330c4cd4105be16175ee8ae3608989835e3ab50d643a2637835639f5901ea308201e63082018ca00302010202020539300a06082a8648ce3d040302306a3126302406035504030c1d59756269636f20576562417574686e20756e6974207465737473204341310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d030107034200046b06cc7af7fe4b180a251bef098174dabb011f6e72cea398fb6124aed056e7108c01efdf5aacf71e66c42110cf038d36c92faafba32e5ce97a451117341d1fe8a32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d0403020348003045022100d64bf76adeaa2d44bcc7a1f68da98830382ef3a6b6493205c57d4007b151fcf8022012f4568c72be6c76e66c524b8e0cefe529bb385732bffe43672d2709448e3220ffffff").get,
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
    ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(attestationStatementFormat = "packed") }

    val BasicAttestationWithoutAaguidExtension: RegistrationTestData = new RegistrationTestData(
      attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020c8d081ed22eb272f43c965cceed9a0598c444ba849410ffe464d4c9527cc3b1ba5225820cfae9dcf781519dcf49eac78ce98f3895329af911ec64bfd9433a19dff7e382903260102215820fa99b52c5c6392d8d96c9a46c5c382bd5483cf23413174653fa653b46e24694f200163666d74667061636b65646761747453746d74bf6373696758483046022100fae904dc12f8322dfab8df9a7f5285701df72888d90f232f3433fb384ffa557c022100cef097751b78aa2abca73340072d5069e897b157985d2548a16526d691f282c1637835639f5901c0308201bc30820162a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d0301070342000455aa22ee12d518248bf6fb97c6923d2d94fc39215ce872cf4f08547261c56dab099a229c09148f78f7fb705a25ede498c484122bb0e1eb8276b833c96f6de786300a06082a8648ce3d040302034800304502205c6eac1497c1520bf1a6050cbcd16ce59727ec240319874dadddc5b3f758fabc0221008358c611c21dd085dca675df9c82437d9835fc71866d1b4635653e91ba913067ffffff").get,
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
    ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(TestAuthenticator.generateAttestationCertificate(extensions = Nil)), attestationStatementFormat = "packed") }

    val BasicAttestationWithWrongAaguidExtension: RegistrationTestData = new RegistrationTestData(
      attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976341000005390f0e0d0c0b0a090807060504030201000020c9e56ad018fca003474751aed40576504d1222308672b09770a3ea11d5af1b7ea522582018af6924402fa6a0756cd534b0740f0a324683a03ea741e92d592ab1e2b78d5a03260102215820c68f6bd3a9fb06fcec89872b518bf31c06d691e6c2b3bb80407517aed270765d200163666d74667061636b65646761747453746d74bf6373696758473045022100d6c52fbb9785b2e4056608523781e3acf9b5beb792474f76819002032873030202204c59e70c8dde385aae4c1b1897292bd804e0f6edc1235e393e9bb9ffe927351e637835639f5901e6308201e230820189a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004784204aef94ff04c0d464ee4dda4c97dca2314f151c718ce9619cc06741c4ccdbf7bb9643096c1f14cd6f51c0b5312dcc31424c73cf4396494be8d75608a5ac5a32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d04030203470030440220396024ca74d621b2e5c5c1350ddbfd41acde0c95e4c82353de5a7d01d3eb563502201030b24397dce0ca92a0a06ad2ebaef0a281208e6ba44806c5d62aa3b0653c97ffffff").get,
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
    ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(aaguid = Vector[Byte](15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0), attestationStatementFormat = "packed") }

    val SelfAttestation: RegistrationTestData = new RegistrationTestData(
      attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020bd3fe2dff3d47319e56a3a31482632e879f009952d0e96ee6518a7619f017f13a522582056f7131370c5b3b6cffa4e8d7e43a82af3e3ccd3269f09708fd8867766e364e403260102215820a4af49910476085c820d376a0d510c207a0becbbcb72a3d006d71b3c3691b352200163666d74667061636b65646761747453746d74bf6373696758473045022100b128aec3a5f86c809c7401cfbb8fa3ffcbd96c7f79ef5d7d841fc98293d4d3ff02207668604dbac157e01f761459f88fe50497cfd906394ed2d6d61c2c5f91a55e3263616c6726ffff").get,
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
    ) { override def regenerate() = TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "packed") }

    val SelfAttestationWithWrongAlgValue = new RegistrationTestData(
      attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020924bdf8eb58991edbae660c21ac2bf2c71a70c711b354ffabd4e59105c3db9e7a5225820d8ac44b2ebaa675781265b232a73387916181bdc13bc4dd0d9adaa7f85747d6503260102215820afdd3af235ce10ea6c777a1c1d121135d42ec72f914d7209988e272e45709095200163666d74667061636b65646761747453746d74bf6373696758473045022100a7ab74706daed3107824e529b79e067dc63f6dbce777453258592cba2e2822ff02201aa7016a3a8eed64bc9c73be41593a3895f4edb6ad421abd883e23968eb64e1463616c6727ffff").get,
      clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
    ) { override def regenerate() = TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "packed", alg = Some(-8)) }
  }
  object Tpm {
    val PrivacyCa: RegistrationTestData = Packed.SelfAttestation.editAttestationObject("fmt", "tpm")
  }
}

case class RegistrationTestData(
  attestationObject: ArrayBuffer,
  clientDataJson: String,
  authenticatorSelection: Option[AuthenticatorSelectionCriteria] = None,
  clientExtensionResults: AuthenticationExtensionsClientInputs = RegistrationTestData.jsonFactory.objectNode(),
  overrideRequest: Option[PublicKeyCredentialCreationOptions] = None,
  requestedExtensions: Option[AuthenticationExtensionsClientInputs] = None,
  rpId: RelyingPartyIdentity = RelyingPartyIdentity(name = "Test party", id = "localhost"),
  userId: UserIdentity = UserIdentity(name = "test@test.org", displayName = "Test user", id = Vector(42, 13, 37)),
  attestationCaCert: Option[X509Certificate] = None
) {
  def regenerate(): (data.PublicKeyCredential[data.AuthenticatorAttestationResponse], Option[X509Certificate]) = null

  def clientData = CollectedClientData(WebAuthnCodecs.json.readTree(clientDataJson))
  def clientDataJsonBytes: ArrayBuffer = clientDataJson.getBytes("UTF-8").toVector
  def clientDataJsonHash: ArrayBuffer = new BouncyCastleCrypto().hash(clientDataJsonBytes.toArray).toVector
  def aaguid: ArrayBuffer = AttestationObject(attestationObject).authenticatorData.attestationData.get.aaguid
  def packedAttestationCert: X509Certificate =
    CertificateParser.parseDer(
      AttestationObject(attestationObject)
        .attestationStatement
        .get("x5c")
        .get(0)
        .binaryValue
    )

  def editClientData[A <: JsonNode](updater: ObjectNode => A): RegistrationTestData = copy(
    clientDataJson = WebAuthnCodecs.json.writeValueAsString(
      updater(WebAuthnCodecs.json.readTree(clientDataJson).asInstanceOf[ObjectNode])
    )
  )

  def editClientData[A <: JsonNode](name: String, value: A): RegistrationTestData = editClientData { clientData: ObjectNode =>
    clientData.set(name, value)
  }
  def editClientData(name: String, value: String): RegistrationTestData = editClientData(name, RegistrationTestData.jsonFactory.textNode(value))
  def responseChallenge: ArrayBuffer = U2fB64Encoding.decode(clientData.challenge).toVector

  def editClientData(name: String, value: ArrayBuffer): RegistrationTestData =
    editClientData(
      name,
      RegistrationTestData.jsonFactory.textNode(U2fB64Encoding.encode(value.toArray))
    )

  def editAttestationObject[A <: JsonNode](name: String, value: A): RegistrationTestData = copy(
    attestationObject = WebAuthnCodecs.cbor.writeValueAsBytes(
      WebAuthnCodecs.cbor.readTree(attestationObject.toArray).asInstanceOf[ObjectNode]
        .set(name, value)
    ).toVector
  )

  def editAttestationObject(name: String, value: String): RegistrationTestData =
    editAttestationObject(name, RegistrationTestData.jsonFactory.textNode(value))

  def editAuthenticatorData(updater: ArrayBuffer => ArrayBuffer): RegistrationTestData = {
    val attObj: ObjectNode = WebAuthnCodecs.cbor.readTree(attestationObject.toArray).asInstanceOf[ObjectNode]
    val authData: ArrayBuffer = attObj.get("authData").binaryValue.toVector
    editAttestationObject("authData", RegistrationTestData.jsonFactory.binaryNode(updater(authData).toArray))
  }

  def request: PublicKeyCredentialCreationOptions = overrideRequest getOrElse PublicKeyCredentialCreationOptions(
    rp = rpId,
    user = userId,
    challenge = U2fB64Encoding.decode(clientData.challenge).toVector,
    pubKeyCredParams = List(PublicKeyCredentialParameters(`type` = PublicKey, alg = -7L)).asJava,
    extensions = requestedExtensions.asJava,
    authenticatorSelection = authenticatorSelection.asJava
  )

  def response = PublicKeyCredential(
    AttestationObject(attestationObject).authenticatorData.attestationData.get.credentialId,
    AuthenticatorAttestationResponse(attestationObject, clientDataJsonBytes),
    clientExtensionResults
  )
}
