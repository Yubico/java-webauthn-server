package com.yubico.webauthn.rp

import java.security.MessageDigest
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.upokecenter.cbor.CBORObject
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.attestation.MetadataResolver
import com.yubico.u2f.attestation.MetadataObject
import com.yubico.u2f.attestation.MetadataService
import com.yubico.u2f.attestation.resolvers.SimpleResolver
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.FinishRegistrationSteps
import com.yubico.webauthn.data
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticationExtensions
import com.yubico.webauthn.data.MakePublicKeyCredentialOptions
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKey
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.Basic
import com.yubico.webauthn.data.SelfAttestation
import com.yubico.webauthn.data.Discouraged
import com.yubico.webauthn.data.Preferred
import com.yubico.webauthn.data.Required
import com.yubico.webauthn.data.impl.PublicKeyCredential
import com.yubico.webauthn.data.impl.AuthenticatorAttestationResponse
import com.yubico.webauthn.impl.FidoU2fAttestationStatementVerifier
import com.yubico.webauthn.impl.PackedAttestationStatementVerifier
import com.yubico.webauthn.test.TestAuthenticator
import com.yubico.webauthn.util.BinaryUtil
import com.yubico.webauthn.util.WebAuthnCodecs
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.x500.X500Name
import org.junit.runner.RunWith
import org.mockito.Mockito
import org.scalacheck.Gen
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner
import org.scalatest.prop.GeneratorDrivenPropertyChecks

import scala.collection.JavaConverters._
import scala.util.Failure
import scala.util.Success
import scala.util.Try

object RelyingPartyRegistrationSpecTestData extends App {
  regenerateTestData()

  def printTestDataCode(credential: data.PublicKeyCredential[data.AuthenticatorAttestationResponse]): Unit = {
    println(s"""
            |attestationObject = BinaryUtil.fromHex("${BinaryUtil.toHex(credential.response.attestationObject)}").get,
            |clientDataJson = \"\"\"${new String(credential.response.clientDataJSON.toArray, "UTF-8")}\"\"\"
            |
            """.stripMargin)
  }

  def regenerateTestData(): Unit = {
    val td = new RelyingPartyRegistrationSpec().TestData
    for { testData <- List(
      td.FidoU2f.BasicAttestation,
      td.FidoU2f.SelfAttestation,
      td.Packed.BasicAttestation,
      td.Packed.BasicAttestationWithoutAaguidExtension,
      td.Packed.BasicAttestationWithWrongAaguidExtension,
      td.Packed.SelfAttestation,
      td.Packed.SelfAttestationWithWrongAlgValue
    ) } {
      printTestDataCode(testData.regenerate())
    }
  }
}

@RunWith(classOf[JUnitRunner])
class RelyingPartyRegistrationSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  def toJson(obj: Map[String, String]): JsonNode = jsonFactory.objectNode().setAll(obj.mapValues(jsonFactory.textNode).asJava)

  object TestData {
    object AndroidKey {
      val BasicAttestation: TestData = Packed.SelfAttestation.editAttestationObject("fmt", "android-key")
    }
    object AndroidSafetynet {
      val BasicAttestation: TestData = Packed.SelfAttestation.editAttestationObject("fmt", "android-safetynet")
    }
    object FidoU2f {

      val BasicAttestation: TestData = new TestData(
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020bf8facaa1004d6cfe4fd47c3d2824796b15851872d7d1798f08c454503225fffa522582086bc6ebc89b8024e61ff9c373658145e27885541030f0b3ea3686a5df3aced8d03260102215820d71fe87fa84dad983b4d9dcdff748412db764b149dc8368fc47d73f9c23948a7200163666d74686669646f2d7532666761747453746d74bf637835639f5901e6308201e230820189a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d030107034200044903cd14102cd02788ac6f0d521fc90266ccc1e826fce9d7e14d474395323904fc985692cf5183af198e9636a37631dfaed8f75db80a9fa688b9788a4cc9b004a32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d040302034700304402207305e8a31438d77ce8bb1ea096c7de39705eb105ac76e3cb6a6732fba96817a5022027d13d42b3978e1827fb829f0a627a9c1bd2ad198d62a94ecef5125b8a4c681aff637369675848304602210094a16bf8faba050dea79cfcf29e0bc79297aaf4afc4ded2767c8c3d698994a2502210086220589da6deb0dbe1d8b92a0db3fdc749b2a0a6c007fa5229a26594315d0bbffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
      ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(attestationStatementFormat = "fido-u2f") }

      val SelfAttestation: TestData = new TestData(
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f00206df43eaa938b658c53fa71eeb6e89459530e1c7243d17c5a24f98f0e9a523784a5225820c2bdd306fa7bf28dd7b5d3cff0dbc64765f5270df99afc97100927a5a714832a032601022158207216bab0f8646f5fc2b247e203e991e51873fc6ad4d582a07108cb36ba812498200163666d74686669646f2d7532666761747453746d74bf637835639f5901e5308201e130820187a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d030107034200047216bab0f8646f5fc2b247e203e991e51873fc6ad4d582a07108cb36ba812498c2bdd306fa7bf28dd7b5d3cff0dbc64765f5270df99afc97100927a5a714832aa3233021301f060b2b0601040182e51c0101040410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d0403020348003045022100c63552850e2515899dfeda270a4c90212e99f103717d775b411153a3ce23d65e022036710be80f3914b62334beaf834cabceeedf273295d09e42472bd558767f3e9aff637369675847304502207d63e85990c2b2c1768b7fc17a46e32a90535699435ecc8b877da2678e42a73d0221009b17cd3c06dcc846a2f1bb83008ded7be4cf79a04f527a797ce1755cdad9c9e8ffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
      ) { override def regenerate() = TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "fido-u2f") }

    }
    object Packed {

      val BasicAttestation: TestData = new TestData(
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020371eac436c78b973dc166ff1d796ae8c6a7fb6d2ef1d6d66e002de57a4f7223fa522582008ceef3bec50ef0707c7589f0956294659c58f2f510553f8493963e7c1462c7e03260102215820668037a881d6df1949313c107133bce1f90d1d5f398fef00928cab8456d403ec200163666d74667061636b65646761747453746d74bf6373696758473045022100825ddb1368dbbb41f97792fc62c0e6ce3420d5d0ebb5d1800ae81b6b730cb9130220116d8c43fb41fb00f033fe32d6d359438a0414a6bc0d7a2b5297851961d3a4c9637835639f5901e7308201e330820189a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004e6b618628de5526ecb100efb6c4df1ecca142119460b7a81f10a6f0ce680ccc8e9914970b508d74f9b59d5517b50fce25261ceb6d98ad2bac567c0dcd1ecac62a32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d0403020348003045022050f131e4a14bb716c7a86b530feef8d44d405974c7609f5e5666eef32a10155d022100c22c195d307d029f66fddd302b23fbc25c187dd94a3d796ab5a5ce54fc4e95ffffffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
      ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(attestationStatementFormat = "packed") }

      val BasicAttestationWithoutAaguidExtension: TestData = new TestData(
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020c8d081ed22eb272f43c965cceed9a0598c444ba849410ffe464d4c9527cc3b1ba5225820cfae9dcf781519dcf49eac78ce98f3895329af911ec64bfd9433a19dff7e382903260102215820fa99b52c5c6392d8d96c9a46c5c382bd5483cf23413174653fa653b46e24694f200163666d74667061636b65646761747453746d74bf6373696758483046022100fae904dc12f8322dfab8df9a7f5285701df72888d90f232f3433fb384ffa557c022100cef097751b78aa2abca73340072d5069e897b157985d2548a16526d691f282c1637835639f5901c0308201bc30820162a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d0301070342000455aa22ee12d518248bf6fb97c6923d2d94fc39215ce872cf4f08547261c56dab099a229c09148f78f7fb705a25ede498c484122bb0e1eb8276b833c96f6de786300a06082a8648ce3d040302034800304502205c6eac1497c1520bf1a6050cbcd16ce59727ec240319874dadddc5b3f758fabc0221008358c611c21dd085dca675df9c82437d9835fc71866d1b4635653e91ba913067ffffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
      ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(TestAuthenticator.generateAttestationCertificate(extensions = Nil)), attestationStatementFormat = "packed") }

      val BasicAttestationWithWrongAaguidExtension: TestData = new TestData(
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976341000005390f0e0d0c0b0a090807060504030201000020c9e56ad018fca003474751aed40576504d1222308672b09770a3ea11d5af1b7ea522582018af6924402fa6a0756cd534b0740f0a324683a03ea741e92d592ab1e2b78d5a03260102215820c68f6bd3a9fb06fcec89872b518bf31c06d691e6c2b3bb80407517aed270765d200163666d74667061636b65646761747453746d74bf6373696758473045022100d6c52fbb9785b2e4056608523781e3acf9b5beb792474f76819002032873030202204c59e70c8dde385aae4c1b1897292bd804e0f6edc1235e393e9bb9ffe927351e637835639f5901e6308201e230820189a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004784204aef94ff04c0d464ee4dda4c97dca2314f151c718ce9619cc06741c4ccdbf7bb9643096c1f14cd6f51c0b5312dcc31424c73cf4396494be8d75608a5ac5a32530233021060b2b0601040182e51c01010404120410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d04030203470030440220396024ca74d621b2e5c5c1350ddbfd41acde0c95e4c82353de5a7d01d3eb563502201030b24397dce0ca92a0a06ad2ebaef0a281208e6ba44806c5d62aa3b0653c97ffffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
      ) { override def regenerate() = TestAuthenticator.createBasicAttestedCredential(aaguid = Vector[Byte](15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0), attestationStatementFormat = "packed") }

      val SelfAttestation: TestData = new TestData(
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020bd3fe2dff3d47319e56a3a31482632e879f009952d0e96ee6518a7619f017f13a522582056f7131370c5b3b6cffa4e8d7e43a82af3e3ccd3269f09708fd8867766e364e403260102215820a4af49910476085c820d376a0d510c207a0becbbcb72a3d006d71b3c3691b352200163666d74667061636b65646761747453746d74bf6373696758473045022100b128aec3a5f86c809c7401cfbb8fa3ffcbd96c7f79ef5d7d841fc98293d4d3ff02207668604dbac157e01f761459f88fe50497cfd906394ed2d6d61c2c5f91a55e3263616c6726ffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
      ) { override def regenerate() = TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "packed") }

      val SelfAttestationWithWrongAlgValue = new TestData(
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020924bdf8eb58991edbae660c21ac2bf2c71a70c711b354ffabd4e59105c3db9e7a5225820d8ac44b2ebaa675781265b232a73387916181bdc13bc4dd0d9adaa7f85747d6503260102215820afdd3af235ce10ea6c777a1c1d121135d42ec72f914d7209988e272e45709095200163666d74667061636b65646761747453746d74bf6373696758473045022100a7ab74706daed3107824e529b79e067dc63f6dbce777453258592cba2e2822ff02201aa7016a3a8eed64bc9c73be41593a3895f4edb6ad421abd883e23968eb64e1463616c6727ffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","type":"webauthn.create","tokenBinding":{"status":"supported"}}"""
      ) { override def regenerate() = TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "packed", alg = Some(-8)) }
    }
    object Tpm {
      val PrivacyCa: TestData = Packed.SelfAttestation.editAttestationObject("fmt", "tpm")
    }
  }

  case class TestData(
    attestationObject: ArrayBuffer,
    clientDataJson: String,
    authenticatorSelection: Option[AuthenticatorSelectionCriteria] = None,
    clientExtensionResults: AuthenticationExtensions = jsonFactory.objectNode(),
    overrideRequest: Option[MakePublicKeyCredentialOptions] = None,
    requestedExtensions: Option[AuthenticationExtensions] = None,
    rpId: RelyingPartyIdentity = RelyingPartyIdentity(name = "Test party", id = "localhost"),
    userId: UserIdentity = UserIdentity(name = "test@test.org", displayName = "Test user", id = Vector(42, 13, 37))
  ) {
    def regenerate(): data.PublicKeyCredential[data.AuthenticatorAttestationResponse] = null

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

    def editClientData[A <: JsonNode](updater: ObjectNode => A): TestData = copy(
      clientDataJson = WebAuthnCodecs.json.writeValueAsString(
        updater(WebAuthnCodecs.json.readTree(clientDataJson).asInstanceOf[ObjectNode])
      )
    )

    def editClientData[A <: JsonNode](name: String, value: A): TestData = editClientData { clientData: ObjectNode =>
      clientData.set(name, value)
    }
    def editClientData(name: String, value: String): TestData = editClientData(name, jsonFactory.textNode(value))
    def responseChallenge: ArrayBuffer = U2fB64Encoding.decode(clientData.challenge).toVector

    def editClientData(name: String, value: ArrayBuffer): TestData =
      editClientData(
        name,
        jsonFactory.textNode(U2fB64Encoding.encode(value.toArray))
      )

    def editAttestationObject[A <: JsonNode](name: String, value: A): TestData = copy(
      attestationObject = WebAuthnCodecs.cbor.writeValueAsBytes(
        WebAuthnCodecs.cbor.readTree(attestationObject.toArray).asInstanceOf[ObjectNode]
          .set(name, value)
      ).toVector
    )

    def editAttestationObject(name: String, value: String): TestData =
      editAttestationObject(name, jsonFactory.textNode(value))

    def editAuthenticatorData(updater: ArrayBuffer => ArrayBuffer): TestData = {
      val attObj: ObjectNode = WebAuthnCodecs.cbor.readTree(attestationObject.toArray).asInstanceOf[ObjectNode]
      val authData: ArrayBuffer = attObj.get("authData").binaryValue.toVector
      editAttestationObject("authData", jsonFactory.binaryNode(updater(authData).toArray))
    }

    def request: MakePublicKeyCredentialOptions = overrideRequest getOrElse MakePublicKeyCredentialOptions(
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

  val crypto: Crypto = new BouncyCastleCrypto
  def sha256(bytes: ArrayBuffer): ArrayBuffer = crypto.hash(bytes.toArray).toVector

  def finishRegistration(
    allowUntrustedAttestation: Boolean = false,
    authenticatorRequirements: Option[AuthenticatorSelectionCriteria] = None,
    callerTokenBindingId: Option[String] = None,
    credentialId: Option[ArrayBuffer] = None,
    makePublicKeyCredentialOptions: Option[MakePublicKeyCredentialOptions] = None,
    metadataService: Option[MetadataService] = None,
    rp: RelyingPartyIdentity = RelyingPartyIdentity(name = "Test party", id = "localhost"),
    testData: TestData
  ): FinishRegistrationSteps = {
    val clientDataJsonBytes: ArrayBuffer = testData.clientDataJson.getBytes("UTF-8").toVector

    new RelyingParty(
      allowUntrustedAttestation = allowUntrustedAttestation,
      authenticatorRequirements = authenticatorRequirements.asJava,
      challengeGenerator = null,
      origins = List(rp.id).asJava,
      preferredPubkeyParams = Nil.asJava,
      rp = rp,
      credentialRepository = null,
      metadataService = metadataService.asJava
    )._finishRegistration(testData.request, testData.response, callerTokenBindingId.asJava)
  }

  private def notImplemented(): Unit = {
    it("Fails.") {
      fail("Test not implemented.")
    }
  }

  describe("§7.1. Registering a new credential") {

    describe("When registering a new credential, represented by an AuthenticatorAttestationResponse structure response and an AuthenticationExtensionsClientOutputs structure clientExtensionResults, as part of a registration ceremony, a Relying Party MUST proceed as follows:") {

      describe("1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.") {
        it("Nothing to test.") {}
      }

      describe("2. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.") {

        it("Fails if clientDataJson is not valid JSON.") {
          val steps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.copy(
              clientDataJson = "{",
              overrideRequest = Some(TestData.FidoU2f.BasicAttestation.request)
            )
          )
          val step: steps.Step2 = steps.begin.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe a [JsonParseException]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if clientDataJson is valid JSON.") {
          val steps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.copy(
              clientDataJson = "{}",
              overrideRequest = Some(TestData.FidoU2f.BasicAttestation.request)
            )
          )
          val step: steps.Step2 = steps.begin.next.get

          step.validations shouldBe a [Success[_]]
          step.clientData should not be null
          step.next shouldBe a [Success[_]]
        }
      }

      describe("3. Verify that the value of C.type is webauthn.create.") {
        it("The default test case succeeds.") {
          val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
          val step: steps.Step3 = steps.begin.next.get.next.get

          step.validations shouldBe a [Success[_]]
        }


        def assertFails(typeString: String): Unit = {
          val steps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.editClientData("type", typeString)
          )
          val step: steps.Step3 = steps.begin.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
        }

        it("""Any value other than "webauthn.create" fails.""") {
          forAll { (typeString: String) =>
            whenever (typeString != "webauthn.create") {
              assertFails(typeString)
            }
          }
          forAll(Gen.alphaNumStr) { (typeString: String) =>
            whenever (typeString != "webauthn.create") {
              assertFails(typeString)
            }
          }
        }
      }

      it("4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.") {
        val steps = finishRegistration(
          testData = TestData.FidoU2f.BasicAttestation.copy(
            overrideRequest = Some(TestData.FidoU2f.BasicAttestation.request.copy(challenge = Vector.fill(16)(0: Byte)))
          )
        )
        val step: steps.Step4 = steps.begin.next.get.next.get.next.get

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [AssertionError]
        step.next shouldBe a [Failure[_]]
      }

      it("5. Verify that the value of C.origin matches the Relying Party's origin.") {
        val steps = finishRegistration(
          testData = TestData.FidoU2f.BasicAttestation.editClientData("origin", "root.evil")
        )
        val step: steps.Step5 = steps.begin.next.get.next.get.next.get.next.get

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [AssertionError]
        step.next shouldBe a [Failure[_]]
      }

      describe("6. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained.") {
        it("Verification succeeds if neither side uses token binding ID.") {
          val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification succeeds if assertion specifies token binding is unsupported, and caller does not use it.") {
          val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation
            .editClientData("tokenBinding", toJson(Map("status" -> "not-supported")))
          )
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification succeeds if assertion specifies token binding is supported, and caller does not use it.") {
          val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation
            .editClientData("tokenBinding", toJson(Map("status" -> "supported")))
          )
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification fails if assertion does not specify token binding status.") {
          val steps = finishRegistration(
            callerTokenBindingId = None,
            testData = TestData.FidoU2f.BasicAttestation.editClientData(_.without("tokenBinding"))
          )
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Verification fails if assertion specifies token binding ID but caller does not.") {
          val steps = finishRegistration(
            callerTokenBindingId = None,
            testData = TestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "present", "id" -> "YELLOWSUBMARINE")))
          )
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        describe("If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.") {
          it("Verification succeeds if both sides specify the same token binding ID.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              testData = TestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "present", "id" -> "YELLOWSUBMARINE")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Verification fails if ID is missing from tokenBinding in assertion.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              testData = TestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "present")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("Verification fails if caller specifies token binding ID but assertion does not support it.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              testData = TestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "not-supported")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("Verification fails if caller specifies token binding ID but assertion does not use it.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              testData = TestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "supported")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("Verification fails if assertion and caller specify different token binding IDs.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("ORANGESUBMARINE"),
              testData = TestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "supported", "id" -> "YELLOWSUBMARINE")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }
        }

      }

      it("7. Compute the hash of response.clientDataJSON using SHA-256.") {
        val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
        val step: steps.Step7 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get

        step.validations shouldBe a [Success[_]]
        step.next shouldBe a [Success[_]]
        step.clientDataJsonHash should equal (MessageDigest.getInstance("SHA-256").digest(TestData.FidoU2f.BasicAttestation.clientDataJsonBytes.toArray).toVector)
      }

      it("8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.") {
        val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
        val step: steps.Step8 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get

        step.validations shouldBe a [Success[_]]
        step.next shouldBe a [Success[_]]
        step.attestation.format should equal ("fido-u2f")
        step.attestation.authenticatorData should not be null
        step.attestation.attestationStatement should not be null
      }

      describe("9. Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.") {
        it("Fails if RP ID is different.") {
          val steps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.editAuthenticatorData { authData: ArrayBuffer =>
              Vector.fill[Byte](32)(0) ++ authData.drop(32)
            }
          )
          val step: steps.Step9 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if RP ID is the same.") {
          val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
          val step: steps.Step9 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("10. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.") {
        val testData = TestData.Packed.BasicAttestation
        val authData = testData.response.response.authenticatorData

        def flagOn(authData: ArrayBuffer): ArrayBuffer = authData.updated(32, (authData(32) | 0x04).toByte)
        def flagOff(authData: ArrayBuffer): ArrayBuffer = authData.updated(32, (authData(32) & 0xfb).toByte)

        it("Succeeds if UV is discouraged and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Discouraged))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is discouraged and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Discouraged))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is preferred and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Preferred))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is preferred and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Preferred))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Fails if UV is required and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Required))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if UV is required and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Required))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("11. If user verification is not required for this registration, verify that the User Present bit of the flags in authData is set.") {
        val testData = TestData.Packed.BasicAttestation
        val authData = testData.response.response.authenticatorData

        def flagOn(authData: ArrayBuffer): ArrayBuffer = authData.updated(32, (authData(32) | 0x04 | 0x01).toByte)
        def flagOff(authData: ArrayBuffer): ArrayBuffer = authData.updated(32, ((authData(32) | 0x04) & 0xfe).toByte)

        it("Fails if UV is discouraged and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Discouraged))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if UV is discouraged and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Discouraged))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Fails if UV is preferred and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Preferred))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if UV is preferred and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Preferred))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is required and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Required))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is required and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Required))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("12. Verify that the values of the ") {

        describe("client extension outputs in clientExtensionResults are as expected, considering the client extension input values that were given as the extensions option in the create() call. In particular, any extension identifier values in the clientExtensionResults MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          it("Fails if clientExtensionResults is not a subset of the extensions requested by the Relying Party.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode()),
                clientExtensionResults = jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an[AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("Succeeds if clientExtensionResults is empty.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = None,
                clientExtensionResults = jsonFactory.objectNode()
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if clientExtensionResults is empty and requested extensions is an empty object.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode()),
                clientExtensionResults = jsonFactory.objectNode()
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if clientExtensionResults is a subset of the extensions requested by the Relying Party.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar"))),
                clientExtensionResults = jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }
        }

        describe("authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the create() call. In particular, any extension identifier values in the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          it("Fails if authenticator extensions is not a subset of the extensions requested by the Relying Party.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode())
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) | 0x80).toByte) ++
                  WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))).toVector
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an[AssertionError]
            step.next shouldBe a [Failure[_]]

          }

          it("Succeeds if authenticator extensions is not present.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = None
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) & 0x7f).toByte)
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if authenticator extensions is empty.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = None
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) | 0x80).toByte) ++
                  WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode()).toVector
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if authenticator extensions is not present and requested extensions is an empty object.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode())
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) & 0x7f).toByte)
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if authenticator extensions is empty and requested extensions is an empty object.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode())
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) | 0x80).toByte) ++
                  WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode()).toVector
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if authenticator extensions is a subset of the extensions requested by the Relying Party.") {
            val steps = finishRegistration(
              testData = TestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar")))
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) | 0x80).toByte) ++
                  WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))).toVector
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }
        }

      }

      describe("13. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].") {
        def setup(format: String): FinishRegistrationSteps = {
          finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.editAttestationObject("fmt", format)
          )
        }

        def checkFailure(format: String): Unit = {
          it(s"""Fails if fmt is "${format}".""") {
            val steps = setup(format)
            val step: steps.Step13 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }
        }

        def checkSuccess(format: String): Unit = {
          it(s"""Succeeds if fmt is "${format}".""") {
            val steps = setup(format)
            val step: steps.Step13 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
            step.format should equal (format)
            step.formatSupported should be(true)
          }
        }

        checkSuccess("android-key")
        checkSuccess("android-safetynet")
        checkSuccess("fido-u2f")
        checkSuccess("packed")
        checkSuccess("tpm")

        checkFailure("FIDO-U2F")
        checkFailure("Fido-U2F")
        checkFailure("bleurgh")
      }

      describe("14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.") {

        describe("For the fido-u2f statement format,") {
          it("the default test case is a valid basic attestation.") {
            val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
            val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (Basic)
            step.next shouldBe a [Success[_]]
          }

          it("a test case with self attestation is valid.") {
            val steps = finishRegistration(testData = TestData.FidoU2f.SelfAttestation)
            val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (SelfAttestation)
            step.next shouldBe a [Success[_]]
          }

          def flipByte(index: Int, bytes: ArrayBuffer): ArrayBuffer = bytes.updated(index, (0xff ^ bytes(index)).toByte)

          it("a test case with different signed client data is not valid.") {
            val testData = TestData.FidoU2f.SelfAttestation
            val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
            val step: steps.Step14 = new steps.Step14(
              attestation = AttestationObject(testData.attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(testData.clientDataJsonBytes.updated(20, (testData.clientDataJsonBytes(20) + 1).toByte).toArray).toVector,
              attestationStatementVerifier = FidoU2fAttestationStatementVerifier
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          def mutateAuthenticatorData(attestationObject: ArrayBuffer)(mutator: ArrayBuffer => ArrayBuffer): ArrayBuffer = {
            val decodedCbor: ObjectNode = WebAuthnCodecs.cbor.readTree(attestationObject.toArray).asInstanceOf[ObjectNode]
            decodedCbor.set("authData", jsonFactory.binaryNode(mutator(decodedCbor.get("authData").binaryValue().toVector).toArray))

            WebAuthnCodecs.cbor.writeValueAsBytes(decodedCbor).toVector
          }

          def checkByteFlipFails(index: Int): Unit = {
            val testData = TestData.FidoU2f.BasicAttestation.editAuthenticatorData { flipByte(index, _) }

            val steps = finishRegistration(
              testData = testData,
              credentialId = Some(Vector.fill[Byte](16)(0))
            )
            val step: steps.Step14 = new steps.Step14(
              attestation = AttestationObject(testData.attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(testData.clientDataJsonBytes.toArray).toVector,
              attestationStatementVerifier = FidoU2fAttestationStatementVerifier
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("a test case with a different signed RP ID hash is not valid.") {
            checkByteFlipFails(0)
          }

          it("a test case with a different signed credential ID is not valid.") {
            checkByteFlipFails(32 + 1 + 4 + 16 + 2 + 1)
          }

          it("a test case with a different signed credential public key is not valid.") {
            val testData = TestData.FidoU2f.BasicAttestation.editAuthenticatorData { authenticatorData =>
              val decoded = AuthenticatorData(authenticatorData)
              val L = decoded.attestationData.get.credentialId.length
              val evilPublicKey = decoded.attestationData.get.credentialPublicKey.updated(30, 0: Byte)

              authenticatorData.take(32 + 1 + 4 + 16 + 2 + L) ++ evilPublicKey
            }
            val steps = finishRegistration(
              testData = testData,
              credentialId = Some(Vector.fill[Byte](16)(0))
            )
            val step: steps.Step14 = new steps.Step14(
              attestation = AttestationObject(testData.attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(testData.clientDataJsonBytes.toArray).toVector,
              attestationStatementVerifier = FidoU2fAttestationStatementVerifier
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          describe("if x5c is not a certificate for an ECDSA public key over the P-256 curve, stop verification and return an error.") {
            val testAuthenticator = TestAuthenticator

            def checkRejected(keypair: KeyPair): Unit = {
              val credential = testAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                testData = TestData(
                  attestationObject = credential.response.attestationObject,
                  clientDataJson = new String(credential.response.clientDataJSON.toArray, "UTF-8")
                ),
                credentialId = Some(credential.rawId)
              )
              val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              val standaloneVerification = Try {
                FidoU2fAttestationStatementVerifier.verifyAttestationSignature(
                  credential.response.attestation,
                  new BouncyCastleCrypto().hash(credential.response.clientDataJSON.toArray).toVector
                )
              }

              step.validations shouldBe a [Failure[_]]
              step.validations.failed.get shouldBe an [AssertionError]
              step.next shouldBe a [Failure[_]]

              standaloneVerification shouldBe a [Failure[_]]
              standaloneVerification.failed.get shouldBe an [AssertionError]
            }

            def checkAccepted(keypair: KeyPair): Unit = {
              val credential = testAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                testData = TestData(
                  attestationObject = credential.response.attestationObject,
                  clientDataJson = new String(credential.response.clientDataJSON.toArray, "UTF-8")
                ),
                credentialId = Some(credential.rawId)
              )
              val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              val standaloneVerification = Try {
                FidoU2fAttestationStatementVerifier.verifyAttestationSignature(
                  credential.response.attestation,
                  new BouncyCastleCrypto().hash(credential.response.clientDataJSON.toArray).toVector
                )
              }

              step.validations shouldBe a [Success[_]]
              step.next shouldBe a [Success[_]]

              standaloneVerification should equal (Success(true))
            }

            it("An RSA attestation certificate is rejected.") {
              checkRejected(testAuthenticator.generateRsaKeypair())
            }

            it("A secp256r1 attestation certificate is accepted.") {
              checkAccepted(testAuthenticator.generateEcKeypair(curve = "secp256r1"))
            }

            it("A secp256k1 attestation certificate is rejected.") {
              checkRejected(testAuthenticator.generateEcKeypair(curve = "secp256k1"))
            }

            it("A P-256 attestation certificate is accepted.") {
              checkAccepted(testAuthenticator.generateEcKeypair(curve = "P-256"))
            }
          }
        }

        describe("For the packed statement format") {
          val verifier = PackedAttestationStatementVerifier

          it("the attestation statement verifier implementation is PackedAttestationStatementVerifier.") {
            val steps = finishRegistration(testData = TestData.Packed.BasicAttestation)
            val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.attestationStatementVerifier should be theSameInstanceAs PackedAttestationStatementVerifier
          }

          describe("the verification procedure is:") {
            describe("1. Verify that the given attestation statement is valid CBOR conforming to the syntax defined above.") {

              it("Fails if attStmt.sig is a text value.") {
                val testData = TestData.Packed.BasicAttestation
                  .editAttestationObject("attStmt", jsonFactory.objectNode().set("sig", jsonFactory.textNode("foo")))

                val result: Try[Boolean] = verifier._verifyAttestationSignature(
                  AttestationObject(testData.attestationObject),
                  testData.clientDataJsonHash
                )

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]
              }

              it("Fails if attStmt.sig is missing.") {
                val testData = TestData.Packed.BasicAttestation
                  .editAttestationObject("attStmt", jsonFactory.objectNode().set("x5c", jsonFactory.arrayNode()))

                val result: Try[Boolean] = verifier._verifyAttestationSignature(
                  AttestationObject(testData.attestationObject),
                  testData.clientDataJsonHash
                )

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]
              }
            }

            it("2. Let authenticatorData denote the authenticator data claimed to have been used for the attestation, and let clientDataHash denote the hash of the serialized client data.") {
              val testData = TestData.Packed.BasicAttestation
              val authenticatorData: AuthenticatorData = AttestationObject(testData.attestationObject).authenticatorData
              val clientDataHash = MessageDigest.getInstance("SHA-256").digest(testData.clientDataJson.getBytes("UTF-8"))

              authenticatorData should not be null
              clientDataHash should not be null
            }

            describe("3. If x5c is present, this indicates that the attestation type is not ECDAA. In this case:") {
              it("The attestation type is identified as Basic.") {
                val steps = finishRegistration(testData = TestData.Packed.BasicAttestation)
                val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.attestationType should be (Basic)
              }

              describe("1. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in x5c with the algorithm specified in alg.") {
                it("Succeeds for the default test case.") {
                  val testData = TestData.Packed.BasicAttestation
                  val result: Try[Boolean] = verifier._verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (Success(true))
                }

                it("Fail if the default test case is mutated.") {
                  val testData = TestData.Packed.BasicAttestation

                  val result: Try[Boolean] = verifier._verifyAttestationSignature(
                    AttestationObject(testData.editAuthenticatorData({ authData: ArrayBuffer => authData.updated(16, if (authData(16) == 0) 1: Byte else 0: Byte) }).attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (Success(false))
                }
              }

              describe("2. Verify that x5c meets the requirements in §7.2.1 Packed attestation statement certificate requirements.") {
                it("Fails for an attestation signature with an invalid country code.") {
                  val authenticator = TestAuthenticator
                  val (badCert, key): (X509Certificate, PrivateKey) = authenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=AA, OU=Authenticator Attestation")
                  )
                  val credential = authenticator.createBasicAttestedCredential(
                    attestationCertAndKey = Some(badCert, key),
                    attestationStatementFormat = "packed"
                  )
                  val result = Try(verifier.verifyAttestationSignature(credential.response.attestation, sha256(credential.response.clientDataJSON)))

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]
                }

                it("succeeds for the default test case.") {
                  val testData = TestData.Packed.BasicAttestation
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (true)
                }
              }

              describe("3. If x5c contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the AAGUID in authenticatorData.") {
                it("Succeeds for the default test case.") {
                  val testData = TestData.Packed.BasicAttestation
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  testData.packedAttestationCert.getNonCriticalExtensionOIDs.asScala should equal (Set("1.3.6.1.4.1.45724.1.1.4"))
                  result should equal (true)
                }

                it("Succeeds if the attestation certificate does not have the extension.") {
                  val testData = TestData.Packed.BasicAttestationWithoutAaguidExtension

                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  testData.packedAttestationCert.getNonCriticalExtensionOIDs shouldBe null
                  result should equal (true)
                }

                it("Fails if the attestation certificate has the extension and it does not match the AAGUID.") {
                  val testData = TestData.Packed.BasicAttestationWithWrongAaguidExtension

                  val result = verifier._verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  testData.packedAttestationCert.getNonCriticalExtensionOIDs should not be empty
                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]
                }
              }

              it("If successful, return attestation type Basic and trust path x5c.") {
                val testData = TestData.Packed.BasicAttestation
                val steps = finishRegistration(testData = testData)
                val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.attestationType should be (Basic)
                step.attestationTrustPath should not be empty
                step.attestationTrustPath.get should be (List(testData.packedAttestationCert))
              }
            }

            describe("4. If ecdaaKeyId is present, then the attestation type is ECDAA. In this case:") {
              it("1. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId (see [FIDOEcdaaAlgorithm]).") {
                fail("Test not implemented.")
              }

              it("2. If successful, return attestation type ECDAA and trust path ecdaaKeyId.") {
                fail("Test not implemented.")
              }
            }

            describe("5. If neither x5c nor ecdaaKeyId is present, self attestation is in use.") {
              val testDataBase = TestData.Packed.SelfAttestation

              it("The attestation type is identified as SelfAttestation.") {
                val steps = finishRegistration(testData = testDataBase)
                val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.attestationType should be (SelfAttestation)
              }

              describe("1. Validate that alg matches the algorithm of the credential private key in authenticatorData.") {
                it("Succeeds for the default test case.") {
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testDataBase.attestationObject),
                    testDataBase.clientDataJsonHash
                  )

                  CBORObject.DecodeFromBytes(AttestationObject(testDataBase.attestationObject).authenticatorData.attestationData.get.credentialPublicKey.toArray).get(CBORObject.FromObject(3)).AsInt64 should equal (-7)
                  AttestationObject(testDataBase.attestationObject).attestationStatement.get("alg").longValue should equal (-7)
                  result should equal (true)
                }

                it("Fails if the alg is a different value.") {
                  val testData = TestData.Packed.SelfAttestationWithWrongAlgValue
                  val result = verifier._verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  CBORObject.DecodeFromBytes(AttestationObject(testData.attestationObject).authenticatorData.attestationData.get.credentialPublicKey.toArray).get(CBORObject.FromObject(3)).AsInt64 should equal (-7)
                  AttestationObject(testData.attestationObject).attestationStatement.get("alg").longValue should equal (-257)
                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]
                }
              }

              describe("2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.") {
                it("Succeeds for the default test case.") {
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testDataBase.attestationObject),
                    testDataBase.clientDataJsonHash
                  )
                  result should equal (true)
                }

                it("Fails if the attestation object is mutated.") {
                  val testData = testDataBase.editAuthenticatorData { authData: ArrayBuffer => authData.updated(16, if (authData(16) == 0) 1: Byte else 0: Byte) }
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (false)
                }

                it("Fails if the client data is mutated.") {
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testDataBase.attestationObject),
                    sha256(testDataBase.clientDataJson.updated(4, 'ä').getBytes("UTF-8").toVector)
                  )
                  result should equal (false)
                }

                it("Fails if the client data hash is mutated.") {
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testDataBase.attestationObject),
                    testDataBase.clientDataJsonHash.updated(7, if (testDataBase.clientDataJsonHash(7) == 0) 1: Byte else 0: Byte))
                  result should equal (false)
                }
              }

              it("3. If successful, return attestation type Self and empty trust path.") {
                val testData = TestData.Packed.SelfAttestation
                val steps = finishRegistration(testData = testData)
                val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.attestationType should be (SelfAttestation)
                step.attestationTrustPath shouldBe empty
              }
            }
          }

          describe("7.2.1. Packed attestation statement certificate requirements") {
            val testDataBase = TestData.Packed.BasicAttestation

            describe("The attestation certificate MUST have the following fields/extensions:") {
              it("Version must be set to 3.") {
                val badCert = Mockito.mock(classOf[X509Certificate])
                val principal = new X500Principal("O=Yubico, C=SE, OU=Authenticator Attestation")
                Mockito.when(badCert.getVersion) thenReturn 2
                Mockito.when(badCert.getSubjectX500Principal) thenReturn principal
                Mockito.when(badCert.getBasicConstraints) thenReturn -1
                val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]

                verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (Success(true))
              }

              describe("Subject field MUST be set to:") {
                it("Subject-C: Country where the Authenticator vendor is incorporated") {
                  val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=AA, OU=Authenticator Attestation")
                  )._1
                  val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]

                  verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (Success(true))
                }

                it("Subject-O: Legal name of the Authenticator vendor") {
                  val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                    name = new X500Name("C=SE, OU=Authenticator Attestation")
                  )._1
                  val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]

                  verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(Success(true))
                }

                it("Subject-OU: Authenticator Attestation") {
                  val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=SE, OU=Foo")
                  )._1
                  val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]

                  verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(Success(true))
                }

                it("Subject-CN: No stipulation.") {
                  // Nothing to test
                }
              }

              it("If the related attestation root certificate is used for multiple authenticator models, the Extension OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as value.") {
                val idFidoGenCeAaguid = "1.3.6.1.4.1.45724.1.1.4"

                val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                  name = new X500Name("O=Yubico, C=SE, OU=Authenticator Attestation"),
                  extensions = List((idFidoGenCeAaguid, false, Vector(0, 1, 2, 3)))
                )._1
                val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]

                val goodCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                  name = new X500Name("O=Yubico, C=SE, OU=Authenticator Attestation"),
                  extensions = Nil
                )._1
                val goodResult = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                goodResult shouldBe a [Failure[_]]
                goodResult.failed.get shouldBe an [AssertionError]

                verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(Success(true))
              }

              it("The Basic Constraints extension MUST have the CA component set to false") {
                val badCert = Mockito.mock(classOf[X509Certificate])
                val principal = new X500Principal("O=Yubico, C=SE, OU=Authenticator Attestation")
                Mockito.when(badCert.getVersion) thenReturn 3
                Mockito.when(badCert.getSubjectX500Principal) thenReturn principal
                Mockito.when(badCert.getBasicConstraints) thenReturn 0
                val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]

                verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (Success(true))
              }

              it("An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both optional as the status of many attestation certificates is available through authenticator metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].") {
                fail("Test not implemented.")
              }
            }
          }
        }

        it("The tpm statement format is supported.") {
          val steps = finishRegistration(testData = TestData.Tpm.PrivacyCa)
          val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("The android-key statement format is supported.") {
          val steps = finishRegistration(testData = TestData.AndroidKey.BasicAttestation)
          val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("The android-safetynet statement format is supported.") {
          val steps = finishRegistration(testData = TestData.AndroidSafetynet.BasicAttestation)
          val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("15. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.") {

        describe("For the fido-u2f statement format") {

          it("with self attestation, no trust anchors are returned.") {
            val steps = finishRegistration(testData = TestData.FidoU2f.SelfAttestation)
            val step: steps.Step15 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.trustResolver.asScala shouldBe empty
            step.next shouldBe a [Success[_]]
          }

          it("with basic attestation, a trust resolver is returned.") {
            val metadataResolver: MetadataResolver = new SimpleResolver
            val metadataService: MetadataService = new MetadataService(metadataResolver, null, null)
            val steps = finishRegistration(
              testData = TestData.FidoU2f.BasicAttestation,
              metadataService = Some(metadataService)
            )
            val step: steps.Step15 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.trustResolver.get should not be null
            step.next shouldBe a [Success[_]]
          }

        }

      }

      describe("16. Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows:") {

        describe("If self attestation was used, check if self attestation is acceptable under Relying Party policy.") {

          describe("The default test case, with self attestation,") {
            it("is rejected if untrusted attestation is not allowed.") {
              val steps = finishRegistration(
                testData = TestData.FidoU2f.SelfAttestation,
                allowUntrustedAttestation = false
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Failure[_]]
              step.validations.failed.get shouldBe an [AssertionError]
              step.attestationTrusted should be (false)
              step.next shouldBe a [Failure[_]]
            }

            it("is accepted if untrusted attestation is allowed.") {
              val steps = finishRegistration(
                testData = TestData.FidoU2f.SelfAttestation,
                allowUntrustedAttestation = true
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (true)
              step.next shouldBe a [Success[_]]
            }
          }
        }

        it("If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 15.") {
          fail("Not implemented.")
        }

        describe("Otherwise, use the X.509 certificates returned by the verification procedure to verify that the attestation public key correctly chains up to an acceptable root certificate.") {

          def generateTests(testData: TestData): Unit = {
            it("is rejected if untrusted attestation is not allowed and trust cannot be derived from the trust anchors.") {
              val metadataResolver = new SimpleResolver
              val metadataService: MetadataService = new MetadataService(metadataResolver, null, null) // Stateful - do not share between tests
              val steps = finishRegistration(
                allowUntrustedAttestation = false,
                testData = testData,
                metadataService = Some(metadataService)
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Failure[_]]
              step.attestationTrusted should be (false)
              step.attestationMetadata.asScala should not be empty
              step.attestationMetadata.get.getMetadataIdentifier should be (null)
              step.next shouldBe a [Failure[_]]
            }

            it("is accepted if untrusted attestation is allowed and trust cannot be derived from the trust anchors.") {
              val metadataResolver = new SimpleResolver
              val metadataService: MetadataService = new MetadataService(metadataResolver, null, null) // Stateful - do not share between tests
              val steps = finishRegistration(
                allowUntrustedAttestation = true,
                testData = testData,
                metadataService = Some(metadataService)
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (false)
              step.attestationMetadata.asScala should not be empty
              step.attestationMetadata.get.getMetadataIdentifier should be (null)
              step.next shouldBe a [Success[_]]
            }

            it("is accepted if trust can be derived from the trust anchors.") {
              val metadataResolver = new SimpleResolver
              val metadataService: MetadataService = new MetadataService(metadataResolver, null, null) // Stateful - do not share between tests
              val attestationCaCertPem = IOUtils.toString(getClass.getResourceAsStream("/attestation-ca-cert.pem"), "UTF-8")

              metadataResolver.addMetadata(
                new MetadataObject(
                  jsonFactory.objectNode().setAll(Map(
                    "vendorInfo" -> jsonFactory.objectNode(),
                    "trustedCertificates" -> jsonFactory.arrayNode().add(jsonFactory.textNode(attestationCaCertPem)),
                    "devices" -> jsonFactory.arrayNode(),
                    "identifier" -> jsonFactory.textNode("Test attestation CA"),
                    "version" -> jsonFactory.numberNode(42)
                  ).asJava)
                )
              )

              val steps = finishRegistration(
                testData = testData,
                metadataService = Some(metadataService)
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (true)
              step.attestationMetadata.asScala should not be empty
              step.attestationMetadata.get.getMetadataIdentifier should equal ("Test attestation CA")
              step.next shouldBe a [Success[_]]
            }
          }

          describe("An android-key basic attestation") {
            it("fails for now.") {
              fail("Test not implemented.")
            }
          }

          describe("An android-safetynet basic attestation") {
            it("fails for now.") {
              fail("Test not implemented.")
            }
          }

          describe("A fido-u2f basic attestation") {
            generateTests(testData = TestData.FidoU2f.BasicAttestation)
          }

          describe("A packed basic attestation") {
            generateTests(testData = TestData.Packed.BasicAttestation)
          }
        }

      }

      describe("17. Check that the credentialId is not yet registered to any other user. If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.") {
        notImplemented()
      }

      describe("18. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.") {
        it("Nothing to test.") {}
      }

      describe("19. If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.") {
        it("Nothing to test.") {}

        describe("NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §6.3.3 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.") {
          it("Nothing to test.") {}
        }
      }

      it("(Deleted) If verification of the attestation statement failed, the Relying Party MUST fail the registration ceremony.") {
        val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation.editClientData("foo", "bar"))
        val step14: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get
        val step15: steps.Step15 = step14.next.get

        step14.validations shouldBe a [Success[_]]
        step14.next shouldBe a [Success[_]]

        step15.validations shouldBe a [Failure[_]]
        step15.validations.failed.get shouldBe an [AssertionError]
        step15.next shouldBe a [Failure[_]]

        steps.run shouldBe a [Failure[_]]
        steps.run.failed.get shouldBe an [AssertionError]
      }

    }

  }

}
