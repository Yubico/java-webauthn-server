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


@RunWith(classOf[JUnitRunner])
class RelyingPartyRegistrationSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  object TestData {
    object AndroidKey {
      val BasicAttestation: TestData = Packed.SelfAttestation.editAttestationObject("fmt", "android-key")
    }
    object AndroidSafetynet {
      val BasicAttestation: TestData = Packed.SelfAttestation.editAttestationObject("fmt", "android-safetynet")
    }
    object FidoU2f {
      val BasicAttestation: TestData = TestData(
        // Generated using TestAuthenticator.createBasicAttestedCredential(attestationStatementFormat = "fido-u2f")
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f00204676bec1c411d9c72fe4a755b9757a027544054cc57b74d5a49c37244ae19e82a5225820d35a320abb751691bcebc4ef902a3c3c928d3e023cf689942942a6f3d247b3d203260102215820db2961a7df335e69c81948383ca642493b071dd6d784f6d190361e367c242ce6200163666d74686669646f2d7532666761747453746d74bf637835639f5902fe308202fa308201e2a003020102020103300d06092a864886f70d01010b0500302c312a302806035504030c21576562417574686e20756e69742074657374206174746573746174696f6e204341301e170d3137303931313132353431395a170d3237303930393132353431395a308185310b30090603550406130253453112301006035504070c0953746f636b686f6c6d310f300d060355040a0c0659756269636f311c301a060355040b0c13576562417574686e20756e69742074657374733133303106035504030c2a576562417574686e20756e69742074657374206174746573746174696f6e2063657274696669636174653059301306072a8648ce3d020106082a8648ce3d030107034200046e8e20021f3b33f2f98876aeed34328d8b9fa226576e78e9f5675d3c68af4c24fca58e4f3a26675e9f027329dab2840fc327dafff5f78d81726d16fbbc0ebce2a3819730819430090603551d1304023000301d0603551d0e041604145df47f419caa95f3936fb9e52620ad8c319daa6630460603551d23043f303da130a42e302c312a302806035504030c21576562417574686e20756e69742074657374206174746573746174696f6e204341820900c4bf47d5aff768f730130603551d25040c300a06082b06010505070302300b0603551d0f040403020780300d06092a864886f70d01010b05000382010100bf46d0d0d87718d1b332a754375c6a5c0bc49ae46e728aedbd11e2b510ba90154df29d147f42bcb7762e31ebf33bfd7ab425c31712e58851e29bc997f83c8fd545ce03a05a9a07bdb45eb9c4579aaffd5205b763d9be2317e07e50c983fab7a8a3aea4e57e26c7ec0f33523d3b6eadac44ac6cb59c95108e7c1e8811b45a9e14de379a6d293dcda02ff210b5e2e23319c18e325fe521e53c3edacf0fa484fb51990193928d710e0bab0e682e5c0f89f21d2b1a47d8848b06f3b342ca03f47ad17b5703805d2d96f8797e5f132acc69c7764a0f5011638c2ddd37365c504a480b35a42557b7889d90d04a180c1432a6b3230127e27fc8b7f5dbe450dd4d3c5ce7ff637369675846304402205896af16f7457396a268ee06fd50ee37b953ed2f96a8b85ec4badce4ac3d253d02206c7477f09863f3229129d4ed26f6c08f00861b1e7d3b634548bc5298db16543bffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.create"}"""
      )
      val SelfAttestation: TestData = TestData(
        // Generated using TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "fido-u2f")
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f00206723f8f6e11877f0b08cfc194409f9f74d3829b1812ae5d4dab3f03af15b2b7da5225820041c3ca500b410a00689f90c2ee6dbd24a19aee46d5e680142dd4e1600fbc5a80326010221582096b865d655e848b7ff17722b8c746ba86014b47cbb5db98630892c8a501eabeb200163666d74686669646f2d7532666761747453746d74bf637835639f5901e6308201e230820187a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d0301070342000496b865d655e848b7ff17722b8c746ba86014b47cbb5db98630892c8a501eabeb041c3ca500b410a00689f90c2ee6dbd24a19aee46d5e680142dd4e1600fbc5a8a3233021301f060b2b0601040182e51c0101040410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d0403020349003046022100d59bddc1d75720260512281fce63aa3fbdf7b259fb6a60c29df7b23a6dc8ac6e022100cfb8f5e39d02e37d828ebd9203e93c21d19d9024e00956774f4a7e675fa925d5ff6373696758473045022100e58f18d162dcedc23cc945b52bb415d6b31aceba155f9aef1dc5461c175f221f022007e12fb1ebb1020b29a06b338b05b7950d05e6b1aa4c52c3ab3d168b7df8485affff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.create"}"""
      )
    }
    object Packed {
      val BasicAttestation: TestData = TestData(
        // Generated using TestAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(a.generateAttestationCertificate()), attestationStatementFormat = "packed")
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a849960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020473cccff94947e2790150cf07cf259e62e97f6e1f600938823a26e86f9542a5abf63616c67266178582100b7e901abc5f848f702063a84f9879e7bfc4420e497d74f04f75ec8096d9da33f6179582100d7d5a29171550d0c4fad243b545c27efeef0716a30083c5ea63a01e96056a502ff63666d74667061636b65646761747453746d74bf6373696758483046022100daaf493e85972038aa0805d9fa8ced463810b5e2a3384a599672ed88bf93e6f9022100c8ae12db36eda8b2744a153794b5535d4ea026701ccca594a6e423e60602fb9a637835639f5901e5308201e130820187a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004ac75ebf919ce2e365ebd31192f5d7f58ac2f0bccd774c28a89224e8f2015176eaf8846dda24d97446d5a25eca1a1e1cfba0a8eff76a4d03e15bb4b0c86fa2fc6a3233021301f060b2b0601040182e51c0101040410000102030405060708090a0b0c0d0e0f300a06082a8648ce3d040302034800304502202ee6095203768431cf1b7107675c1cf0eb029096b317b700ce37977b0310f178022100ce5bfb5a58241da8c4e3a86dfafab596b798df87ef5f79ed59d395e11d1817abffffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.create"}"""
      )
      val BasicAttestationWithoutAaguidExtension: TestData = TestData(
        // Generated using TestAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(a.generateAttestationCertificate(extensions = Nil)), attestationStatementFormat = "packed")
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158ab49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f00208a77a78607430f6ddad766aaeecce6d974ca4d42f95be216f0a10ee50bdef599bf63616c6765455332353661785820499841182f0321043a5873495d102de28ef1fb92c230c604dfe8bc21c931c70a61795820220a01182407d642c4ca2a09ba2170a042f087a18bf284ebf83d89eb6a0c65cbff63666d74667061636b65646761747453746d74bf637835639f5901c0308201bc30820162a00302010202020539300a06082a8648ce3d04030230673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b3009060355040613025345301e170d3138303930363137343230305a170d3138303930363137343230305a30673123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473310f300d060355040a0c0659756269636f31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130253453059301306072a8648ce3d020106082a8648ce3d03010703420004056f968a406e763871595e76df2d0f95ea8189ecef39c210daf819bc9826e2ffd8be0631aa372604206e7260f0f5bbf5fb43532a9a0699ac8e31a8203f35e4d6300a06082a8648ce3d0403020348003045022100c7a9fc10eb81f7a888c6e05ea01e94393f95c9fbbf8ec747e967a97db65f45a802200881e68dc8805bd18fa156511f0f5da282378bd77868560f5a8b8f96fdfc3423ff6373696758463044022072f8b21e55bfd74fcf14116bd01b5efe034aae8d9b8b6f3763c02d25e487655a022040438688022ba64c1db18b2c2b9637d6243945ec8b73bbbfef1a4755092a204affff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.create"}"""
      )
      val BasicAttestationWithWrongAaguidExtension: TestData = TestData(
        // Generated using TestAuthenticator.createBasicAttestedCredential(aaguid = Vector[Byte](15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0), attestationStatementFormat = "packed")
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158ac49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976341000005390f0e0d0c0b0a0908070605040302010000202aba487f856dccd69c13c8a0e41332ecafc1965b66dad5027bea312fbc2f45fabf63616c676545533235366178582022387031d413f5dbfe60b9750c0209fdcfa5d6eacae7d1a64504ff7a58aa5d2c6179582100abe15cad50dd40204a4fd4ea1b6b8ec7492b779ab7f8dfd7ecde1e31aefd39c0ff63666d74667061636b65646761747453746d74bf637835639f5902fe308202fa308201e2a003020102020103300d06092a864886f70d01010b0500302c312a302806035504030c21576562417574686e20756e69742074657374206174746573746174696f6e204341301e170d3137303931313132353431395a170d3237303930393132353431395a308185310b30090603550406130253453112301006035504070c0953746f636b686f6c6d310f300d060355040a0c0659756269636f311c301a060355040b0c13576562417574686e20756e69742074657374733133303106035504030c2a576562417574686e20756e69742074657374206174746573746174696f6e2063657274696669636174653059301306072a8648ce3d020106082a8648ce3d030107034200046e8e20021f3b33f2f98876aeed34328d8b9fa226576e78e9f5675d3c68af4c24fca58e4f3a26675e9f027329dab2840fc327dafff5f78d81726d16fbbc0ebce2a3819730819430090603551d1304023000301d0603551d0e041604145df47f419caa95f3936fb9e52620ad8c319daa6630460603551d23043f303da130a42e302c312a302806035504030c21576562417574686e20756e69742074657374206174746573746174696f6e204341820900c4bf47d5aff768f730130603551d25040c300a06082b06010505070302300b0603551d0f040403020780300d06092a864886f70d01010b05000382010100bf46d0d0d87718d1b332a754375c6a5c0bc49ae46e728aedbd11e2b510ba90154df29d147f42bcb7762e31ebf33bfd7ab425c31712e58851e29bc997f83c8fd545ce03a05a9a07bdb45eb9c4579aaffd5205b763d9be2317e07e50c983fab7a8a3aea4e57e26c7ec0f33523d3b6eadac44ac6cb59c95108e7c1e8811b45a9e14de379a6d293dcda02ff210b5e2e23319c18e325fe521e53c3edacf0fa484fb51990193928d710e0bab0e682e5c0f89f21d2b1a47d8848b06f3b342ca03f47ad17b5703805d2d96f8797e5f132acc69c7764a0f5011638c2ddd37365c504a480b35a42557b7889d90d04a180c1432a6b3230127e27fc8b7f5dbe450dd4d3c5ce7ff6373696758463044022034ae9278ba1dcac079e94c292b28a7993a82cb2c0e87ecde14f9385b177f8627022039facd2b523cf6e067fc504308f0e3b1e67d5afd74d6c4838fa391a781fc5c21ffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.create"}"""
      )
      val SelfAttestation: TestData = TestData(
        // Generated using TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "packed")
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f00203d9d5bfaaa4da0ad497290893c912d7b4254040231840d3bda0f44ceba9156b4a5225820b91175047561dae5c25d070685f79252303da23fcbc0cae0623c8d9706805dd60326010221582045ff2cae9d88d50575f707ee3a311d7e72b8d27dca1ddfbe036dc0bb14a668f9200163666d74667061636b65646761747453746d74bf6373696758473045022100e9ad9bd2bb84b59779d6146abd6a58c88599930bac44855c57fa7fda086e840b02206bb7dffeb2c066a8c356a91b3ca903006265c2726cf575cf0231d54c95eeb10263616c6726ffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.create"}"""
      )
      val SelfAttestationWithWrongAlgValue = TestData(
        // Generated using TestAuthenticator.createSelfAttestedCredential(attestationStatementFormat = "packed") after editing generator code to set the wrong alg value
        attestationObject = BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f002042c3d73e9556f5608ceb1d9697180a5718c4cd70b27e825bea233beef405e9f2a52258206c34d919639345ec6d6c93d74fba5a61fb46a3b0c7377eb15b7aa275ef4e549303260102215820e6cb7a6e5d4559d7a9c61ada1778b1e1113031f685ad14dcc9bb4678761be885200163666d74667061636b65646761747453746d74bf637369675847304502200179a686702d4e9cc4682d558edeae8c9c27289c1ca0739f40074de693f7a2d0022100eea8a76c40fe05b490222c6b98cf11a1a3ca72441b0e8cc7d13990b3efa6025663616c67390100ffff").get,
        clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.create"}"""
      )
    }
    object Tpm {
      val PrivacyCa: TestData = Packed.SelfAttestation.editAttestationObject("fmt", "tpm")
    }
  }

  case class TestData(
    attestationObject: ArrayBuffer,
    clientDataJson: String,
    clientExtensionResults: AuthenticationExtensions = jsonFactory.objectNode(),
    overrideRequest: Option[MakePublicKeyCredentialOptions] = None,
    requestedExtensions: Option[AuthenticationExtensions] = None,
    rpId: RelyingPartyIdentity = RelyingPartyIdentity(name = "Test party", id = "localhost"),
    userId: UserIdentity = UserIdentity(name = "test@test.org", displayName = "Test user", id = Vector(42, 13, 37))
  ) {
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
      extensions = requestedExtensions.asJava
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

  describe("§7.1. Registering a new credential") {

    describe("When registering a new credential, represented by a AuthenticatorAttestationResponse structure, as part of a registration ceremony, a Relying Party MUST proceed as follows:") {

      it("1. Perform JSON deserialization on the clientDataJSON field of the AuthenticatorAttestationResponse object to extract the client data C claimed as collected during the credential creation.") {
        val steps = finishRegistration(
          testData = TestData.FidoU2f.BasicAttestation.copy(
            clientDataJson = "{",
            overrideRequest = Some(TestData.FidoU2f.BasicAttestation.request)
          )
        )
        val step1: steps.Step1 = steps.begin

        step1.validations shouldBe a [Failure[_]]
        step1.validations.failed.get shouldBe a [JsonParseException]
        step1.next shouldBe a [Failure[_]]
      }

      describe("2. Verify that the type in C is the string webauthn.create.") {
        it("The default test case succeeds.") {
          val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
          val step: steps.Step4 = steps.begin.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
        }


        def assertFails(typeString: String): Unit = {
          val steps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.editClientData("type", typeString)
          )
          val step: steps.Step2 = steps.begin.next.get

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

      it("3. Verify that the challenge in C matches the challenge that was sent to the authenticator in the create() call.") {
        val steps = finishRegistration(
          testData = TestData.FidoU2f.BasicAttestation.copy(
            overrideRequest = Some(TestData.FidoU2f.BasicAttestation.request.copy(challenge = Vector.fill(16)(0: Byte)))
          )
        )
        val step: steps.Step3 = steps.begin.next.get.next.get

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [AssertionError]
        step.next shouldBe a [Failure[_]]
      }

      it("4. Verify that the origin in C matches the Relying Party's origin.") {
        val steps = finishRegistration(
          testData = TestData.FidoU2f.BasicAttestation.editClientData("origin", "root.evil")
        )
        val step: steps.Step4 = steps.begin.next.get.next.get.next.get

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [AssertionError]
        step.next shouldBe a [Failure[_]]
      }

      describe("5. Verify that the tokenBindingId in C matches the Token Binding ID for the TLS connection over which the attestation was obtained.") {
        it("Verification succeeds if neither side specifies token binding ID.") {
          val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
          val step: steps.Step5 = steps.begin.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification succeeds if both sides specify the same token binding ID.") {
          val steps = finishRegistration(
            callerTokenBindingId = Some("YELLOWSUBMARINE"),
            testData = TestData.FidoU2f.BasicAttestation.editClientData("tokenBindingId", "YELLOWSUBMARINE")
          )
          val step: steps.Step5 = steps.begin.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification fails if caller specifies token binding ID but attestation does not.") {
          val steps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation,
            callerTokenBindingId = Some("YELLOWSUBMARINE")
          )
          val step: steps.Step5 = steps.begin.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Verification fails if attestation specifies token binding ID but caller does not.") {
          val steps = finishRegistration(
            callerTokenBindingId = None,
            testData = TestData.FidoU2f.BasicAttestation.editClientData("tokenBindingId", "YELLOWSUBMARINE")
          )
          val step: steps.Step5 = steps.begin.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Verification fails if attestation and caller specify different token binding IDs.") {
          val steps = finishRegistration(
            callerTokenBindingId = Some("ORANGESUBMARINE"),
            testData = TestData.FidoU2f.BasicAttestation.editClientData("tokenBindingId", "YELLOWSUBMARINE")
          )
          val step: steps.Step5 = steps.begin.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }
      }

      describe("6. Verify that the") {
        it("clientExtensions in C is a subset of the extensions requested by the RP.") {
          val failSteps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.editClientData("clientExtensions", jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo")))
          )
          val failStep: failSteps.Step6 = failSteps.begin.next.get.next.get.next.get.next.get.next.get

          failStep.validations shouldBe a [Failure[_]]
          failStep.validations.failed.get shouldBe an[AssertionError]
          failStep.next shouldBe a [Failure[_]]

          val successSteps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.copy(
              requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar")))
            )
          )
          val successStep: successSteps.Step6 = successSteps.begin.next.get.next.get.next.get.next.get.next.get

          successStep.validations shouldBe a [Success[_]]
          successStep.next shouldBe a [Success[_]]
        }

        it("authenticatorExtensions in C is also a subset of the extensions requested by the RP.") {
          val failSteps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.editClientData(
              "authenticatorExtensions", jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))
            )
          )
          val failStep: failSteps.Step6 = failSteps.begin.next.get.next.get.next.get.next.get.next.get

          failStep.validations shouldBe a [Failure[_]]
          failStep.validations.failed.get shouldBe an[AssertionError]
          failStep.next shouldBe a [Failure[_]]

          val successSteps = finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.copy(
              requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar")))
            ).editClientData(
              "authenticatorExtensions", jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))
            )
          )
          val successStep: successSteps.Step6 = successSteps.begin.next.get.next.get.next.get.next.get.next.get

          successStep.validations shouldBe a [Success[_]]
          successStep.next shouldBe a [Success[_]]
        }
      }

      describe("7. Compute the hash of clientDataJSON using the algorithm identified by C.hashAlgorithm.") {
        it("SHA-256 is always used.") {
          val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
          val step: steps.Step7 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
          step.clientDataJsonHash should equal (MessageDigest.getInstance("SHA-256").digest(TestData.FidoU2f.BasicAttestation.clientDataJsonBytes.toArray).toVector)
        }
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

      describe("10. Determine the attestation statement format by performing an USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].") {
        def setup(format: String): FinishRegistrationSteps = {
          finishRegistration(
            testData = TestData.FidoU2f.BasicAttestation.editAttestationObject("fmt", format)
          )
        }

        def checkFailure(format: String): Unit = {
          it(s"""Fails if fmt is "${format}".""") {
            val steps = setup(format)
            val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }
        }

        def checkSuccess(format: String): Unit = {
          it(s"""Succeeds if fmt is "${format}".""") {
            val steps = setup(format)
            val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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

      describe("11. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 6.") {

        describe("For the fido-u2f statement format,") {
          it("the default test case is a valid basic attestation.") {
            val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
            val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (Basic)
            step.next shouldBe a [Success[_]]
          }

          it("a test case with self attestation is valid.") {
            val steps = finishRegistration(testData = TestData.FidoU2f.SelfAttestation)
            val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (SelfAttestation)
            step.next shouldBe a [Success[_]]
          }

          def flipByte(index: Int, bytes: ArrayBuffer): ArrayBuffer = bytes.updated(index, (0xff ^ bytes(index)).toByte)

          it("a test case with different signed client data is not valid.") {
            val testData = TestData.FidoU2f.SelfAttestation
            val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation)
            val step: steps.Step11 = new steps.Step11(
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
            val step: steps.Step11 = new steps.Step11(
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
            val step: steps.Step11 = new steps.Step11(
              attestation = AttestationObject(testData.attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(testData.clientDataJsonBytes.toArray).toVector,
              attestationStatementVerifier = FidoU2fAttestationStatementVerifier
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          describe("if x5c is not a certificate for an ECDSA public key over the P-256 curve, stop verification and return an error.") {
            val testAuthenticator = new TestAuthenticator()

            def checkRejected(keypair: KeyPair): Unit = {
              val credential = testAuthenticator.createCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                testData = TestData(
                  attestationObject = credential.response.attestationObject,
                  clientDataJson = new String(credential.response.clientDataJSON.toArray, "UTF-8")
                ),
                credentialId = Some(credential.rawId)
              )
              val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
              val credential = testAuthenticator.createCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                testData = TestData(
                  attestationObject = credential.response.attestationObject,
                  clientDataJson = new String(credential.response.clientDataJSON.toArray, "UTF-8")
                ),
                credentialId = Some(credential.rawId)
              )
              val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
            val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
            step.attestationStatementVerifier.get should be theSameInstanceAs PackedAttestationStatementVerifier
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
              val clientDataHash = MessageDigest.getInstance(WebAuthnCodecs.json.readTree(testData.clientDataJson).get("hashAlgorithm").textValue()).digest(testData.clientDataJson.getBytes("UTF-8"))

              authenticatorData should not be null
              clientDataHash should not be null
            }

            describe("3. If x5c is present, this indicates that the attestation type is not ECDAA. In this case:") {
              it("The attestation type is identified as Basic.") {
                val steps = finishRegistration(testData = TestData.Packed.BasicAttestation)
                val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
                  val authenticator = new TestAuthenticator
                  val (badCert, key): (X509Certificate, PrivateKey) = authenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=AA, OU=Authenticator Attestation")
                  )
                  val credential = authenticator.createCredential(
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
                val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
                val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
                val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
                  val badCert: X509Certificate = new TestAuthenticator().generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=AA, OU=Authenticator Attestation")
                  )._1
                  val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]

                  verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (Success(true))
                }

                it("Subject-O: Legal name of the Authenticator vendor") {
                  val badCert: X509Certificate = new TestAuthenticator().generateAttestationCertificate(
                    name = new X500Name("C=SE, OU=Authenticator Attestation")
                  )._1
                  val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]

                  verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(Success(true))
                }

                it("Subject-OU: Authenticator Attestation") {
                  val badCert: X509Certificate = new TestAuthenticator().generateAttestationCertificate(
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

                val badCert: X509Certificate = new TestAuthenticator().generateAttestationCertificate(
                  name = new X500Name("O=Yubico, C=SE, OU=Authenticator Attestation"),
                  extensions = List((idFidoGenCeAaguid, false, Vector(0, 1, 2, 3)))
                )._1
                val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]

                val goodCert: X509Certificate = new TestAuthenticator().generateAttestationCertificate(
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
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("The android-key statement format is supported.") {
          val steps = finishRegistration(testData = TestData.AndroidKey.BasicAttestation)
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("The android-safetynet statement format is supported.") {
          val steps = finishRegistration(testData = TestData.AndroidSafetynet.BasicAttestation)
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("12. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.") {

        describe("For the fido-u2f statement format") {

          it("with self attestation, no trust anchors are returned.") {
            val steps = finishRegistration(testData = TestData.FidoU2f.SelfAttestation)
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.trustResolver.get should not be null
            step.next shouldBe a [Success[_]]
          }

        }

      }

      describe("13. Assess the attestation trustworthiness using the outputs of the verification procedure in step 10, as follows:") {

        describe("If self attestation was used, check if self attestation is acceptable under Relying Party policy.") {

          describe("The default test case, with self attestation,") {
            it("is rejected if untrusted attestation is not allowed.") {
              val steps = finishRegistration(
                testData = TestData.FidoU2f.SelfAttestation,
                allowUntrustedAttestation = false
              )
              val step: steps.Step13 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
              val step: steps.Step13 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (true)
              step.next shouldBe a [Success[_]]
            }
          }
        }

        it("If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 11.") {
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
              val step: steps.Step13 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
              val step: steps.Step13 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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
              val step: steps.Step13 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

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

      describe("14. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.") {
        it("Nothing to test.") {}
      }

      describe("15. If the attestation statement attStmt successfully verified but is not trustworthy per step 12 above, the Relying Party SHOULD fail the registration ceremony.") {
        it("Nothing to test.") {}
      }

      describe("15. NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §6.3.3 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.") {
        it("Nothing to test.") {}
      }

      it("15. (Deleted) If verification of the attestation statement failed, the Relying Party MUST fail the registration ceremony.") {
        val steps = finishRegistration(testData = TestData.FidoU2f.BasicAttestation.editClientData("foo", "bar"))
        val step10: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get
        val step11: steps.Step11 = step10.next.get

        step10.validations shouldBe a [Success[_]]
        step10.next shouldBe a [Success[_]]

        step11.validations shouldBe a [Failure[_]]
        step11.validations.failed.get shouldBe an [AssertionError]
        step11.next shouldBe a [Failure[_]]

        steps.run shouldBe a [Failure[_]]
        steps.run.failed.get shouldBe an [AssertionError]
      }

      it("To avoid ambiguity during authentication, the Relying Party SHOULD check that each credential is registered to no more than one user. If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.") {
        fail("Not implemented.")
      }

    }

  }

}
