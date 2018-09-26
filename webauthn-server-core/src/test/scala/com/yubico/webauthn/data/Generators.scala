package com.yubico.webauthn.data

import java.net.URL
import java.security.interfaces.ECPublicKey
import java.util.Optional

import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBOREncodeOptions
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.scalacheck.gen.JacksonGenerators._
import com.yubico.scalacheck.gen.JavaGenerators._
import com.yubico.webauthn.WebAuthnCodecs
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.attestation.Attestation
import com.yubico.webauthn.attestation.Generators._
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import org.scalacheck.Arbitrary.arbitrary

import scala.collection.JavaConverters._


object Generators {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  private def setFlag(flags: Byte, mask: Byte, value: Boolean): Byte =
    if (value)
      (flags | (mask & (-0x01).toByte)).toByte
    else
      (flags & (mask ^ (-0x01).toByte)).toByte

  implicit val arbitraryAssertionRequest: Arbitrary[AssertionRequest] = Arbitrary(for {
    publicKeyCredentialRequestOptions <- arbitrary[PublicKeyCredentialRequestOptions]
    username <- arbitrary[Optional[String]]
  } yield AssertionRequest.builder()
    .publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions)
    .username(username)
    .build())

  implicit val arbitraryAssertionResult: Arbitrary[AssertionResult] = Arbitrary(for {
    credentialId <- arbitrary[ByteArray]
    signatureCount <- arbitrary[Long]
    signatureCounterValid <- arbitrary[Boolean]
    success <- arbitrary[Boolean]
    userHandle <- arbitrary[ByteArray]
    username <- arbitrary[String]
    warnings <- arbitrary[java.util.List[String]]
  } yield AssertionResult.builder()
    .credentialId(credentialId)
    .signatureCount(signatureCount)
    .signatureCounterValid(signatureCounterValid)
    .success(success)
    .userHandle(userHandle)
    .username(username)
    .warnings(warnings)
    .build())

  implicit val arbitraryAttestationData: Arbitrary[AttestationData] = Arbitrary(for {
    aaguid <- byteArray(16)
    credentialId <- arbitrary[ByteArray]
    credentialPublicKey <- Gen.delay(Gen.const(TestAuthenticator.generateEcKeypair().getPublic.asInstanceOf[ECPublicKey]))
    credentialPublicKeyCose = WebAuthnCodecs.ecPublicKeyToCose(credentialPublicKey)
  } yield AttestationData.builder()
    .aaguid(aaguid)
    .credentialId(credentialId)
    .credentialPublicKey(credentialPublicKeyCose)
    .build())
  def attestationDataBytes: Gen[ByteArray] = for {
    attestationData <- arbitrary[AttestationData]
  } yield new ByteArray(
    attestationData.getAaguid.getBytes
    ++ BinaryUtil.encodeUint16(attestationData.getCredentialId.getBytes.length)
    ++ attestationData.getCredentialId.getBytes
    ++ attestationData.getCredentialPublicKey.getBytes
  )

  implicit val arbitraryAttestationObject: Arbitrary[AttestationObject] = Arbitrary(for {
    bytes <- attestationObjectBytes
  } yield new AttestationObject(bytes))
  def attestationObjectBytes: Gen[ByteArray] = Gen.oneOf(packedAttestationObject, fidoU2fAttestationObject)

  def packedAttestationObject: Gen[ByteArray] = for {
    authData <- authenticatorDataBytes
    alg <- arbitrary[COSEAlgorithmIdentifier]
    sig <- arbitrary[ByteArray]
    x5c <- arbitrary[List[ByteArray]]
    attStmt = jsonFactory.objectNode().setAll(Map(
      "alg" -> jsonFactory.numberNode(alg.getId),
      "sig" -> jsonFactory.binaryNode(sig.getBytes),
      "x5c" -> jsonFactory.arrayNode().addAll(x5c.map(cert => jsonFactory.binaryNode(cert.getBytes)).asJava)
    ).asJava)
    attObj = jsonFactory.objectNode().setAll(Map(
      "authData" -> jsonFactory.binaryNode(authData.getBytes),
      "fmt" -> jsonFactory.textNode("packed"),
      "attStmt" -> attStmt
    ).asJava)
  } yield new ByteArray(WebAuthnCodecs.cbor().writeValueAsBytes(attObj))

  def fidoU2fAttestationObject: Gen[ByteArray] = for {
    authData <- authenticatorDataBytes
    alg <- arbitrary[COSEAlgorithmIdentifier]
    sig <- arbitrary[ByteArray]
    x5c <- arbitrary[List[ByteArray]]
    attStmt = jsonFactory.objectNode().setAll(Map(
      "sig" -> jsonFactory.binaryNode(sig.getBytes),
      "x5c" -> jsonFactory.arrayNode().addAll(x5c.map(cert => jsonFactory.binaryNode(cert.getBytes)).asJava)
    ).asJava)
    attObj = jsonFactory.objectNode().setAll(Map(
      "authData" -> jsonFactory.binaryNode(authData.getBytes),
      "fmt" -> jsonFactory.textNode("fido-u2f"),
      "attStmt" -> attStmt
    ).asJava)
  } yield new ByteArray(WebAuthnCodecs.cbor().writeValueAsBytes(attObj))

  implicit val arbitraryAuthenticationDataFlags: Arbitrary[AuthenticationDataFlags] = Arbitrary(for {
    value <- arbitrary[Byte]
  } yield new AuthenticationDataFlags(value))

  implicit val arbitraryAuthenticatorAssertionResponse: Arbitrary[AuthenticatorAssertionResponse] = Arbitrary(for {
    authenticatorData <- authenticatorDataBytes
    clientDataJson <- clientDataJsonBytes
    signature <- arbitrary[ByteArray]
    userHandle <- arbitrary[Option[ByteArray]]
  } yield new AuthenticatorAssertionResponse(
    authenticatorData,
    clientDataJson,
    signature,
    userHandle.orNull
  ))

  implicit val arbitraryAuthenticatorAttestationResponse: Arbitrary[AuthenticatorAttestationResponse] = Arbitrary(for {
    attestationObject <- attestationObjectBytes
    clientDataJSON <- clientDataJsonBytes
  } yield new AuthenticatorAttestationResponse(attestationObject, clientDataJSON))

  implicit val arbitraryAuthenticatorData: Arbitrary[AuthenticatorData] = Arbitrary(authenticatorDataBytes map (new AuthenticatorData(_)))
  def authenticatorDataBytes: Gen[ByteArray] = for {
    fixedBytes <- byteArray(37)
    attestationDataBytes <- Gen.option(attestationDataBytes)
    extensions <- arbitrary[Option[CBORObject]]

    extensionsBytes = extensions map { exts => new ByteArray(exts.EncodeToBytes(CBOREncodeOptions.NoDuplicateKeys.And(CBOREncodeOptions.NoIndefLengthStrings))) }
    atFlag = attestationDataBytes.isDefined
    edFlag = extensionsBytes.isDefined
    flagsByte: Byte = setFlag(setFlag(fixedBytes.getBytes()(32), 0x40, atFlag), BinaryUtil.singleFromHex("80"), edFlag)
  } yield new ByteArray(
    fixedBytes.getBytes.updated(32, flagsByte)
      ++ attestationDataBytes.map(_.getBytes).getOrElse(Array.empty)
      ++ extensionsBytes.map(_.getBytes).getOrElse(Array.empty)
  )

  implicit val arbitraryAuthenticatorSelectionCriteria: Arbitrary[AuthenticatorSelectionCriteria] = Arbitrary(for {
    authenticatorAttachment <- arbitrary[Optional[AuthenticatorAttachment]]
    requireResidentKey <- arbitrary[Boolean]
    userVerification <- arbitrary[UserVerificationRequirement]
  } yield AuthenticatorSelectionCriteria.builder()
    .authenticatorAttachment(authenticatorAttachment)
    .requireResidentKey(requireResidentKey)
    .userVerification(userVerification)
    .build())

  implicit val arbitraryByteArray: Arbitrary[ByteArray] = Arbitrary(arbitrary[Array[Byte]].map(new ByteArray(_)))
  def byteArray(size: Int): Gen[ByteArray] = Gen.listOfN(size, arbitrary[Byte]).map(ba => new ByteArray(ba.toArray))

  implicit val arbitraryCollectedClientData: Arbitrary[CollectedClientData] = Arbitrary(clientDataJsonBytes map (new CollectedClientData(_)))
  def clientDataJsonBytes: Gen[ByteArray] = for {
    jsonBase <- arbitrary[ObjectNode]
    challenge <- arbitrary[ByteArray]
    origin <- arbitrary[URL]
    tpe <- Gen.alphaNumStr
    tokenBinding <- arbitrary[Optional[TokenBindingInfo]]
    authenticatorExtensions <- arbitrary[Optional[ObjectNode]]
    clientExtensions <- arbitrary[Optional[ObjectNode]]
    json = {
      val json = jsonBase
        .set("challenge", jsonFactory.textNode(challenge.getBase64Url)).asInstanceOf[ObjectNode]
        .set("origin", jsonFactory.textNode(origin.toExternalForm)).asInstanceOf[ObjectNode]
        .set("type", jsonFactory.textNode(tpe)).asInstanceOf[ObjectNode]

      tokenBinding.asScala foreach { tb =>
        json.set("tokenBinding", WebAuthnCodecs.json().readTree(WebAuthnCodecs.json().writeValueAsString(tb)))
      }

      authenticatorExtensions.asScala foreach { ae =>
        json.set("authenticatorExtensions", WebAuthnCodecs.json().readTree(WebAuthnCodecs.json().writeValueAsString(ae)))
      }

      clientExtensions.asScala foreach { ce =>
        json.set("clientExtensions", WebAuthnCodecs.json().readTree(WebAuthnCodecs.json().writeValueAsString(ce)))
      }

      json
    }
  } yield new ByteArray(WebAuthnCodecs.json().writeValueAsBytes(json))

  implicit val arbitraryCOSEAlgorithmIdentifier: Arbitrary[COSEAlgorithmIdentifier] = Arbitrary(Gen.oneOf(COSEAlgorithmIdentifier.values()))

  implicit val arbitraryPublicKeyCredentialWithAssertion: Arbitrary[PublicKeyCredential[AuthenticatorAssertionResponse]] = Arbitrary(for {
    id <- arbitrary[ByteArray]
    response <- arbitrary[AuthenticatorAssertionResponse]
    clientExtensionResults <- arbitrary[ObjectNode]
  } yield new PublicKeyCredential(id, response, clientExtensionResults))

  implicit val arbitraryPublicKeyCredentialWithAttestation: Arbitrary[PublicKeyCredential[AuthenticatorAttestationResponse]] = Arbitrary(for {
    id <- arbitrary[ByteArray]
    response <- arbitrary[AuthenticatorAttestationResponse]
    clientExtensionResults <- arbitrary[ObjectNode]
  } yield new PublicKeyCredential(id, response, clientExtensionResults))

  implicit val arbitraryPublicKeyCredentialCreationOptions: Arbitrary[PublicKeyCredentialCreationOptions] = Arbitrary(for {
    attestation <- arbitrary[AttestationConveyancePreference]
    authenticatorSelection <- arbitrary[Optional[AuthenticatorSelectionCriteria]]
    challenge <- arbitrary[ByteArray]
    excludeCredentials <- arbitrary[Optional[java.util.Set[PublicKeyCredentialDescriptor]]]
    extensions <- arbitrary[Optional[ObjectNode]]
    pubKeyCredParams <- arbitrary[java.util.List[PublicKeyCredentialParameters]]
    rp <- arbitrary[RelyingPartyIdentity]
    timeout <- arbitrary[Optional[java.lang.Long]]
    user <- arbitrary[UserIdentity]
  } yield PublicKeyCredentialCreationOptions.builder()
    .attestation(attestation)
    .authenticatorSelection(authenticatorSelection)
    .challenge(challenge)
    .excludeCredentials(excludeCredentials)
    .extensions(extensions)
    .pubKeyCredParams(pubKeyCredParams)
    .rp(rp)
    .timeout(timeout)
    .user(user)
    .build())

  implicit val arbitraryPublicKeyCredentialDescriptor: Arbitrary[PublicKeyCredentialDescriptor] = Arbitrary(for {
    id <- arbitrary[ByteArray]
    transports <- arbitrary[Optional[java.util.Set[AuthenticatorTransport]]]
    tpe <- arbitrary[PublicKeyCredentialType]
  } yield PublicKeyCredentialDescriptor.builder()
    .id(id)
    .transports(transports)
    .`type`(tpe)
    .build())

  implicit val arbitraryPublicKeyCredentialParameters: Arbitrary[PublicKeyCredentialParameters] = Arbitrary(for {
    alg <- arbitrary[COSEAlgorithmIdentifier]
    tpe <- arbitrary[PublicKeyCredentialType]
  } yield PublicKeyCredentialParameters.builder()
    .alg(alg)
    .`type`(tpe)
    .build())

  implicit val arbitraryPublicKeyCredentialRequestOptions: Arbitrary[PublicKeyCredentialRequestOptions] = Arbitrary(for {
    allowCredentials <- arbitrary[Optional[java.util.List[PublicKeyCredentialDescriptor]]]
    challenge <- arbitrary[ByteArray]
    extensions <- arbitrary[Optional[ObjectNode]]
    rpId <- arbitrary[Optional[String]]
    timeout <- arbitrary[Optional[java.lang.Long]]
    userVerification <- arbitrary[UserVerificationRequirement]
  } yield PublicKeyCredentialRequestOptions.builder()
    .allowCredentials(allowCredentials)
    .challenge(challenge)
    .extensions(extensions)
    .rpId(rpId)
    .timeout(timeout)
    .userVerification(userVerification)
    .build())

  implicit val arbitraryRegistrationResult: Arbitrary[RegistrationResult] = Arbitrary(for {
    attestationMetadata <- arbitrary[Optional[Attestation]]
    attestationTrusted <- arbitrary[Boolean]
    attestationType <- arbitrary[AttestationType]
    keyId <- arbitrary[PublicKeyCredentialDescriptor]
    publicKeyCose <- arbitrary[ByteArray]
    warnings <- arbitrary[java.util.List[String]]
  } yield RegistrationResult.builder()
    .attestationMetadata(attestationMetadata)
    .attestationTrusted(attestationTrusted)
    .attestationType(attestationType)
    .keyId(keyId)
    .publicKeyCose(publicKeyCose)
    .warnings(warnings)
    .build())

  implicit val arbitraryRelyingPartyIdentity: Arbitrary[RelyingPartyIdentity] = Arbitrary(for {
    icon <- arbitrary[Optional[URL]]
    id <- arbitrary[String]
    name <- arbitrary[String]
  } yield RelyingPartyIdentity.builder()
    .icon(icon)
    .id(id)
    .name(name)
    .build())

  implicit val arbitraryTokenBindingInfo: Arbitrary[TokenBindingInfo] = Arbitrary(Gen.oneOf(
    Gen.const(TokenBindingInfo.notSupported()),
    Gen.const(TokenBindingInfo.supported()),
    arbitrary[ByteArray] map TokenBindingInfo.present
  ))

  implicit val arbitraryUserIdentity: Arbitrary[UserIdentity] = Arbitrary(for {
    displayName <- arbitrary[String]
    name <- arbitrary[String]
    icon <- arbitrary[Optional[URL]]
    id <- arbitrary[ByteArray]
    name <- arbitrary[String]
  } yield UserIdentity.builder()
    .displayName(displayName)
    .icon(icon)
    .id(id)
    .name(name)
    .build())

}
