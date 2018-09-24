package com.yubico.webauthn.data

import java.net.URL
import java.util.Optional

import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.scalacheck.gen.JacksonGenerators._
import com.yubico.scalacheck.gen.JavaGenerators._
import com.yubico.webauthn.WebAuthnCodecs
import com.yubico.webauthn.attestation.Attestation
import com.yubico.webauthn.attestation.Generators._
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import org.scalacheck.Arbitrary.arbitrary

import scala.collection.JavaConverters._


object Generators {

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
    aaguid <- arbitrary[ByteArray]
    credentialId <- arbitrary[ByteArray]
    credentialPublicKey <- arbitrary[ByteArray]
  } yield AttestationData.builder()
    .aaguid(aaguid)
    .credentialId(credentialId)
    .credentialPublicKey(credentialPublicKey)
    .build())

  implicit val arbitraryAttestationObject: Arbitrary[AttestationObject] = Arbitrary(for {
    bytes <- arbitrary[ByteArray]
  } yield new AttestationObject(bytes))

  implicit val arbitraryAuthenticationDataFlags: Arbitrary[AuthenticationDataFlags] = Arbitrary(for {
    value <- arbitrary[Byte]
  } yield new AuthenticationDataFlags(value))

  implicit val arbitraryAuthenticatorAssertionResponse: Arbitrary[AuthenticatorAssertionResponse] = Arbitrary(for {
    authenticatorData <- arbitrary[ByteArray]
    clientDataJson <- arbitrary[ByteArray]
    signature <- arbitrary[ByteArray]
    userHandle <- arbitrary[Option[ByteArray]]
  } yield new AuthenticatorAssertionResponse(
    authenticatorData,
    clientDataJson,
    signature,
    userHandle.orNull
  ))

  implicit val arbitraryAuthenticatorAttestationResponse: Arbitrary[AuthenticatorAttestationResponse] = Arbitrary(for {
    attestationObject <- arbitrary[ByteArray]
    clientDataJSON <- arbitrary[ByteArray]
  } yield new AuthenticatorAttestationResponse(attestationObject, clientDataJSON))

  implicit val arbitraryAuthenticatorData: Arbitrary[AuthenticatorData] = Arbitrary(for {
    bytes <- arbitrary[ByteArray]
  } yield new AuthenticatorData(bytes))

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

  implicit val arbitraryCollectedClientData: Arbitrary[CollectedClientData] = Arbitrary(for {
    json <- arbitrary[ObjectNode]
  } yield new CollectedClientData(json))

  implicit val arbitraryCOSEAlgorithmIdentifier: Arbitrary[COSEAlgorithmIdentifier] = Arbitrary(Gen.oneOf(COSEAlgorithmIdentifier.values().asScala.toSeq))

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
    keyId <- arbitrary[PublicKeyCredentialDescriptor]
    publicKeyCose <- arbitrary[ByteArray]
    warnings <- arbitrary[java.util.List[String]]
  } yield RegistrationResult.builder()
    .attestationMetadata(attestationMetadata)
    .attestationTrusted(attestationTrusted)
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
