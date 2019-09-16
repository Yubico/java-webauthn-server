// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn.data

import java.net.URL
import java.security.interfaces.ECPublicKey
import java.util.Optional

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.upokecenter.cbor.CBOREncodeOptions
import com.upokecenter.cbor.CBORObject
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.internal.util.JacksonCodecs
import com.yubico.scalacheck.gen.JacksonGenerators
import com.yubico.scalacheck.gen.JacksonGenerators._
import com.yubico.scalacheck.gen.JavaGenerators._
import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.extension.appid.AppId
import com.yubico.webauthn.extension.appid.Generators._
import com.yubico.webauthn.WebAuthnTestCodecs
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen

import scala.collection.JavaConverters._


object Generators {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  private def setFlag(flags: Byte, mask: Byte, value: Boolean): Byte =
    if (value)
      (flags | (mask & (-0x01).toByte)).toByte
    else
      (flags & (mask ^ (-0x01).toByte)).toByte

  implicit val arbitraryAssertionExtensionInputs: Arbitrary[AssertionExtensionInputs] = Arbitrary(for {
    appid <- arbitrary[Optional[AppId]]
    recovery <- arbitrary[Optional[RecoveryExtensionInput]]
  } yield AssertionExtensionInputs.builder()
    .appid(appid)
    .recovery(recovery)
    .build())

  implicit val arbitraryAssertionRequest: Arbitrary[AssertionRequest] = Arbitrary(for {
    publicKeyCredentialRequestOptions <- arbitrary[PublicKeyCredentialRequestOptions]
    username <- arbitrary[Optional[String]]
  } yield AssertionRequest.builder()
    .publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions)
    .username(username)
    .build())

  implicit val arbitraryAttestedCredentialData: Arbitrary[AttestedCredentialData] = Arbitrary(for {
    aaguid <- byteArray(16)
    credentialId <- arbitrary[ByteArray]
    credentialPublicKey <- Gen.delay(Gen.const(TestAuthenticator.generateEcKeypair().getPublic.asInstanceOf[ECPublicKey]))
    credentialPublicKeyCose = WebAuthnTestCodecs.ecPublicKeyToCose(credentialPublicKey)
  } yield AttestedCredentialData.builder()
    .aaguid(aaguid)
    .credentialId(credentialId)
    .credentialPublicKey(credentialPublicKeyCose)
    .build())
  def attestedCredentialDataBytes: Gen[ByteArray] = for {
    attestedCredentialData <- arbitrary[AttestedCredentialData]
  } yield new ByteArray(
    attestedCredentialData.getAaguid.getBytes
    ++ BinaryUtil.encodeUint16(attestedCredentialData.getCredentialId.getBytes.length)
    ++ attestedCredentialData.getCredentialId.getBytes
    ++ attestedCredentialData.getCredentialPublicKey.getBytes
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
  } yield new ByteArray(JacksonCodecs.cbor().writeValueAsBytes(attObj))

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
  } yield new ByteArray(JacksonCodecs.cbor().writeValueAsBytes(attObj))

  implicit val arbitraryAuthenticatorDataFlags: Arbitrary[AuthenticatorDataFlags] = Arbitrary(for {
    value <- arbitrary[Byte]
  } yield new AuthenticatorDataFlags(value))

  implicit val arbitraryAuthenticatorAssertionResponse: Arbitrary[AuthenticatorAssertionResponse] = Arbitrary(for {
    authenticatorData <- authenticatorDataBytes
    clientDataJson <- clientDataJsonBytes
    signature <- arbitrary[ByteArray]
    userHandle <- arbitrary[Option[ByteArray]]
  } yield AuthenticatorAssertionResponse.builder()
    .authenticatorData(authenticatorData)
    .clientDataJSON(clientDataJson)
    .signature(signature)
    .userHandle(userHandle.asJava)
    .build()
  )

  implicit val arbitraryAuthenticatorAttestationResponse: Arbitrary[AuthenticatorAttestationResponse] = Arbitrary(for {
    attestationObject <- attestationObjectBytes
    clientDataJSON <- clientDataJsonBytes
  } yield AuthenticatorAttestationResponse.builder()
    .attestationObject(attestationObject)
    .clientDataJSON(clientDataJSON)
    .build()
  )

  implicit val arbitraryAuthenticatorData: Arbitrary[AuthenticatorData] = Arbitrary(authenticatorDataBytes map (new AuthenticatorData(_)))
  def authenticatorDataBytes: Gen[ByteArray] = for {
    fixedBytes <- byteArray(37)
    attestedCredentialDataBytes <- Gen.option(attestedCredentialDataBytes)
    extensions <- arbitrary[Option[CBORObject]]

    extensionsBytes = extensions map { exts => new ByteArray(exts.EncodeToBytes(CBOREncodeOptions.DefaultCtap2Canonical)) }
    atFlag = attestedCredentialDataBytes.isDefined
    edFlag = extensionsBytes.isDefined
    flagsByte: Byte = setFlag(setFlag(fixedBytes.getBytes()(32), 0x40, atFlag), BinaryUtil.singleFromHex("80"), edFlag)
  } yield new ByteArray(
    fixedBytes.getBytes.updated(32, flagsByte)
      ++ attestedCredentialDataBytes.map(_.getBytes).getOrElse(Array.empty)
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

  implicit val arbitraryAuthenticatorTransport: Arbitrary[AuthenticatorTransport] = Arbitrary(
    Gen.oneOf(
      Gen.oneOf(AuthenticatorTransport.values()),
      arbitrary[String] map AuthenticatorTransport.of
    ))

  implicit val arbitraryByteArray: Arbitrary[ByteArray] = Arbitrary(arbitrary[Array[Byte]].map(new ByteArray(_)))
  def byteArray(size: Int): Gen[ByteArray] = Gen.listOfN(size, arbitrary[Byte]).map(ba => new ByteArray(ba.toArray))

  implicit val arbitraryClientAssertionExtensionOutputs: Arbitrary[ClientAssertionExtensionOutputs] = Arbitrary(for {
    appid <- arbitrary[Optional[java.lang.Boolean]]
  } yield ClientAssertionExtensionOutputs.builder()
    .appid(appid)
    .build())
  def clientAssertionExtensionOutputs(
    appid: Gen[Optional[java.lang.Boolean]] = arbitrary[Optional[java.lang.Boolean]]
  ): Gen[ClientAssertionExtensionOutputs] = for {
    appid <- appid
  } yield ClientAssertionExtensionOutputs.builder()
    .appid(appid)
    .build()

  implicit val arbitraryClientRegistrationExtensionOutputs: Arbitrary[ClientRegistrationExtensionOutputs] = Arbitrary(Gen.const(ClientRegistrationExtensionOutputs.builder().build()))

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
        json.set("tokenBinding", JacksonCodecs.json().readTree(JacksonCodecs.json().writeValueAsString(tb)))
      }

      authenticatorExtensions.asScala foreach { ae =>
        json.set("authenticatorExtensions", JacksonCodecs.json().readTree(JacksonCodecs.json().writeValueAsString(ae)))
      }

      clientExtensions.asScala foreach { ce =>
        json.set("clientExtensions", JacksonCodecs.json().readTree(JacksonCodecs.json().writeValueAsString(ce)))
      }

      json
    }
  } yield new ByteArray(JacksonCodecs.json().writeValueAsBytes(json))

  implicit val arbitraryCOSEAlgorithmIdentifier: Arbitrary[COSEAlgorithmIdentifier] = Arbitrary(Gen.oneOf(COSEAlgorithmIdentifier.values()))

  implicit val arbitraryCredentialRevocation: Arbitrary[CredentialRevocation] = Arbitrary(for {
    revokedCredentialId <- arbitrary[ByteArray]
    recoveryCredentialId <- arbitrary[ByteArray]
    newCredentialId <- arbitrary[ByteArray]
  } yield CredentialRevocation.builder()
    .revokedCredentialId(revokedCredentialId)
    .recoveryCredentialId(recoveryCredentialId)
    .newCredentialId(newCredentialId)
    .build())

  implicit val arbitraryPublicKeyCredentialWithAssertion: Arbitrary[PublicKeyCredential[AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs]] = Arbitrary(for {
    id <- arbitrary[ByteArray]
    response <- arbitrary[AuthenticatorAssertionResponse]
    clientExtensionResults <- arbitrary[ClientAssertionExtensionOutputs]
  } yield PublicKeyCredential.builder().id(id).response(response).clientExtensionResults(clientExtensionResults).build())

  implicit val arbitraryPublicKeyCredentialWithAttestation: Arbitrary[PublicKeyCredential[AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs]] = Arbitrary(for {
    id <- arbitrary[ByteArray]
    response <- arbitrary[AuthenticatorAttestationResponse]
    clientExtensionResults <- arbitrary[ClientRegistrationExtensionOutputs]
  } yield PublicKeyCredential.builder().id(id).response(response).clientExtensionResults(clientExtensionResults).build())

  implicit val arbitraryPublicKeyCredentialCreationOptions: Arbitrary[PublicKeyCredentialCreationOptions] = Arbitrary(for {
    attestation <- arbitrary[AttestationConveyancePreference]
    authenticatorSelection <- arbitrary[Optional[AuthenticatorSelectionCriteria]]
    challenge <- arbitrary[ByteArray]
    excludeCredentials <- arbitrary[Optional[java.util.Set[PublicKeyCredentialDescriptor]]]
    extensions <- arbitrary[RegistrationExtensionInputs]
    pubKeyCredParams <- arbitrary[java.util.List[PublicKeyCredentialParameters]]
    rp <- arbitrary[RelyingPartyIdentity]
    timeout <- arbitrary[Optional[java.lang.Long]]
    user <- arbitrary[UserIdentity]
  } yield PublicKeyCredentialCreationOptions.builder()
    .rp(rp)
    .user(user)
    .challenge(challenge)
    .pubKeyCredParams(pubKeyCredParams)
    .attestation(attestation)
    .authenticatorSelection(authenticatorSelection)
    .excludeCredentials(excludeCredentials)
    .extensions(extensions)
    .timeout(timeout)
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
    extensions <- arbitrary[AssertionExtensionInputs]
    rpId <- arbitrary[Optional[String]]
    timeout <- arbitrary[Optional[java.lang.Long]]
    userVerification <- arbitrary[UserVerificationRequirement]
  } yield PublicKeyCredentialRequestOptions.builder()
    .challenge(challenge)
    .allowCredentials(allowCredentials)
    .extensions(extensions)
    .rpId(rpId)
    .timeout(timeout)
    .userVerification(userVerification)
    .build())

  implicit val arbitraryRecoveryCredential: Arbitrary[RecoveryCredential] = Arbitrary(for {
    aaguid <- byteArray(16)
    credentialId <- arbitrary[ByteArray]
    mainCredentialId <- arbitrary[ByteArray]
    publicKey <- Gen.delay(Gen.const(TestAuthenticator.generateEcKeypair().getPublic.asInstanceOf[ECPublicKey]))
    publicKeyCose = WebAuthnTestCodecs.ecPublicKeyToCose(publicKey)
  } yield RecoveryCredential.builder()
    .aaguid(aaguid)
    .credentialId(credentialId)
    .replacesCredentialId(mainCredentialId)
    .publicKeyCose(publicKeyCose)
    .build())

  implicit val arbitraryRecoveryCredentialsState: Arbitrary[RecoveryCredentialsState] = Arbitrary(for {
    mainCredentialId <- arbitrary[ByteArray]
    recoveryCredentials <- arbitrary[Set[RecoveryCredential]]
    state <- arbitrary[Int]
  } yield RecoveryCredentialsState.builder()
    .mainCredentialId(mainCredentialId)
    .recoveryCredentials(recoveryCredentials.asJava)
    .state(state)
    .build())

  implicit val arbitraryRecoveryExtensionInput: Arbitrary[RecoveryExtensionInput] = Arbitrary(for {
    action <- arbitrary[RecoveryExtensionAction]
    allowCredentials: Option[List[PublicKeyCredentialDescriptor]] <-
      if (action == RecoveryExtensionAction.RECOVER)
        Gen.some(arbitrary[List[PublicKeyCredentialDescriptor]])
      else
        Gen.const(None)
  } yield RecoveryExtensionInput.builder()
    .action(action)
    .allowCredentials(allowCredentials.map(_.asJava).asJava)
    .build())

  implicit val arbitraryRecoveryExtensionOutput: Arbitrary[RecoveryExtensionOutput] = Arbitrary(for {
    action <- arbitrary[RecoveryExtensionAction]
    state <- arbitrary[Int]
    creds: Option[List[AttestedCredentialData]] <-
      if (action == RecoveryExtensionAction.GENERATE)
        Gen.some(arbitrary[List[AttestedCredentialData]])
      else
        Gen.const(None)
    credId: Option[ByteArray] <-
      if (action == RecoveryExtensionAction.RECOVER)
        Gen.some(arbitrary[ByteArray])
      else
        Gen.const(None)
    sig: Option[ByteArray] <-
      if (action == RecoveryExtensionAction.RECOVER)
        Gen.some(arbitrary[ByteArray])
      else
        Gen.const(None)
  } yield RecoveryExtensionOutput.builder()
    .action(action)
    .state(state)
    .creds(creds.map(_.asJava).orNull)
    .credId(credId.orNull)
    .sig(sig.orNull)
    .build())

  implicit val arbitraryRegistrationExtensionInputs: Arbitrary[RegistrationExtensionInputs] = Arbitrary(for {
    recovery <- arbitrary[Optional[RecoveryExtensionInput]]
  } yield RegistrationExtensionInputs.builder()
    .recovery(recovery)
    .build())

  implicit val arbitraryRelyingPartyIdentity: Arbitrary[RelyingPartyIdentity] = Arbitrary(for {
    icon <- arbitrary[Optional[URL]]
    id <- arbitrary[String]
    name <- arbitrary[String]
  } yield RelyingPartyIdentity.builder()
    .id(id)
    .name(name)
    .icon(icon)
    .build())

  implicit val arbitraryTokenBindingInfo: Arbitrary[TokenBindingInfo] = Arbitrary(Gen.oneOf(
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
    .name(name)
    .displayName(displayName)
    .id(id)
    .icon(icon)
    .build())

  def knownExtensionId: Gen[String] = Gen.oneOf("appid", "txAuthSimple", "txAuthGeneric", "authnSel", "exts", "uvi", "loc", "uvm", "biometricPerfBounds")

  def anyAuthenticatorExtensions[A <: ExtensionInputs](implicit a: Arbitrary[A]): Gen[(A, ObjectNode)] =
    for {
      requested <- arbitrary[A]
      returned: ObjectNode <- JacksonGenerators.objectNode(names = Gen.oneOf(knownExtensionId, Gen.alphaNumStr))
    } yield (requested, returned)

  def subsetAuthenticatorExtensions[A <: ExtensionInputs](implicit a: Arbitrary[A]): Gen[(A, ObjectNode)] =
    for {
      requested <- arbitrary[A]
      returned: ObjectNode <- JacksonGenerators.objectNode(names = Gen.oneOf(knownExtensionId, Gen.alphaNumStr))
    } yield {
      val toRemove: Set[String] = returned.fieldNames().asScala.filter({ extId: String =>
        (requested.getExtensionIds contains extId) == false
      }).toSet

      for { extId <- toRemove } {
        returned.remove(extId)
      }

      (requested, returned)
    }

  def anyAssertionExtensions: Gen[(AssertionExtensionInputs, ClientAssertionExtensionOutputs)] =
    for {
      requested <- arbitrary[AssertionExtensionInputs]
      returned <- arbitrary[ClientAssertionExtensionOutputs]
    } yield (requested, returned)

  def anyRegistrationExtensions: Gen[(RegistrationExtensionInputs, ClientRegistrationExtensionOutputs)] =
    for {
      requested <- arbitrary[RegistrationExtensionInputs]
      returned <- arbitrary[ClientRegistrationExtensionOutputs]
    } yield (requested, returned)

  def unrequestedAssertionExtensions: Gen[(AssertionExtensionInputs, ClientAssertionExtensionOutputs)] =
    for {
      requested <- arbitrary[AssertionExtensionInputs]
      returned <- arbitrary[ClientAssertionExtensionOutputs] suchThat { returned =>
        ! returned.getExtensionIds.asScala.subsetOf(requested.getExtensionIds.asScala)
      }
    } yield {
      (requested, returned)
    }

  def subsetAssertionExtensions: Gen[(AssertionExtensionInputs, ClientAssertionExtensionOutputs)] =
    for {
      requested <- arbitrary[AssertionExtensionInputs]
      returned <- clientAssertionExtensionOutputs(
        appid = if (requested.getAppid.isPresent) arbitrary[Optional[java.lang.Boolean]] else Gen.const(Optional.empty[java.lang.Boolean])
      )
    } yield {
      (requested, returned)
    }

  def subsetRegistrationExtensions: Gen[(RegistrationExtensionInputs, ClientRegistrationExtensionOutputs)] =
    for {
      requested <- arbitrary[RegistrationExtensionInputs]
      returned <- arbitrary[ClientRegistrationExtensionOutputs]
    } yield {
      (requested, returned)
    }

}
