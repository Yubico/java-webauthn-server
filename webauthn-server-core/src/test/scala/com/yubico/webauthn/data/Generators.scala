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

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.upokecenter.cbor.CBOREncodeOptions
import com.upokecenter.cbor.CBORObject
import com.yubico.fido.metadata.Generators.keyProtectionType
import com.yubico.fido.metadata.Generators.matcherProtectionType
import com.yubico.fido.metadata.Generators.userVerificationMethod
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.JacksonCodecs
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.scalacheck.gen.JacksonGenerators
import com.yubico.scalacheck.gen.JacksonGenerators._
import com.yubico.scalacheck.gen.JavaGenerators._
import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.WebAuthnTestCodecs
import com.yubico.webauthn.data.Extensions.CredentialProperties.CredentialPropertiesOutput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationInput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationOutput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationInput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationOutput
import com.yubico.webauthn.data.Extensions.Uvm.UvmEntry
import com.yubico.webauthn.extension.appid.AppId
import com.yubico.webauthn.extension.appid.Generators._
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen

import java.net.URL
import java.security.interfaces.ECPublicKey
import java.util.Optional
import scala.jdk.CollectionConverters._

object Generators {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  private def setFlag(flags: Byte, mask: Byte, value: Boolean): Byte =
    if (value)
      (flags | (mask & (-0x01).toByte)).toByte
    else
      (flags & (mask ^ (-0x01).toByte)).toByte

  implicit val arbitraryAssertionExtensionInputs
      : Arbitrary[AssertionExtensionInputs] = Arbitrary(
    for {
      appid <- arbitrary[Optional[AppId]]
    } yield AssertionExtensionInputs
      .builder()
      .appid(appid)
      .build()
  )

  implicit val arbitraryAssertionRequest: Arbitrary[AssertionRequest] =
    Arbitrary(
      for {
        publicKeyCredentialRequestOptions <-
          arbitrary[PublicKeyCredentialRequestOptions]
        username <- arbitrary[Optional[String]]
      } yield AssertionRequest
        .builder()
        .publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions)
        .username(username)
        .build()
    )

  implicit val arbitraryAttestedCredentialData
      : Arbitrary[AttestedCredentialData] = Arbitrary(
    for {
      aaguid <- byteArray(16)
      credentialId <- arbitrary[ByteArray]
      credentialPublicKey <- Gen.delay(
        Gen.const(
          TestAuthenticator
            .generateEcKeypair()
            .getPublic
            .asInstanceOf[ECPublicKey]
        )
      )
      credentialPublicKeyCose =
        WebAuthnTestCodecs.ecPublicKeyToCose(credentialPublicKey)
    } yield AttestedCredentialData
      .builder()
      .aaguid(aaguid)
      .credentialId(credentialId)
      .credentialPublicKey(credentialPublicKeyCose)
      .build()
  )
  def attestedCredentialDataBytes: Gen[ByteArray] =
    for {
      attestedCredentialData <- arbitrary[AttestedCredentialData]
    } yield new ByteArray(
      attestedCredentialData.getAaguid.getBytes
        ++ BinaryUtil.encodeUint16(
          attestedCredentialData.getCredentialId.getBytes.length
        )
        ++ attestedCredentialData.getCredentialId.getBytes
        ++ attestedCredentialData.getCredentialPublicKey.getBytes
    )

  implicit val arbitraryAttestationObject: Arbitrary[AttestationObject] =
    Arbitrary(for {
      bytes <- attestationObjectBytes()
    } yield new AttestationObject(bytes))
  def attestationObjectBytes(
      extensionOutputsGen: Gen[Option[CBORObject]] =
        Gen.option(Extensions.authenticatorAssertionExtensionOutputs())
  ): Gen[ByteArray] =
    Gen.oneOf(
      packedAttestationObject(extensionOutputsGen),
      fidoU2fAttestationObject(extensionOutputsGen),
    )

  def packedAttestationObject(
      extensionOutputsGen: Gen[Option[CBORObject]] =
        Gen.option(Extensions.authenticatorAssertionExtensionOutputs())
  ): Gen[ByteArray] =
    for {
      authData <- authenticatorDataBytes(extensionOutputsGen)
      alg <- arbitrary[COSEAlgorithmIdentifier]
      sig <- arbitrary[ByteArray]
      x5c <- arbitrary[List[ByteArray]]
      attStmt =
        jsonFactory
          .objectNode()
          .setAll[ObjectNode](
            Map(
              "alg" -> jsonFactory.numberNode(alg.getId),
              "sig" -> jsonFactory.binaryNode(sig.getBytes),
              "x5c" -> jsonFactory
                .arrayNode()
                .addAll(
                  x5c.map(cert => jsonFactory.binaryNode(cert.getBytes)).asJava
                ),
            ).asJava
          )
      attObj =
        jsonFactory
          .objectNode()
          .setAll[ObjectNode](
            Map(
              "authData" -> jsonFactory.binaryNode(authData.getBytes),
              "fmt" -> jsonFactory.textNode("packed"),
              "attStmt" -> attStmt,
            ).asJava
          )
    } yield new ByteArray(JacksonCodecs.cbor().writeValueAsBytes(attObj))

  def fidoU2fAttestationObject(
      extensionOutputsGen: Gen[Option[CBORObject]] =
        Gen.option(Extensions.authenticatorAssertionExtensionOutputs())
  ): Gen[ByteArray] =
    for {
      authData <- authenticatorDataBytes(extensionOutputsGen)
      sig <- arbitrary[ByteArray]
      x5c <- arbitrary[List[ByteArray]]
      attStmt =
        jsonFactory
          .objectNode()
          .setAll[ObjectNode](
            Map(
              "sig" -> jsonFactory.binaryNode(sig.getBytes),
              "x5c" -> jsonFactory
                .arrayNode()
                .addAll(
                  x5c.map(cert => jsonFactory.binaryNode(cert.getBytes)).asJava
                ),
            ).asJava
          )
      attObj =
        jsonFactory
          .objectNode()
          .setAll[ObjectNode](
            Map(
              "authData" -> jsonFactory.binaryNode(authData.getBytes),
              "fmt" -> jsonFactory.textNode("fido-u2f"),
              "attStmt" -> attStmt,
            ).asJava
          )
    } yield new ByteArray(JacksonCodecs.cbor().writeValueAsBytes(attObj))

  implicit val arbitraryAuthenticatorDataFlags
      : Arbitrary[AuthenticatorDataFlags] = Arbitrary(for {
    value <- arbitrary[Byte]
  } yield new AuthenticatorDataFlags(value))

  implicit val arbitraryAuthenticatorAssertionResponse
      : Arbitrary[AuthenticatorAssertionResponse] = Arbitrary(
    authenticatorAssertionResponse()
  )
  def authenticatorAssertionResponse(
      extensionOutputsGen: Gen[Option[CBORObject]] =
        Gen.option(Extensions.authenticatorAssertionExtensionOutputs())
  ): Gen[AuthenticatorAssertionResponse] =
    for {
      authenticatorData <- authenticatorDataBytes(extensionOutputsGen)
      clientDataJson <- clientDataJsonBytes
      signature <- arbitrary[ByteArray]
      userHandle <- arbitrary[Option[ByteArray]]
    } yield AuthenticatorAssertionResponse
      .builder()
      .authenticatorData(authenticatorData)
      .clientDataJSON(clientDataJson)
      .signature(signature)
      .userHandle(userHandle.asJava)
      .build()

  implicit val arbitraryAuthenticatorAttestationResponse
      : Arbitrary[AuthenticatorAttestationResponse] = Arbitrary(
    for {
      attestationObject <- attestationObjectBytes()
      clientDataJSON <- clientDataJsonBytes
    } yield AuthenticatorAttestationResponse
      .builder()
      .attestationObject(attestationObject)
      .clientDataJSON(clientDataJSON)
      .build()
  )

  implicit val arbitraryAuthenticatorData: Arbitrary[AuthenticatorData] =
    Arbitrary(
      authenticatorDataBytes(extensionsGen =
        Gen.option(
          Gen.oneOf(
            Extensions.authenticatorRegistrationExtensionOutputs(),
            Extensions.authenticatorAssertionExtensionOutputs(),
          )
        )
      ) map (new AuthenticatorData(_))
    )

  def authenticatorDataBytes(
      extensionsGen: Gen[Option[CBORObject]]
  ): Gen[ByteArray] =
    for {
      fixedBytes <- byteArray(37)
      attestedCredentialDataBytes <- Gen.option(attestedCredentialDataBytes)
      extensions <- extensionsGen

      extensionsBytes = extensions map { exts =>
        new ByteArray(
          exts.EncodeToBytes(CBOREncodeOptions.DefaultCtap2Canonical)
        )
      }
      atFlag = attestedCredentialDataBytes.isDefined
      edFlag = extensionsBytes.isDefined
      flagsByte: Byte = setFlag(
        setFlag(fixedBytes.getBytes()(32), 0x40, atFlag),
        BinaryUtil.singleFromHex("80"),
        edFlag,
      )
    } yield new ByteArray(
      fixedBytes.getBytes.updated(32, flagsByte)
        ++ attestedCredentialDataBytes.map(_.getBytes).getOrElse(Array.empty)
        ++ extensionsBytes.map(_.getBytes).getOrElse(Array.empty)
    )

  implicit val arbitraryAuthenticatorSelectionCriteria
      : Arbitrary[AuthenticatorSelectionCriteria] = Arbitrary(
    for {
      authenticatorAttachment <- arbitrary[Optional[AuthenticatorAttachment]]
      residentKey <- arbitrary[ResidentKeyRequirement]
      userVerification <- arbitrary[UserVerificationRequirement]
    } yield AuthenticatorSelectionCriteria
      .builder()
      .authenticatorAttachment(authenticatorAttachment)
      .residentKey(residentKey)
      .userVerification(userVerification)
      .build()
  )

  implicit val arbitraryAuthenticatorTransport
      : Arbitrary[AuthenticatorTransport] = Arbitrary(
    Gen.oneOf(
      Gen.oneOf(AuthenticatorTransport.values().toIndexedSeq),
      arbitrary[String] map AuthenticatorTransport.of,
    )
  )

  implicit val arbitraryByteArray: Arbitrary[ByteArray] = Arbitrary(
    arbitrary[Array[Byte]].map(new ByteArray(_))
  )
  def byteArray(maxSize: Int): Gen[ByteArray] =
    Gen.listOfN(maxSize, arbitrary[Byte]).map(ba => new ByteArray(ba.toArray))

  def byteArray(minSize: Int, maxSize: Int): Gen[ByteArray] =
    for {
      nums <- Gen.infiniteLazyList(arbitrary[Byte]).map(_.take(minSize))
      len <- Gen.chooseNum(minSize, maxSize)
    } yield new ByteArray(nums.take(len).toArray)

  def flipOneBit(bytes: ByteArray): Gen[ByteArray] =
    for {
      byteIndex: Int <- Gen.choose(0, bytes.size() - 1)
      bitIndex: Int <- Gen.choose(0, 7)
      flipMask: Byte = (1 << bitIndex).toByte
    } yield new ByteArray(
      bytes.getBytes
        .updated(byteIndex, (bytes.getBytes()(byteIndex) ^ flipMask).toByte)
    )

  object Extensions {
    private val RegistrationExtensionIds: Set[String] =
      Set("appidExclude", "credProps", "largeBlob", "uvm")
    private val AuthenticationExtensionIds: Set[String] =
      Set("appid", "largeBlob", "uvm")
    private val ExtensionIds: Set[String] =
      RegistrationExtensionIds ++ AuthenticationExtensionIds

    private val ClientRegistrationExtensionOutputIds: Set[String] =
      RegistrationExtensionIds - "uvm"
    private val AuthenticatorRegistrationExtensionOutputIds: Set[String] =
      RegistrationExtensionIds -- Set("appidExclude", "credProps", "largeBlob")

    private val ClientAuthenticationExtensionOutputIds: Set[String] =
      AuthenticationExtensionIds - "uvm"
    private val AuthenticatorAuthenticationExtensionOutputIds: Set[String] =
      AuthenticationExtensionIds -- Set("appid", "credProps", "largeBlob")

    def registrationExtensionInputs(
        appidExcludeGen: Gen[Option[AppId]] = Gen.option(arbitrary[AppId]),
        credPropsGen: Gen[Option[Boolean]] = Gen.option(arbitrary[Boolean]),
        largeBlobGen: Gen[
          Option[com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationInput]
        ] = Gen.option(LargeBlob.largeBlobRegistrationInput),
        uvmGen: Gen[Option[Boolean]] = Gen.option(Gen.const(true)),
    ): Gen[RegistrationExtensionInputs] =
      for {
        appidExclude <- appidExcludeGen
        credProps <- credPropsGen
        largeBlob <- largeBlobGen
        uvm <- uvmGen
      } yield {
        val b = RegistrationExtensionInputs.builder()
        appidExclude.foreach({ i => b.appidExclude(i) })
        credProps.foreach({ i => b.credProps(i) })
        largeBlob.foreach({ i => b.largeBlob(i) })
        if (uvm.contains(true)) { b.uvm() }
        val result = b.build()
        result
      }

    def registrationExtensionInputsJson(
        gen: Gen[RegistrationExtensionInputs] = registrationExtensionInputs(),
        genExtra: Gen[ObjectNode] = arbitrary[ObjectNode],
    ): Gen[ObjectNode] =
      for {
        base <- gen
        extra <- genExtra
      } yield {
        val result = extra
        result.setAll(JacksonCodecs.json().valueToTree[ObjectNode](base))
        result
      }

    def clientRegistrationExtensionOutputs(
        appidExcludeGen: Gen[Option[Boolean]] = Gen.option(true),
        credPropsGen: Gen[Option[
          com.yubico.webauthn.data.Extensions.CredentialProperties.CredentialPropertiesOutput
        ]] = Gen.option(CredProps.credentialPropertiesOutput),
        largeBlobGen: Gen[Option[
          com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationOutput
        ]] = Gen.option(LargeBlob.largeBlobRegistrationOutput),
    ): Gen[ClientRegistrationExtensionOutputs] =
      for {
        appidExclude <- appidExcludeGen
        credProps <- credPropsGen
        largeBlob <- largeBlobGen
      } yield {
        val b = ClientRegistrationExtensionOutputs.builder()
        appidExclude.foreach(appidExclude => b.appidExclude(appidExclude))
        credProps.foreach(b.credProps)
        largeBlob.foreach(b.largeBlob)
        b.build()
      }

    private def allClientRegistrationExtensionOutputs(
        credPropsGen: Gen[
          com.yubico.webauthn.data.Extensions.CredentialProperties.CredentialPropertiesOutput
        ] = CredProps.credentialPropertiesOutput,
        largeBlobGen: Gen[
          com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationOutput
        ] = LargeBlob.largeBlobRegistrationOutput,
    ): Gen[ClientRegistrationExtensionOutputs] =
      clientRegistrationExtensionOutputs(
        appidExcludeGen = Gen.some(true),
        credPropsGen = Gen.some(credPropsGen),
        largeBlobGen = Gen.some(largeBlobGen),
      )

    def authenticatorRegistrationExtensionOutputs(
        uvmGen: Gen[Option[CBORObject]] = Gen.option(Uvm.authenticatorOutput)
    ): Gen[CBORObject] =
      for {
        uvm: Option[CBORObject] <- uvmGen
      } yield {
        val result = CBORObject.NewMap()
        uvm.foreach(result.set("uvm", _))
        result
      }

    private def allAuthenticatorRegistrationExtensionOutputs(
        uvmGen: Gen[CBORObject] = Uvm.authenticatorOutput
    ): Gen[CBORObject] =
      authenticatorRegistrationExtensionOutputs(uvmGen = Gen.some(uvmGen))

    private def unknownAuthenticatorRegistrationExtensionOutput
        : Gen[CBORObject] =
      JacksonGenerators.cborValue(genJson = JacksonGenerators.objectNode())

    def assertionExtensionInputs(
        appidGen: Gen[Option[AppId]] = Gen.option(arbitrary[AppId]),
        largeBlobGen: Gen[
          Option[com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationInput]
        ] = Gen.option(LargeBlob.largeBlobAuthenticationInput),
        uvmGen: Gen[Option[Boolean]] = Gen.option(true),
    ): Gen[AssertionExtensionInputs] =
      for {
        appid <- appidGen
        largeBlob <- largeBlobGen
        uvm <- uvmGen
      } yield {
        val b = AssertionExtensionInputs.builder()
        appid.foreach({ i => b.appid(i) })
        largeBlob.foreach({ i => b.largeBlob(i) })
        if (uvm.contains(true)) { b.uvm() }
        b.build()
      }

    def assertionExtensionInputsJson(
        gen: Gen[AssertionExtensionInputs] = assertionExtensionInputs(),
        genExtra: Gen[ObjectNode] = arbitrary[ObjectNode],
    ): Gen[ObjectNode] =
      for {
        base <- gen
        extra <- genExtra
      } yield {
        val result = extra
        result.setAll(JacksonCodecs.json().valueToTree[ObjectNode](base))
        result
      }

    private def allClientAssertionExtensionOutputs(
        largeBlobGen: Gen[
          com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationOutput
        ] = LargeBlob.largeBlobAuthenticationOutput
    ): Gen[ClientAssertionExtensionOutputs] =
      for {
        largeBlob <- largeBlobGen
      } yield {
        val b = ClientAssertionExtensionOutputs.builder()
        b.appid(true)
        b.largeBlob(largeBlob)
        b.build()
      }

    def authenticatorAssertionExtensionOutputs(
        uvmGen: Gen[Option[CBORObject]] = Gen.option(Uvm.authenticatorOutput)
    ): Gen[CBORObject] =
      for {
        uvm: Option[CBORObject] <- uvmGen
      } yield {
        val result = CBORObject.NewMap()
        uvm.foreach(result.set("uvm", _))
        result
      }

    private def allAuthenticatorAssertionExtensionOutputs(
        uvmGen: Gen[CBORObject] = Uvm.authenticatorOutput
    ): Gen[CBORObject] =
      authenticatorAssertionExtensionOutputs(uvmGen = Gen.some(uvmGen))

    private def unknownAuthenticatorAssertionExtensionOutput: Gen[CBORObject] =
      JacksonGenerators.cborValue(genJson = JacksonGenerators.objectNode())

    def filter(
        inputs: RegistrationExtensionInputs,
        extensionIds: Set[String],
    ): RegistrationExtensionInputs = {
      val resultBuilder = RegistrationExtensionInputs.builder
      for { extensionId <- extensionIds } {
        extensionId match {
          case "appidExclude" =>
            resultBuilder.appidExclude(inputs.getAppidExclude orElse null)
          case "credProps" =>
            if (inputs.getCredProps) {
              resultBuilder.credProps()
            }
          case "largeBlob" =>
            resultBuilder.largeBlob(inputs.getLargeBlob orElse null)
          case "uvm" =>
            if (inputs.getUvm) {
              resultBuilder.uvm()
            }
        }
      }
      resultBuilder.build
    }

    def filter(
        inputs: AssertionExtensionInputs,
        extensionIds: Set[String],
    ): AssertionExtensionInputs = {
      val resultBuilder = AssertionExtensionInputs.builder
      for { extensionId <- extensionIds } {
        extensionId match {
          case "appid" => resultBuilder.appid(inputs.getAppid orElse null)
          case "largeBlob" =>
            resultBuilder.largeBlob(inputs.getLargeBlob orElse null)
          case "uvm" =>
            if (inputs.getUvm) {
              resultBuilder.uvm()
            }
        }
      }
      resultBuilder.build
    }

    def filter(
        clientOutputs: ClientRegistrationExtensionOutputs,
        extensionIds: Set[String],
    ): ClientRegistrationExtensionOutputs = {
      val resultBuilder = ClientRegistrationExtensionOutputs.builder
      for { extensionId <- extensionIds } {
        extensionId match {
          case "appidExclude" =>
            resultBuilder.appidExclude(clientOutputs.getAppidExclude.get)
          case "credProps" =>
            resultBuilder.credProps(clientOutputs.getCredProps orElse null)
          case "largeBlob" =>
            resultBuilder.largeBlob(clientOutputs.getLargeBlob orElse null)
          case "uvm" => // Skip
        }
      }
      resultBuilder.build
    }

    def filter(
        clientOutputs: ClientAssertionExtensionOutputs,
        extensionIds: Set[String],
    ): ClientAssertionExtensionOutputs = {
      val resultBuilder = ClientAssertionExtensionOutputs.builder
      for { extensionId <- extensionIds } {
        extensionId match {
          case "appid" => resultBuilder.appid(clientOutputs.getAppid)
          case "largeBlob" =>
            resultBuilder.largeBlob(clientOutputs.getLargeBlob orElse null)
          case "uvm" => // Skip
        }
      }
      resultBuilder.build
    }

    def filter(
        authenticatorOutputs: CBORObject,
        extensionIds: Set[String],
    ): CBORObject = {
      val deleteExtensions: Set[String] = authenticatorOutputs.getKeys.asScala
        .map(_.AsString)
        .toSet -- extensionIds
      for { extensionId <- deleteExtensions } {
        authenticatorOutputs.Remove(extensionId)
      }
      authenticatorOutputs
    }

    def subsetRegistrationExtensions: Gen[
      (
          RegistrationExtensionInputs,
          ClientRegistrationExtensionOutputs,
          CBORObject,
      )
    ] =
      for {
        inputs <- arbitrary[RegistrationExtensionInputs]
        clientOutputs <- allClientRegistrationExtensionOutputs()
        authenticatorOutputs <- allAuthenticatorRegistrationExtensionOutputs()

        requestedExtensionIds <-
          Gen.someOf(inputs.getExtensionIds.asScala).map(_.toSet)
        returnedExtensionIds <- Gen.oneOf(
          Gen.const(requestedExtensionIds),
          Gen.someOf(requestedExtensionIds).map(_.toSet),
        )
      } yield (
        filter(inputs, requestedExtensionIds),
        filter(clientOutputs, returnedExtensionIds),
        filter(authenticatorOutputs, returnedExtensionIds),
      )

    def unrequestedClientRegistrationExtensions: Gen[
      (
          RegistrationExtensionInputs,
          ClientRegistrationExtensionOutputs,
          CBORObject,
      )
    ] =
      for {
        inputs <- arbitrary[RegistrationExtensionInputs]
        clientOutputs <- allClientRegistrationExtensionOutputs()
        authenticatorOutputs <- allAuthenticatorRegistrationExtensionOutputs()

        unrequestedClientExtensionIds: Set[String] <-
          Gen.nonEmptyContainerOf[Set, String](
            Gen.oneOf(ClientRegistrationExtensionOutputIds)
          )
        requestedExtensionIds: Set[String] <-
          Gen
            .someOf(inputs.getExtensionIds.asScala)
            .map(_.toSet -- unrequestedClientExtensionIds)
        returnedExtensionIds: Set[String] <-
          Gen
            .someOf(requestedExtensionIds)
            .map(_.toSet ++ unrequestedClientExtensionIds)
      } yield (
        filter(inputs, requestedExtensionIds),
        filter(clientOutputs, returnedExtensionIds),
        filter(authenticatorOutputs, requestedExtensionIds),
      )

    def unrequestedAuthenticatorRegistrationExtensions: Gen[
      (
          RegistrationExtensionInputs,
          ClientRegistrationExtensionOutputs,
          CBORObject,
      )
    ] =
      for {
        inputs <- arbitrary[RegistrationExtensionInputs]
        clientOutputs <- allClientRegistrationExtensionOutputs()
        authenticatorOutputs <- allAuthenticatorRegistrationExtensionOutputs()

        unrequestedAuthenticatorExtensionIds: Set[String] <-
          Gen.nonEmptyContainerOf[Set, String](
            Gen.oneOf(AuthenticatorRegistrationExtensionOutputIds)
          )
        requestedExtensionIds: Set[String] <-
          Gen
            .someOf(inputs.getExtensionIds.asScala)
            .map(_.toSet -- unrequestedAuthenticatorExtensionIds)
        returnedExtensionIds: Set[String] <-
          Gen
            .someOf(requestedExtensionIds)
            .map(_.toSet ++ unrequestedAuthenticatorExtensionIds)
      } yield (
        filter(inputs, requestedExtensionIds),
        filter(clientOutputs, requestedExtensionIds),
        filter(authenticatorOutputs, returnedExtensionIds),
      )

    def anyRegistrationExtensions: Gen[
      (
          RegistrationExtensionInputs,
          ClientRegistrationExtensionOutputs,
          CBORObject,
      )
    ] =
      for {
        inputs <- arbitrary[RegistrationExtensionInputs]
        clientOutputs <- allClientRegistrationExtensionOutputs()
        authenticatorOutputs <- allAuthenticatorRegistrationExtensionOutputs()

        requestedExtensionIds <-
          Gen.someOf(RegistrationExtensionIds).map(_.toSet)
        returnedClientExtensionIds <-
          Gen.someOf(ClientRegistrationExtensionOutputIds).map(_.toSet)
        returnedAuthenticatorExtensionIds <-
          Gen.someOf(AuthenticatorRegistrationExtensionOutputIds).map(_.toSet)
      } yield (
        filter(inputs, requestedExtensionIds),
        filter(clientOutputs, returnedClientExtensionIds),
        filter(authenticatorOutputs, returnedAuthenticatorExtensionIds),
      )

    def subsetAssertionExtensions: Gen[
      (AssertionExtensionInputs, ClientAssertionExtensionOutputs, CBORObject)
    ] =
      for {
        inputs <- arbitrary[AssertionExtensionInputs]
        clientOutputs <- allClientAssertionExtensionOutputs()
        authenticatorOutputs <- allAuthenticatorAssertionExtensionOutputs()

        requestedExtensionIds <-
          Gen.someOf(inputs.getExtensionIds.asScala).map(_.toSet)
        returnedExtensionIds <- Gen.oneOf(
          Gen.const(requestedExtensionIds),
          Gen.someOf(requestedExtensionIds).map(_.toSet),
        )
      } yield (
        filter(inputs, requestedExtensionIds),
        filter(clientOutputs, returnedExtensionIds),
        filter(authenticatorOutputs, returnedExtensionIds),
      )

    def unrequestedClientAssertionExtensions: Gen[
      (AssertionExtensionInputs, ClientAssertionExtensionOutputs, CBORObject)
    ] =
      for {
        inputs <- arbitrary[AssertionExtensionInputs]
        clientOutputs <- allClientAssertionExtensionOutputs()
        authenticatorOutputs <- allAuthenticatorAssertionExtensionOutputs()

        unrequestedClientExtensionIds: Set[String] <-
          Gen.nonEmptyContainerOf[Set, String](
            Gen.oneOf(ClientAuthenticationExtensionOutputIds)
          )
        requestedExtensionIds: Set[String] <-
          Gen
            .someOf(inputs.getExtensionIds.asScala)
            .map(_.toSet -- unrequestedClientExtensionIds)
        returnedExtensionIds: Set[String] <-
          Gen
            .someOf(requestedExtensionIds)
            .map(_.toSet ++ unrequestedClientExtensionIds)
      } yield (
        filter(inputs, requestedExtensionIds),
        filter(clientOutputs, returnedExtensionIds),
        filter(authenticatorOutputs, requestedExtensionIds),
      )

    def unrequestedAuthenticatorAssertionExtensions: Gen[
      (AssertionExtensionInputs, ClientAssertionExtensionOutputs, CBORObject)
    ] =
      for {
        inputs <- arbitrary[AssertionExtensionInputs]
        clientOutputs <- allClientAssertionExtensionOutputs()
        authenticatorOutputs <- allAuthenticatorAssertionExtensionOutputs()

        unrequestedAuthenticatorExtensionIds: Set[String] <-
          Gen.nonEmptyContainerOf[Set, String](
            Gen.oneOf(AuthenticatorAuthenticationExtensionOutputIds)
          )
        requestedExtensionIds: Set[String] <-
          Gen
            .someOf(inputs.getExtensionIds.asScala)
            .map(_.toSet -- unrequestedAuthenticatorExtensionIds)
        returnedExtensionIds: Set[String] <-
          Gen
            .someOf(requestedExtensionIds)
            .map(_.toSet ++ unrequestedAuthenticatorExtensionIds)
      } yield (
        filter(inputs, requestedExtensionIds),
        filter(clientOutputs, requestedExtensionIds),
        filter(authenticatorOutputs, returnedExtensionIds),
      )

    def anyAssertionExtensions: Gen[
      (AssertionExtensionInputs, ClientAssertionExtensionOutputs, CBORObject)
    ] =
      for {
        inputs <- arbitrary[AssertionExtensionInputs]
        clientOutputs <- allClientAssertionExtensionOutputs()
        authenticatorOutputs <- allAuthenticatorAssertionExtensionOutputs()

        requestedExtensionIds <-
          Gen.someOf(AuthenticationExtensionIds).map(_.toSet)
        returnedClientExtensionIds <-
          Gen.someOf(ClientAuthenticationExtensionOutputIds).map(_.toSet)
        returnedAuthenticatorExtensionIds <-
          Gen.someOf(AuthenticatorAuthenticationExtensionOutputIds).map(_.toSet)
      } yield (
        filter(inputs, requestedExtensionIds),
        filter(clientOutputs, returnedClientExtensionIds),
        filter(authenticatorOutputs, returnedAuthenticatorExtensionIds),
      )

    object CredProps {
      def credentialPropertiesOutput: Gen[CredentialPropertiesOutput] =
        for {
          rk <- arbitrary[Boolean]
        } yield new CredentialPropertiesOutput(rk)
    }

    object LargeBlob {
      def largeBlobSupport: Gen[LargeBlobSupport] =
        Gen.oneOf(LargeBlobSupport.values.asScala)

      def largeBlobRegistrationInput: Gen[LargeBlobRegistrationInput] =
        for {
          support <- largeBlobSupport
        } yield new LargeBlobRegistrationInput(support)

      def largeBlobRegistrationOutput: Gen[LargeBlobRegistrationOutput] =
        for {
          supported <- arbitrary[Boolean]
        } yield new LargeBlobRegistrationOutput(supported)

      def largeBlobAuthenticationInput: Gen[LargeBlobAuthenticationInput] =
        arbitrary[ByteArray] flatMap { write =>
          Gen.oneOf(
            LargeBlobAuthenticationInput.read(),
            LargeBlobAuthenticationInput.write(write),
          )
        }

      def largeBlobAuthenticationOutput: Gen[LargeBlobAuthenticationOutput] =
        for {
          blob <- arbitrary[ByteArray]
          written <- arbitrary[Boolean]
          result <- Gen.oneOf(
            new LargeBlobAuthenticationOutput(blob, null),
            new LargeBlobAuthenticationOutput(null, written),
          )
        } yield result
    }

    object Uvm {
      def uvmEntry: Gen[UvmEntry] =
        for {
          userVerificationMethod <- userVerificationMethod
          keyProtectionType <- keyProtectionType
          matcherProtectionType <- matcherProtectionType
        } yield new UvmEntry(
          userVerificationMethod,
          keyProtectionType,
          matcherProtectionType,
        )

      def encodeUvmEntry(entry: UvmEntry): Array[Int] =
        Array(
          entry.getUserVerificationMethod.getValue,
          entry.getKeyProtectionType.getValue,
          entry.getMatcherProtectionType.getValue,
        )

      def authenticatorOutput: Gen[CBORObject] =
        for {
          entry1 <- uvmEntry
          entry23 <- Gen.listOfN(2, uvmEntry)
        } yield {
          CBORObject.FromObject(
            Array(encodeUvmEntry(entry1)) ++ (entry23.map(encodeUvmEntry))
          )
        }
    }
  }

  implicit val arbitraryClientAssertionExtensionOutputs
      : Arbitrary[ClientAssertionExtensionOutputs] = Arbitrary(
    Extensions.anyAssertionExtensions map { case (_, caeo, _) => caeo }
  )
  implicit val arbitraryClientRegistrationExtensionOutputs
      : Arbitrary[ClientRegistrationExtensionOutputs] = Arbitrary(
    Extensions.anyRegistrationExtensions map { case (_, creo, _) => creo }
  )

  implicit val arbitraryAuthenticatorAssertionExtensionOutputs
      : Arbitrary[Option[AuthenticatorAssertionExtensionOutputs]] = Arbitrary(
    Extensions.anyAssertionExtensions map {
      case (_, _, aaeo) =>
        AuthenticatorAssertionExtensionOutputs.fromCbor(aaeo).asScala
    }
  )
  implicit val arbitraryAuthenticatorRegistrationExtensionOutputs
      : Arbitrary[Option[AuthenticatorRegistrationExtensionOutputs]] =
    Arbitrary(
      Extensions.anyRegistrationExtensions map {
        case (_, _, areo) =>
          AuthenticatorRegistrationExtensionOutputs.fromCbor(areo).asScala
      }
    )

  implicit val arbitraryCollectedClientData: Arbitrary[CollectedClientData] =
    Arbitrary(clientDataJsonBytes map (new CollectedClientData(_)))
  def clientDataJsonBytes: Gen[ByteArray] =
    for {
      jsonBase <- arbitrary[ObjectNode]
      challenge <- arbitrary[ByteArray]
      origin <- arbitrary[URL]
      tpe <- Gen.alphaNumStr
      tokenBinding <- arbitrary[Optional[TokenBindingInfo]]
      authenticatorExtensions <- arbitrary[Optional[ObjectNode]]
      clientExtensions <- arbitrary[Optional[ObjectNode]]
      json = {
        val json = jsonBase
          .set("challenge", jsonFactory.textNode(challenge.getBase64Url))
          .asInstanceOf[ObjectNode]
          .set("origin", jsonFactory.textNode(origin.toExternalForm))
          .asInstanceOf[ObjectNode]
          .set("type", jsonFactory.textNode(tpe))
          .asInstanceOf[ObjectNode]

        tokenBinding.asScala foreach { tb =>
          json.set[ObjectNode](
            "tokenBinding",
            JacksonCodecs
              .json()
              .readTree(JacksonCodecs.json().writeValueAsString(tb)),
          )
        }

        authenticatorExtensions.asScala foreach { ae =>
          json.set[ObjectNode](
            "authenticatorExtensions",
            JacksonCodecs
              .json()
              .readTree(JacksonCodecs.json().writeValueAsString(ae)),
          )
        }

        clientExtensions.asScala foreach { ce =>
          json.set[ObjectNode](
            "clientExtensions",
            JacksonCodecs
              .json()
              .readTree(JacksonCodecs.json().writeValueAsString(ce)),
          )
        }

        json
      }
    } yield new ByteArray(JacksonCodecs.json().writeValueAsBytes(json))

  implicit val arbitraryCOSEAlgorithmIdentifier
      : Arbitrary[COSEAlgorithmIdentifier] = Arbitrary(
    Gen.oneOf(COSEAlgorithmIdentifier.values().toIndexedSeq)
  )

  implicit val arbitraryPublicKeyCredentialWithAssertion
      : Arbitrary[PublicKeyCredential[
        AuthenticatorAssertionResponse,
        ClientAssertionExtensionOutputs,
      ]] = Arbitrary(
    for {
      id <- arbitrary[ByteArray]
      (_, clientExtensionResults, authenticatorExtensionOutputs) <-
        Extensions.anyAssertionExtensions
      response <- arbitrary[AuthenticatorAssertionResponse]
    } yield PublicKeyCredential
      .builder()
      .id(id)
      .response(response)
      .clientExtensionResults(clientExtensionResults)
      .build()
  )

  implicit val arbitraryPublicKeyCredentialWithAttestation
      : Arbitrary[PublicKeyCredential[
        AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ]] = Arbitrary(
    for {
      id <- arbitrary[ByteArray]
      response <- arbitrary[AuthenticatorAttestationResponse]
      clientExtensionResults <- arbitrary[ClientRegistrationExtensionOutputs]
    } yield PublicKeyCredential
      .builder()
      .id(id)
      .response(response)
      .clientExtensionResults(clientExtensionResults)
      .build()
  )

  implicit val arbitraryPublicKeyCredentialCreationOptions
      : Arbitrary[PublicKeyCredentialCreationOptions] = Arbitrary(
    for {
      attestation <- arbitrary[AttestationConveyancePreference]
      authenticatorSelection <-
        arbitrary[Optional[AuthenticatorSelectionCriteria]]
      challenge <- arbitrary[ByteArray]
      excludeCredentials <-
        arbitrary[Optional[java.util.Set[PublicKeyCredentialDescriptor]]]
      extensions <- arbitrary[RegistrationExtensionInputs]
      pubKeyCredParams <-
        arbitrary[java.util.List[PublicKeyCredentialParameters]]
      rp <- arbitrary[RelyingPartyIdentity]
      timeout <- arbitrary[Optional[java.lang.Long]]
      user <- arbitrary[UserIdentity]
    } yield PublicKeyCredentialCreationOptions
      .builder()
      .rp(rp)
      .user(user)
      .challenge(challenge)
      .pubKeyCredParams(pubKeyCredParams)
      .attestation(attestation)
      .authenticatorSelection(authenticatorSelection)
      .excludeCredentials(excludeCredentials)
      .extensions(extensions)
      .timeout(timeout)
      .build()
  )

  implicit val arbitraryPublicKeyCredentialDescriptor
      : Arbitrary[PublicKeyCredentialDescriptor] = Arbitrary(
    for {
      id <- arbitrary[ByteArray]
      transports <- arbitrary[Optional[java.util.Set[AuthenticatorTransport]]]
      tpe <- arbitrary[PublicKeyCredentialType]
    } yield PublicKeyCredentialDescriptor
      .builder()
      .id(id)
      .transports(transports)
      .`type`(tpe)
      .build()
  )

  implicit val arbitraryPublicKeyCredentialParameters
      : Arbitrary[PublicKeyCredentialParameters] = Arbitrary(
    for {
      alg <- arbitrary[COSEAlgorithmIdentifier]
      tpe <- arbitrary[PublicKeyCredentialType]
    } yield PublicKeyCredentialParameters
      .builder()
      .alg(alg)
      .`type`(tpe)
      .build()
  )

  implicit val arbitraryPublicKeyCredentialRequestOptions
      : Arbitrary[PublicKeyCredentialRequestOptions] = Arbitrary(
    for {
      allowCredentials <-
        arbitrary[Optional[java.util.List[PublicKeyCredentialDescriptor]]]
      challenge <- arbitrary[ByteArray]
      extensions <- arbitrary[AssertionExtensionInputs]
      rpId <- arbitrary[Optional[String]]
      timeout <- arbitrary[Optional[java.lang.Long]]
      userVerification <- arbitrary[UserVerificationRequirement]
    } yield PublicKeyCredentialRequestOptions
      .builder()
      .challenge(challenge)
      .allowCredentials(allowCredentials)
      .extensions(extensions)
      .rpId(rpId)
      .timeout(timeout)
      .userVerification(userVerification)
      .build()
  )

  implicit val arbitraryRegistrationExtensionInputs
      : Arbitrary[RegistrationExtensionInputs] = Arbitrary(
    Extensions.registrationExtensionInputs()
  )

  implicit val arbitraryRelyingPartyIdentity: Arbitrary[RelyingPartyIdentity] =
    Arbitrary(
      for {
        icon <- arbitrary[Optional[URL]]
        id <- arbitrary[String]
        name <- arbitrary[String]
      } yield RelyingPartyIdentity
        .builder()
        .id(id)
        .name(name)
        .icon(icon)
        .build()
    )

  implicit val arbitraryTokenBindingInfo: Arbitrary[TokenBindingInfo] =
    Arbitrary(
      Gen.oneOf(
        Gen.const(TokenBindingInfo.supported()),
        arbitrary[ByteArray] map TokenBindingInfo.present,
      )
    )

  implicit val arbitraryUserIdentity: Arbitrary[UserIdentity] = Arbitrary(
    for {
      displayName <- arbitrary[String]
      name <- arbitrary[String]
      icon <- arbitrary[Optional[URL]]
      id <- arbitrary[ByteArray]
    } yield UserIdentity
      .builder()
      .name(name)
      .displayName(displayName)
      .id(id)
      .icon(icon)
      .build()
  )

}
