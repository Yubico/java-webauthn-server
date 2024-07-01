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
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.JacksonCodecs
import com.yubico.scalacheck.gen.GenUtil.halfsized
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
import com.yubico.webauthn.extension.uvm.Generators.keyProtectionType
import com.yubico.webauthn.extension.uvm.Generators.matcherProtectionType
import com.yubico.webauthn.extension.uvm.Generators.userVerificationMethod
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen

import java.net.URL
import java.security.interfaces.ECPublicKey
import java.util.Optional
import scala.jdk.CollectionConverters._
import scala.jdk.OptionConverters.RichOption
import scala.jdk.OptionConverters.RichOptional

object Generators {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  private def setFlag(mask: Byte, value: Boolean)(flags: Byte): Byte =
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
      halfsized(
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
    )

  implicit val arbitraryAttestedCredentialData
      : Arbitrary[AttestedCredentialData] = Arbitrary(
    halfsized(
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
    halfsized(for {
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
    } yield new ByteArray(JacksonCodecs.cbor().writeValueAsBytes(attObj)))

  def fidoU2fAttestationObject(
      extensionOutputsGen: Gen[Option[CBORObject]] =
        Gen.option(Extensions.authenticatorAssertionExtensionOutputs())
  ): Gen[ByteArray] =
    halfsized(for {
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
    } yield new ByteArray(JacksonCodecs.cbor().writeValueAsBytes(attObj)))

  val authenticatorDataFlagsByte: Gen[Byte] = for {
    value <- arbitrary[Byte]
    bsMask = (((value & 0x08) << 1) & 0xef).toByte // Bit 0x10 cannot be set unless 0x08 is
  } yield (value & bsMask).toByte

  implicit val arbitraryAuthenticatorDataFlags
      : Arbitrary[AuthenticatorDataFlags] = Arbitrary(
    authenticatorDataFlagsByte.map(new AuthenticatorDataFlags(_))
  )

  implicit val arbitraryAuthenticatorAssertionResponse
      : Arbitrary[AuthenticatorAssertionResponse] = Arbitrary(
    authenticatorAssertionResponse()
  )
  def authenticatorAssertionResponse(
      extensionOutputsGen: Gen[Option[CBORObject]] =
        Gen.option(Extensions.authenticatorAssertionExtensionOutputs())
  ): Gen[AuthenticatorAssertionResponse] =
    halfsized(
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
        .userHandle(userHandle.toJava)
        .build()
    )

  implicit val arbitraryAuthenticatorAttestationResponse
      : Arbitrary[AuthenticatorAttestationResponse] = Arbitrary(
    halfsized(
      for {
        attestationObject <- attestationObjectBytes()
        clientDataJSON <- clientDataJsonBytes
      } yield AuthenticatorAttestationResponse
        .builder()
        .attestationObject(attestationObject)
        .clientDataJSON(clientDataJSON)
        .build()
    )
  )

  implicit val arbitraryAuthenticatorData: Arbitrary[AuthenticatorData] =
    Arbitrary(
      halfsized(
        authenticatorDataBytes(extensionsGen =
          Gen.option(
            Gen.oneOf(
              Extensions.authenticatorRegistrationExtensionOutputs(),
              Extensions.authenticatorAssertionExtensionOutputs(),
            )
          )
        ) map (new AuthenticatorData(_))
      )
    )

  val arbitraryBackupFlags: Arbitrary[(Boolean, Boolean)] = Arbitrary(
    arbitrary[(Boolean, Boolean)].map({ case (be, bs) => (be, be && bs) })
  )

  def authenticatorDataBytes(
      extensionsGen: Gen[Option[CBORObject]],
      rpIdHashGen: Gen[ByteArray] = byteArray(32),
      upFlagGen: Gen[Boolean] = Gen.const(true),
      uvFlagGen: Gen[Boolean] = arbitrary[Boolean],
      backupFlagsGen: Gen[(Boolean, Boolean)] = arbitraryBackupFlags.arbitrary,
      signatureCountGen: Gen[ByteArray] = byteArray(4),
  ): Gen[ByteArray] =
    halfsized(
      for {
        rpIdHash <- rpIdHashGen
        signatureCount <- signatureCountGen
        attestedCredentialDataBytes <- Gen.option(attestedCredentialDataBytes)

        extensions <- extensionsGen
        extensionsBytes = extensions map { exts =>
          new ByteArray(
            exts.EncodeToBytes(CBOREncodeOptions.DefaultCtap2Canonical)
          )
        }

        flagsBase <- arbitrary[Byte]
        upFlag <- upFlagGen
        uvFlag <- uvFlagGen
        (beFlag, bsFlag) <- backupFlagsGen
        atFlag = attestedCredentialDataBytes.isDefined
        edFlag = extensionsBytes.isDefined
        flagsByte: Byte = setFlag(0x01, upFlag)(
          setFlag(0x03, uvFlag)(
            setFlag(0x40, atFlag)(
              setFlag(BinaryUtil.singleFromHex("80"), edFlag)(
                setFlag(0x08, beFlag)(setFlag(0x10, bsFlag)(flagsBase))
              )
            )
          )
        )
      } yield new ByteArray(
        rpIdHash.getBytes
          :+ flagsByte
          :++ signatureCount.getBytes
            ++ attestedCredentialDataBytes
              .map(_.getBytes)
              .getOrElse(Array.empty)
            ++ extensionsBytes.map(_.getBytes).getOrElse(Array.empty)
      )
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
      nums <- Gen.infiniteLazyList(arbitrary[Byte])
      len <- Gen.chooseNum(minSize, maxSize)
    } yield new ByteArray(nums.take(len).toArray)

  def flipBit(bitIndex: Int)(bytes: ByteArray): ByteArray = {
    val byteIndex: Int = bitIndex / 8
    val bitIndexInByte: Int = bitIndex % 8
    val flipMask: Byte = (1 << bitIndexInByte).toByte
    new ByteArray(
      bytes.getBytes
        .updated(byteIndex, (bytes.getBytes()(byteIndex) ^ flipMask).toByte)
    )
  }

  def flipOneBit(bytes: ByteArray): Gen[ByteArray] =
    for {
      bitIndex <- Gen.choose(0, 8 * bytes.size() - 1)
    } yield flipBit(bitIndex)(bytes)

  object Extensions {
    private val RegistrationExtensionIds: Set[String] =
      Set("appidExclude", "credProps", "largeBlob", "uvm")
    private val AuthenticationExtensionIds: Set[String] =
      Set("appid", "largeBlob", "uvm")

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
        largeBlob <- halfsized(largeBlobGen)
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
        extra <- halfsized(genExtra)
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
        largeBlob <- halfsized(largeBlobGen)
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
        uvmGen: Gen[Option[CBORObject]] = Gen.option(Uvm.authenticatorOutput),
        includeUnknown: Boolean = true,
    ): Gen[CBORObject] =
      for {
        base <-
          if (includeUnknown)
            halfsized(unknownAuthenticatorRegistrationExtensionOutput)
          else Gen.const(CBORObject.NewMap())
        uvm: Option[CBORObject] <- halfsized(uvmGen)
      } yield {
        val result = base
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
        largeBlob <- halfsized(largeBlobGen)
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
        extra <- halfsized(genExtra)
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
        largeBlob <- halfsized(largeBlobGen)
      } yield {
        val b = ClientAssertionExtensionOutputs.builder()
        b.appid(true)
        b.largeBlob(largeBlob)
        b.build()
      }

    def authenticatorAssertionExtensionOutputs(
        uvmGen: Gen[Option[CBORObject]] = Gen.option(Uvm.authenticatorOutput),
        includeUnknown: Boolean = true,
    ): Gen[CBORObject] =
      for {
        base <-
          if (includeUnknown)
            halfsized(unknownAuthenticatorAssertionExtensionOutput)
          else Gen.const(CBORObject.NewMap())
        uvm: Option[CBORObject] <- halfsized(uvmGen)
      } yield {
        val result = base
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
      halfsized(
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
      )

    def unrequestedClientRegistrationExtensions: Gen[
      (
          RegistrationExtensionInputs,
          ClientRegistrationExtensionOutputs,
          CBORObject,
      )
    ] =
      halfsized(
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
      )

    def unrequestedAuthenticatorRegistrationExtensions: Gen[
      (
          RegistrationExtensionInputs,
          ClientRegistrationExtensionOutputs,
          CBORObject,
      )
    ] =
      halfsized(
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
      )

    def anyRegistrationExtensions: Gen[
      (
          RegistrationExtensionInputs,
          ClientRegistrationExtensionOutputs,
          CBORObject,
      )
    ] =
      halfsized(
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
      )

    def subsetAssertionExtensions: Gen[
      (AssertionExtensionInputs, ClientAssertionExtensionOutputs, CBORObject)
    ] =
      halfsized(
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
      )

    def unrequestedClientAssertionExtensions: Gen[
      (AssertionExtensionInputs, ClientAssertionExtensionOutputs, CBORObject)
    ] =
      halfsized(
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
      )

    def unrequestedAuthenticatorAssertionExtensions: Gen[
      (AssertionExtensionInputs, ClientAssertionExtensionOutputs, CBORObject)
    ] =
      halfsized(
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
      )

    def anyAssertionExtensions: Gen[
      (AssertionExtensionInputs, ClientAssertionExtensionOutputs, CBORObject)
    ] =
      halfsized(
        for {
          inputs <- arbitrary[AssertionExtensionInputs]
          clientOutputs <- allClientAssertionExtensionOutputs()
          authenticatorOutputs <- allAuthenticatorAssertionExtensionOutputs()

          requestedExtensionIds <-
            Gen.someOf(AuthenticationExtensionIds).map(_.toSet)
          returnedClientExtensionIds <-
            Gen.someOf(ClientAuthenticationExtensionOutputIds).map(_.toSet)
          returnedAuthenticatorExtensionIds <-
            Gen
              .someOf(AuthenticatorAuthenticationExtensionOutputIds)
              .map(_.toSet)
        } yield (
          filter(inputs, requestedExtensionIds),
          filter(clientOutputs, returnedClientExtensionIds),
          filter(authenticatorOutputs, returnedAuthenticatorExtensionIds),
        )
      )

    object CredProps {
      def credentialPropertiesOutput: Gen[CredentialPropertiesOutput] =
        for {
          rk <- arbitrary[Option[Boolean]]
          authenticatorDisplayName <- arbitrary[Option[String]]
        } yield {
          val b = CredentialPropertiesOutput.builder()
          rk.foreach(b.rk(_))
          authenticatorDisplayName.foreach(b.authenticatorDisplayName)
          b.build()
        }
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
        } yield LargeBlobRegistrationOutput.supported(supported)

      def largeBlobAuthenticationInput: Gen[LargeBlobAuthenticationInput] =
        halfsized(
          Gen.oneOf(
            Gen.const(LargeBlobAuthenticationInput.read()),
            arbitrary[ByteArray].map(LargeBlobAuthenticationInput.write),
          )
        )

      def largeBlobAuthenticationOutput: Gen[LargeBlobAuthenticationOutput] =
        halfsized(for {
          blob <- arbitrary[ByteArray]
          written <- arbitrary[Boolean]
          result <- Gen.oneOf(
            LargeBlobAuthenticationOutput.read(blob),
            LargeBlobAuthenticationOutput.write(written),
          )
        } yield result)
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
        halfsized(for {
          entries <- Gen.resize(3, Gen.nonEmptyListOf(uvmEntry))
        } yield CBORObject.FromObject(entries.map(encodeUvmEntry).toArray))
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
        AuthenticatorAssertionExtensionOutputs.fromCbor(aaeo).toScala
    }
  )
  implicit val arbitraryAuthenticatorRegistrationExtensionOutputs
      : Arbitrary[Option[AuthenticatorRegistrationExtensionOutputs]] =
    Arbitrary(
      Extensions.anyRegistrationExtensions map {
        case (_, _, areo) =>
          AuthenticatorRegistrationExtensionOutputs.fromCbor(areo).toScala
      }
    )

  implicit val arbitraryCollectedClientData: Arbitrary[CollectedClientData] =
    Arbitrary(clientDataJsonBytes map (new CollectedClientData(_)))
  def clientDataJsonBytes: Gen[ByteArray] =
    halfsized(for {
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

        tokenBinding.toScala foreach { tb =>
          json.set[ObjectNode](
            "tokenBinding",
            JacksonCodecs
              .json()
              .readTree(JacksonCodecs.json().writeValueAsString(tb)),
          )
        }

        authenticatorExtensions.toScala foreach { ae =>
          json.set[ObjectNode](
            "authenticatorExtensions",
            JacksonCodecs
              .json()
              .readTree(JacksonCodecs.json().writeValueAsString(ae)),
          )
        }

        clientExtensions.toScala foreach { ce =>
          json.set[ObjectNode](
            "clientExtensions",
            JacksonCodecs
              .json()
              .readTree(JacksonCodecs.json().writeValueAsString(ce)),
          )
        }

        json
      }
    } yield new ByteArray(JacksonCodecs.json().writeValueAsBytes(json)))

  implicit val arbitraryCOSEAlgorithmIdentifier
      : Arbitrary[COSEAlgorithmIdentifier] = Arbitrary(
    Gen.oneOf(COSEAlgorithmIdentifier.values().toIndexedSeq)
  )

  implicit val arbitraryPublicKeyCredentialWithAssertion
      : Arbitrary[PublicKeyCredential[
        AuthenticatorAssertionResponse,
        ClientAssertionExtensionOutputs,
      ]] = Arbitrary(
    halfsized(
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
  )

  implicit val arbitraryPublicKeyCredentialWithAttestation
      : Arbitrary[PublicKeyCredential[
        AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ]] = Arbitrary(
    halfsized(
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
  )

  implicit val arbitraryPublicKeyCredentialCreationOptions
      : Arbitrary[PublicKeyCredentialCreationOptions] = Arbitrary(
    halfsized(
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
  )

  implicit val arbitraryPublicKeyCredentialDescriptor
      : Arbitrary[PublicKeyCredentialDescriptor] = Arbitrary(
    halfsized(
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
  )

  implicit val arbitraryPublicKeyCredentialParameters
      : Arbitrary[PublicKeyCredentialParameters] = Arbitrary(
    halfsized(
      for {
        alg <- arbitrary[COSEAlgorithmIdentifier]
        tpe <- arbitrary[PublicKeyCredentialType]
      } yield PublicKeyCredentialParameters
        .builder()
        .alg(alg)
        .`type`(tpe)
        .build()
    )
  )

  implicit val arbitraryPublicKeyCredentialRequestOptions
      : Arbitrary[PublicKeyCredentialRequestOptions] = Arbitrary(
    halfsized(
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
  )

  implicit val arbitraryRegistrationExtensionInputs
      : Arbitrary[RegistrationExtensionInputs] = Arbitrary(
    Extensions.registrationExtensionInputs()
  )

  implicit val arbitraryRelyingPartyIdentity: Arbitrary[RelyingPartyIdentity] =
    Arbitrary(
      halfsized(
        for {
          id <- arbitrary[String]
          name <- arbitrary[String]
        } yield RelyingPartyIdentity
          .builder()
          .id(id)
          .name(name)
          .build()
      )
    )

  implicit val arbitraryTokenBindingInfo: Arbitrary[TokenBindingInfo] =
    Arbitrary(
      Gen.oneOf(
        Gen.const(TokenBindingInfo.supported()),
        arbitrary[ByteArray] map TokenBindingInfo.present,
      )
    )

  implicit val arbitraryUserIdentity: Arbitrary[UserIdentity] = Arbitrary(
    halfsized(
      for {
        displayName <- arbitrary[String]
        name <- arbitrary[String]
        id <- arbitrary[ByteArray]
      } yield UserIdentity
        .builder()
        .name(name)
        .displayName(displayName)
        .id(id)
        .build()
    )
  )

}
