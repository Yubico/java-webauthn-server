package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.yubico.webauthn.util.BinaryUtil

import scala.collection.JavaConverters


case class AuthenticatorData(
  private val authData: ArrayBuffer,
) {
  private val RpIdHashLength = 32
  private val FlagsLength = 1
  private val CounterLength = 4
  private val FixedLengthPartEndIndex = RpIdHashLength + FlagsLength + CounterLength

  /**
    * The SHA-256 hash of the RP ID associated with the credential.
    */
  val rpIdHash: ArrayBuffer = authData.take(RpIdHashLength)

  /**
    * The flags byte.
    */
  val flags: AuthenticationDataFlags = AuthenticationDataFlags(authData(32))

  /**
    * The 32-bit unsigned signature counter.
    */
  val signatureCounter: Long = {
    val bytes = authData.drop(RpIdHashLength + FlagsLength).take(CounterLength)
    BinaryUtil.getUint32(bytes) getOrElse {
      throw new IllegalArgumentException(s"Invalid signature counter bytes: ${bytes}")
    }
  }

  /**
    * Attestation data, if present.
    *
    * See ''§5.3.1 Attestation data'' of [[com.yubico.webauthn.VersionInfo]] for details.
    */
  val attestationData: Optional[AttestationData] =
    com.yubico.scala.util.JavaConverters.asJavaOptional(optionalParts._1)

  /**
    * Extension-defined authenticator data, if present.
    *
    * See ''§8 WebAuthn Extensions'' of [[com.yubico.webauthn.VersionInfo]] for details.
    */
  val extensions: Optional[JsonNode] =
    com.yubico.scala.util.JavaConverters.asJavaOptional(optionalParts._2)

  private def objectMapper: ObjectMapper = new ObjectMapper(new CBORFactory)

  private lazy val optionalParts: (Option[AttestationData], Option[JsonNode]) =
    if (flags.AT)
      parseAttestationData(authData drop FixedLengthPartEndIndex)
    else if (flags.ED)
      (None, Some(objectMapper.readTree(authData.drop(FixedLengthPartEndIndex).toArray)))
    else
      (None, None)

  private def parseAttestationData(bytes: ArrayBuffer): (Some[AttestationData], Option[JsonNode]) = {

    val credentialIdLengthBytes = bytes.slice(16, 16 + 2)
    val L: Int = BinaryUtil.getUint16(credentialIdLengthBytes) getOrElse {
      throw new IllegalArgumentException(s"Invalid credential ID length bytes: ${credentialIdLengthBytes}")
    }

    val optionalBytes: ArrayBuffer = bytes.drop(16 + 2 + L)

    val allRemainingCbor: List[JsonNode] = (
      for { item <- JavaConverters.asScalaIterator(
                      objectMapper
                        .reader
                        .forType(classOf[JsonNode])
                        .readValues[JsonNode](optionalBytes.toArray)
                    )
      } yield item
    ).toList

    val credentialPublicKey = allRemainingCbor.head
    val extensions: Option[JsonNode] =
      if (flags.ED) Some(allRemainingCbor(1))
      else None

    (
      Some(AttestationData(
        aaguid = bytes.slice(0, 16),
        credentialId = bytes.slice(16 + 2, 16 + 2 + L),
        credentialPublicKey = credentialPublicKey,
      )),
      extensions
    )
  }

}
