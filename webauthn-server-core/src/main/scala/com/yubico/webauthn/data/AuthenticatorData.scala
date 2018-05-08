package com.yubico.webauthn.data

import java.io.ByteArrayInputStream
import java.util.Optional

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.upokecenter.cbor.CBORObject
import com.upokecenter.cbor.CBORException
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.util.BinaryUtil

import scala.util.Success
import scala.util.Try
import scala.util.Failure


case class AuthenticatorData(
  @JsonIgnore
  authData: ArrayBuffer
) {
  private val RpIdHashLength = 32
  private val FlagsLength = 1
  private val CounterLength = 4
  private val FixedLengthPartEndIndex = RpIdHashLength + FlagsLength + CounterLength

  @JsonProperty("authData")
  def authDataBase64: String = U2fB64Encoding.encode(authData.toArray)

  /**
    * The SHA-256 hash of the RP ID associated with the credential.
    */
  @JsonIgnore
  val rpIdHash: ArrayBuffer = authData.take(RpIdHashLength)
  @JsonProperty("rpIdHash") def rpIdHashBase64: String = U2fB64Encoding.encode(rpIdHash.toArray)

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
  val attestationData: Optional[AttestationData] = optionalParts._1.asJava

  /**
    * Extension-defined authenticator data, if present.
    *
    * See ''§8 WebAuthn Extensions'' of [[com.yubico.webauthn.VersionInfo]] for details.
    */
  val extensions: Optional[ArrayBuffer] = optionalParts._2.asJava

  private lazy val optionalParts: (Option[AttestationData], Option[ArrayBuffer]) =
    if (flags.AT)
      parseAttestationData(flags, authData drop FixedLengthPartEndIndex)
    else if (flags.ED)
      (None, Some(validateExtensions(authData.drop(FixedLengthPartEndIndex))))
    else
      (None, None)

  private def parseAttestationData(flags: AuthenticationDataFlags, bytes: ArrayBuffer): (Some[AttestationData], Option[ArrayBuffer]) = {

    val credentialIdLengthBytes = bytes.slice(16, 16 + 2)
    val L: Int = BinaryUtil.getUint16(credentialIdLengthBytes) getOrElse {
      throw new IllegalArgumentException(s"Invalid credential ID length bytes: ${credentialIdLengthBytes}")
    }

    var indefiniteLengthBytes = new ByteArrayInputStream(bytes.drop(16 + 2 + L).toArray)

    val credentialPublicKey: CBORObject = CBORObject.Read(indefiniteLengthBytes)
    val extensions: Option[CBORObject] = (flags.ED, indefiniteLengthBytes.available > 0) match {
      case (true, true) => Some(CBORObject.Read(indefiniteLengthBytes))
      case (false, true) => throw new IllegalArgumentException(s"Flags indicate no extension data, but ${indefiniteLengthBytes.available} bytes remain after attestation data.")
      case (true, false) => throw new IllegalArgumentException(s"Flags indicate there should be extension data, but no bytes remain after attestation data.")
      case (false, false) => None
    }

    (
      Some(AttestationData(
        aaguid = bytes.slice(0, 16),
        credentialId = bytes.slice(16 + 2, 16 + 2 + L),
        credentialPublicKey = credentialPublicKey.EncodeToBytes().toVector
      )),
      extensions map { _.EncodeToBytes.toVector }
    )
  }

  private def validateExtensions(bytes: ArrayBuffer): ArrayBuffer =
    Try {
      CBORObject.DecodeFromBytes(bytes.toArray)
    } match {
      case Success(_) => bytes
      case Failure(e: CBORException) => throw new IllegalArgumentException(e)
      case Failure(e) => throw e
    }

}
