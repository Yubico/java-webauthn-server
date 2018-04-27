package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonSubTypes.Type
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


@JsonTypeInfo(use = Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@jackson_type")
@JsonSubTypes(Array(
  new Type(classOf[impl.PublicKeyCredential[_]])
))
trait PublicKeyCredential[+A <: AuthenticatorResponse] extends Credential {

  /**
    * This attribute is inherited from `Credential`, though PublicKeyCredential
    * overrides `Credential`'s getter, instead returning the base64url encoding
    * of the [[rawId]].
    */
  override val id: String = U2fB64Encoding.encode(rawId.toArray)

  /**
    * An identifier for the credential, chosen by the client.
    *
    * This identifier is used to look up credentials for use, and is therefore
    * expected to be globally unique with high probability across all
    * credentials of the same type, across all authenticators. This API does
    * not constrain the format or length of this identifier, except that it
    * must be sufficient for the platform to uniquely select a key. For
    * example, an authenticator without on-board storage may create identifiers
    * containing a credential private key wrapped with a symmetric key that is
    * burned into the authenticator.
    */
  val rawId: ArrayBuffer

  /**
    * The authenticator's response to the client’s request to either create a
    * public key credential, or generate an authentication assertion.
    *
    * If the PublicKeyCredential is created in response to create(), this
    * attribute’s value will be an [[AuthenticatorAttestationResponse]],
    * otherwise, the PublicKeyCredential was created in response to get(), and
    * this attribute’s value will be an [[AuthenticatorAssertionResponse]].
    */
  val response: A

  /**
    * A map containing extension identifier → client extension output entries
    * produced by the extension’s client extension processing.
    */
  val clientExtensionResults: AuthenticationExtensionsClientInputs

  /**
    * The PublicKeyCredential's type value is the string "public-key".
    */
  override val `type` = "public-key"

}
