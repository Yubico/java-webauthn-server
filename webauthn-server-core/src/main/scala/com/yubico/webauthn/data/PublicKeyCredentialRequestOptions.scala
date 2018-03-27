package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


/**
  * The PublicKeyCredentialRequestOptions dictionary supplies get() with the data it needs to generate an assertion.
  *
  * Its `challenge` member must be present, while its other members are optional.
  */
case class PublicKeyCredentialRequestOptions(

  /**
    * A challenge that the selected authenticator signs, along with other data, when producing an authentication assertion.
    */
  @JsonIgnore
  challenge: ArrayBuffer,

  /**
    * Specifies the relying party identifier claimed by the caller.
    *
    * If omitted, its value will be set by the client.
    */
  rpId: Optional[String] = scala.None.asJava,

  /**
    * A list of public key credentials acceptable to the caller, in descending order of the caller’s preference.
    */
  allowCredentials: Optional[java.util.List[PublicKeyCredentialDescriptor]] = scala.None.asJava,

  /**
    * This member describes the Relying Party's requirements regarding user verification for the get() operation. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    */
  userVerification: UserVerificationRequirement = Preferred,

  /**
    * Additional parameters requesting additional processing by the client and authenticator.
    *
    * For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
    */
  extensions: Optional[AuthenticationExtensions] = scala.None.asJava

) {

  @JsonProperty("challenge")
  def challengeBase64: String = U2fB64Encoding.encode(challenge.toArray)

}
