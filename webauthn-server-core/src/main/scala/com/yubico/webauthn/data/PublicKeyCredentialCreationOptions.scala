package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnore
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.json.JsonSerializable
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


case class PublicKeyCredentialCreationOptions(

  /**
    * Contains data about the Relying Party responsible for the request.
    */
  rp: RelyingPartyIdentity,

  /**
    * Contains data about the user account for which the Relying Party is
    * requesting attestation.
    */
  user: UserIdentity,

  /**
    * A challenge intended to be used for generating the newly created
    * credential’s attestation object.
    */
  @JsonIgnore
  challenge: ArrayBuffer,

  /**
    * Information about the desired properties of the credential to be created.
    *
    * The sequence is ordered from most preferred to least preferred. The
    * client will make a best-effort to create the most preferred credential
    * that it can.
    */
  pubKeyCredParams: java.util.List[PublicKeyCredentialParameters],

  /**
    * Specifies a time, in milliseconds, that the caller is willing to wait for
    * the call to complete. This is treated as a hint, and MAY be overridden by
    * the platform.
    */
  timeout: Optional[Long] = None.asJava,

  /**
    * Intended for use by Relying Parties that wish to limit the creation of
    * multiple credentials for the same account on a single authenticator. The
    * client is requested to return an error if the new credential would be
    * created on an authenticator that also contains one of the credentials
    * enumerated in this parameter.
    */
  excludeCredentials: Optional[java.util.Collection[PublicKeyCredentialDescriptor]] = None.asJava,

  /**
    * Intended for use by Relying Parties that wish to select the appropriate
    * authenticators to participate in the create() operation.
    */
  authenticatorSelection: Optional[AuthenticatorSelectionCriteria] = None.asJava,

  /**
    * Intended for use by Relying Parties that wish to express their preference
    * for attestation conveyance. The default is none.
    */
  attestation: AttestationConveyancePreference = AttestationConveyancePreference.default,

  /**
    * Additional parameters requesting additional processing by the client and
    * authenticator.
    *
    * For example, the caller may request that only authenticators with certain
    * capabilies be used to create the credential, or that particular
    * information be returned in the attestation object. Some extensions are
    * defined in §8 WebAuthn Extensions; consult the IANA "WebAuthn Extension
    * Identifier" registry  for an up-to-date list of registered WebAuthn
    * Extensions.
    */
  extensions: Optional[AuthenticationExtensionsClientInputs] = None.asJava
) extends JsonSerializable {

  @JsonProperty("challenge")
  def challengeBase64: String = U2fB64Encoding.encode(challenge.toArray)

}
