package com.yubico.webauthn.data

import java.util.Optional


/**
  * This class may be used to specify requirements regarding authenticator
  * attributes.
  *
  * @note The member identifiers are intentionally short, rather than
  *       descriptive, because they will be serialized into a message to the
  *       authenticator, which may be sent over a low-bandwidth link.
  */
case class AuthenticatorSelectionCriteria(

  /**
    * If present, eligible authenticators are filtered to only authenticators
    * attached with the specified §4.4.4 Authenticator Attachment enumeration.
    */
  aa: Optional[AuthenticatorAttachment],

  /**
    * requireResidentKey
    * Describes the Relying Party's requirements regarding availability of the
    * Client-side-resident Credential Private Key. If the parameter is set to
    * true, the authenticator MUST create a Client-side-resident Credential
    * Private Key when creating a public key credential.
    */
  rk: Boolean = false,

  /**
    * requireUserVerification
    *
    * This member describes the Relying Party's requirements regarding the
    * authenticator being capable of performing user verification. If the
    * parameter is set to true, the authenticator MUST perform user verification
    * when performing the create() operation and future §4.1.4 Use an existing
    * credential to make an assertion - PublicKeyCredential’s
    * \[\[DiscoverFromExternalSource]](options) method operations when it is
    * requested to verify the credential.
    */
  uv: Boolean = false,

)
