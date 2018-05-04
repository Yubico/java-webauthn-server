package com.yubico.webauthn.data

import java.util.Optional

import com.yubico.scala.util.JavaConverters._


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
  authenticatorAttachment: Optional[AuthenticatorAttachment] = None.asJava,

  /**
    * requireResidentKey
    * Describes the Relying Party's requirements regarding availability of the
    * Client-side-resident Credential Private Key. If the parameter is set to
    * true, the authenticator MUST create a Client-side-resident Credential
    * Private Key when creating a public key credential.
    */
  requireResidentKey: Boolean = false,

  /**
    * requireUserVerification
    *
    * This member describes the Relying Party's requirements regarding user
    * verification for the create() operation. Eligible authenticators are
    * filtered to only those capable of satisfying this requirement.
    */
  userVerification: UserVerificationRequirement = Preferred

)
