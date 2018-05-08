package com.yubico.webauthn.data


/**
  * 5.3.3. Attestation Types
  *
  * WebAuthn supports multiple attestation types:
  */
sealed trait AttestationType {
  def name: String
}

/**
  * Basic Attestation
  *
  * In the case of basic attestation, the authenticator’s attestation key pair
  * is specific to an authenticator model. Thus, authenticators of the same
  * model often share the same attestation key pair. See §5.3.5.1 Privacy for
  * futher information.
  */
case object Basic extends AttestationType { override val name = "Basic" }

/**
  * Self Attestation
  *
  * In the case of self attestation, also known as surrogate basic attestation,
  * the Authenticator does not have any specific attestation key. Instead it
  * uses the authentication key itself to create the attestation signature.
  * Authenticators without meaningful protection measures for an attestation
  * private key typically use this attestation type.
  */
case object SelfAttestation extends AttestationType { override val name = "Self attestation" }

/**
  * Privacy CA
  *
  *
  * In this case, the Authenticator owns an authenticator-specific
  * (endorsement) key. This key is used to securely communicate with a trusted
  * third party, the Privacy CA. The Authenticator can generate multiple
  * attestation key pairs and asks the Privacy CA to issue an attestation
  * certificate for it. Using this approach, the Authenticator can limit the
  * exposure of the endorsement key (which is a global correlation handle) to
  * Privacy CA(s). Attestation keys can be requested for each public key
  * credential individually.
  *
  * Note: This concept typically leads to multiple attestation certificates.
  * The attestation certificate requested most recently is called "active".
  */
case object PrivacyCa extends AttestationType { override val name = "Privacy CA" }

/**
  * Elliptic Curve based Direct Anonymous Attestation (ECDAA)
  *
  * In this case, the Authenticator receives direct anonymous attestation (DAA)
  * credentials from a single DAA-Issuer. These DAA credentials are used along
  * with blinding to sign the attestation data. The concept of blinding avoids
  * the DAA credentials being misused as global correlation handle. WebAuthn
  * supports DAA using elliptic curve cryptography and bilinear pairings,
  * called ECDAA in this specification. Consequently we denote the DAA-Issuer
  * as ECDAA-Issuer.
  */
case object Ecdaa extends AttestationType { override val name = "ECDAA" }

/**
  * No attestation
  *
  * The none attestation statement format is used to replace any
  * authenticator-provided attestation statement when a Relying Party indicates
  * it does not wish to receive attestation information, see §5.4.6 Attestation
  * Conveyance Preference enumeration (enum AttestationConveyancePreference).
  */
case object NoneAttestation extends AttestationType { override val name = "None" }
