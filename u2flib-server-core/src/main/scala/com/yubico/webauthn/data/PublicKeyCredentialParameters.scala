package com.yubico.webauthn.data

/**
  * Used to supply additional parameters when creating a new credential.
  *
  * @param `type` specifies the type of credential to be created.
  * @param alg specifies the cryptographic signature algorithm with which the
  *            newly generated credential will be used, and thus also the type
  *            of asymmetric key pair to be generated, e.g., RSA or Elliptic
  *            Curve.
  *
  * @note we use "alg" as the latter member name, rather than spelling-out
  *       "algorithm", because it will be serialized into a message to the
  *       authenticator, which may be sent over a low-bandwidth link.
  */
case class PublicKeyCredentialParameters(
  `type`: PublicKeyCredentialType,
  alg: COSEAlgorithmIdentifier,
)
