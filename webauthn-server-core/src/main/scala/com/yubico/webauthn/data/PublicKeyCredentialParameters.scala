package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty


/**
  * Used to supply additional parameters when creating a new credential.
  *
  * @param alg specifies the cryptographic signature algorithm with which the
  *            newly generated credential will be used, and thus also the type
  *            of asymmetric key pair to be generated, e.g., RSA or Elliptic
  *            Curve.
  * @param `type` specifies the type of credential to be created.
  * @note we use "alg" as the latter member name, rather than spelling-out
  *       "algorithm", because it will be serialized into a message to the
  *       authenticator, which may be sent over a low-bandwidth link.
  */
case class PublicKeyCredentialParameters(
  alg: COSEAlgorithmIdentifier,
  @JsonIgnore
  `type`: PublicKeyCredentialType = PublicKey
) {

  @JsonProperty("type")
  def typeJson: String = `type`.id
}
