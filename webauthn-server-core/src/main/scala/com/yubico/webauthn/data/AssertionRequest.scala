package com.yubico.webauthn.data

import java.util.Optional


case class AssertionRequest(
  requestId: String,
  username: Optional[String],
  publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions
)
