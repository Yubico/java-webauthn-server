package com.yubico.webauthn.data

import java.util.Optional


case class AssertionResult(
  credentialId: ArrayBuffer,
  signatureCount: Long,
  signatureCounterValid: Boolean,
  success: Boolean,
  userHandle: Optional[Base64UrlString]
)

