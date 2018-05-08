package com.yubico.webauthn.data

case class AssertionResult(
  credentialId: ArrayBuffer,
  signatureCount: Long,
  signatureCounterValid: Boolean,
  success: Boolean
)
