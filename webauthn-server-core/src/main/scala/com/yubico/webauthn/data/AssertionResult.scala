package com.yubico.webauthn.data

import scala.collection.JavaConverters._


case class AssertionResult(
  credentialId: ArrayBuffer,
  signatureCount: Long,
  signatureCounterValid: Boolean,
  success: Boolean,
  userHandle: Base64UrlString,
  warnings: List[String]
) {
  def warningsAsJava: java.util.List[String] = warnings.asJava
}

