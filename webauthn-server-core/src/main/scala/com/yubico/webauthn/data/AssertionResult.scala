package com.yubico.webauthn.data

import com.yubico.u2f.data.messages.key.util.U2fB64Encoding

import scala.collection.JavaConverters._


case class AssertionResult(
  credentialId: ArrayBuffer,
  signatureCount: Long,
  signatureCounterValid: Boolean,
  success: Boolean,
  username: String,
  userHandle: Base64UrlString,
  warnings: List[String]
) {
  def credentialIdBase64: Base64UrlString = U2fB64Encoding.encode(credentialId.toArray)
  def warningsAsJava: java.util.List[String] = warnings.asJava
}

