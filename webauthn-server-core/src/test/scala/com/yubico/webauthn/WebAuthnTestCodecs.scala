package com.yubico.webauthn


/**
  * Re-exports from [[WebAuthnCodecs]] so tests can use it
  */
object WebAuthnTestCodecs {

  def ecPublicKeyToCose = WebAuthnCodecs.ecPublicKeyToCose _
  def ecPublicKeyToRaw = WebAuthnCodecs.ecPublicKeyToRaw _
  def importCosePublicKey = WebAuthnCodecs.importCosePublicKey _

}
