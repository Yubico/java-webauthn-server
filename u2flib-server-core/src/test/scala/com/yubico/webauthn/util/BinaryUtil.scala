package com.yubico.webauthn.util

object BinaryUtil {

  def toHex(bytes: Seq[Byte]): String = bytes map (_.toInt.toHexString) mkString ""

}
