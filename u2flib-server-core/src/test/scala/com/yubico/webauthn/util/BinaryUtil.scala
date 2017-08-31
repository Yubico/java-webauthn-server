package com.yubico.webauthn.util

object BinaryUtil {

  /**
    * @param bytes Bytes to encode
    * @return The `bytes` encoded as lowercase hexadecimal digits
    */
  def toHex(bytes: Seq[Byte]): String = bytes map (_.toInt.toHexString) mkString ""

}
