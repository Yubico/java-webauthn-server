package com.yubico.webauthn.util

import com.yubico.webauthn.data.HexString

import scala.util.Try

object BinaryUtil {

  /**
    * @param bytes Bytes to encode
    * @return The `bytes` encoded as lowercase hexadecimal digits
    */
  def toHex(bytes: Seq[Byte]): HexString = bytes map (_.toInt.toHexString) mkString ""

  /**
    * @param hex String of hexadecimal digits to decode as bytes.
    * @return
    *         - [[IllegalArgumentException]] if the length of `hex` is not even.
    *         - [[NumberFormatException]] if `hex` contains characters that are not hexadecimal digits.
    *         - The decoded bytes otherwise.
    */
  def fromHex(hex: HexString): Try[Vector[Byte]] = Try(
    hex.length % 2 match {
      case 0 =>
        hex
          .grouped(2)
          .map { hexDigits => Integer.parseInt(hexDigits, 16).toByte }
          .toVector

      case _ =>
        throw new IllegalArgumentException(s"Hex string must be of even length, was: ${hex.length}")
    }
  )

}
