package com.yubico.webauthn.util

import java.nio.ByteBuffer
import java.nio.ByteOrder

import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.u2f.exceptions.U2fBadInputException
import com.yubico.webauthn.data.HexString
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.Base64UrlString

import scala.util.Try

object BinaryUtil {

  /**
    * @param bytes Bytes to encode
    * @return The `bytes` encoded as lowercase hexadecimal digits
    */
  def toHex(bytes: Seq[Byte]): String = bytes map ("%02x" format _) mkString ""

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

  def fromBase64(base64: Base64UrlString): Vector[Byte] = Try(
    U2fB64Encoding.decode(base64).toVector
  ) getOrElse { throw new U2fBadInputException("Bad base64 encoding") }

  def toBase64(bytes: ArrayBuffer): Base64UrlString = U2fB64Encoding.encode(bytes.toArray)

  /**
    * Read one byte as an unsigned 8-bit integer.
    *
    * Result is of type Short because Scala/Java don't have unsigned types.
    *
    * @return A value between 0 and 255, inclusive.
    */
  def getUint8(byte: Byte): Short =
  // Prepend a zero so we can parse it as a signed int16 instead of a signed int8
    ByteBuffer.wrap(Array[Byte](0, byte)).getShort

  /**
    * Read one byte as an unsigned 8-bit integer.
    *
    * Result is of type Long because Scala/Java don't have unsigned types.
    *
    * @return A value between 0 and 255, inclusive.
    */
  def getUint8(bytes: ArrayBuffer): Try[Short] = Try(
    if (bytes.length == 1)
      getUint8(bytes(0))
    else
      throw new IllegalArgumentException(s"Argument must be 1 byte, was: ${bytes.length}")
  )

  /**
    * Read 2 bytes as a big endian unsigned 16-bit integer.
    *
    * Result is of type Int because Scala/Java don't have unsigned types.
    *
    * @return A value between 0 and 2^16- 1, inclusive.
    */
  def getUint16(bytes: ArrayBuffer): Try[Int] = Try(
    if (bytes.length == 2)
    // Prepend zeroes so we can parse it as a signed int32 instead of a signed int16
      ByteBuffer.wrap((Vector[Byte](0, 0) ++ bytes).toArray).order(ByteOrder.BIG_ENDIAN).getInt
    else
      throw new IllegalArgumentException(s"Argument must be 2 bytes, was: ${bytes.length}")
  )

  /**
    * Read 4 bytes as a big endian unsigned 32-bit integer.
    *
    * Result is of type Long because Scala/Java don't have unsigned types.
    * @return A value between 0 and 2^32 - 1, inclusive.
    */
  def getUint32(bytes: ArrayBuffer): Try[Long] = Try(
    if (bytes.length == 4)
    // Prepend zeroes so we can parse it as a signed int64 instead of a signed int32
      ByteBuffer.wrap((Vector[Byte](0, 0, 0, 0) ++ bytes).toArray).order(ByteOrder.BIG_ENDIAN).getLong
    else
      throw new IllegalArgumentException(s"Argument must be 4 bytes, was: ${bytes.length}")
  )

}
