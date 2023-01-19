package com.yubico.scalacheck.gen

import org.scalacheck.Gen

object GenUtil {

  /** @return
    *   The generator `g` wrapped so that its size is at most `maxSize`.
    */
  def maxSized[T](maxSize: Int, g: Gen[T]): Gen[T] =
    Gen.sized(size => Gen.resize(Math.min(maxSize, size), g))

  /** @return
    *   The generator `g` wrapped to reduce its size by half, but no lower than
    *   to 1 if the original size was 1 or greater.
    */
  def halfsized[T](g: Gen[T]): Gen[T] =
    Gen.sized(size => {
      val s = if (size / 2 == 0 && size != 0) 1 else size / 2
      Gen.resize(s, g)
    })

}
