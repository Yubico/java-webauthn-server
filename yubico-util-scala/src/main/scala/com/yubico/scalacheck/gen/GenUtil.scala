package com.yubico.scalacheck.gen

import org.scalacheck.Gen

object GenUtil {

  /** @return
    *   The generator `g` wrapped so that its size is at most `maxSize`.
    */
  def maxSized[T](maxSize: Int, g: Gen[T]): Gen[T] =
    Gen.sized(size => Gen.resize(Math.min(maxSize, size), g))

}
