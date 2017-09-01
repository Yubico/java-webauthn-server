package com.yubico.scala.util

import java.util.Optional


object JavaConverters {

  implicit def asJavaOptional[A](a: Option[A]): Optional[A] = a match {
    case Some(value) => Optional.of(value)
    case None => Optional.empty()
  }

  implicit def asScalaOption[A](a: Optional[A]): Option[A] =
    if (a.isPresent) Some(a.get())
    else None

}
