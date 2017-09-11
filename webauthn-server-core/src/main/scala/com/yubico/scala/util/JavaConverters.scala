package com.yubico.scala.util

import java.util.Optional


case class AsJavaOptional[A](a: Option[A]) {
  def asJava[B >: A]: Optional[B] = a match {
    case Some(value) => Optional.of(value)
    case None => Optional.empty()
  }
}
case class AsScalaOption[A](a: Optional[A]) {
  def asScala: Option[A] = if (a.isPresent) Some(a.get()) else None
}

object JavaConverters {

  implicit def asJavaOptionalConverter[A](a: Option[A]): AsJavaOptional[A] = AsJavaOptional(a)
  implicit def asScalaOptionConverter[A](a: Optional[A]): AsScalaOption[A] = AsScalaOption(a)

}
