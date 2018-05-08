package com.yubico.scala.util

import java.util.Optional
import java.util.function.Supplier

import scala.language.implicitConversions


case class AsJavaOptional[A](a: Option[A]) {
  def asJava[B >: A]: Optional[B] = a match {
    case Some(value) => Optional.of(value)
    case None => Optional.empty()
  }
}
case class AsScalaOption[A](a: Optional[A]) {
  def asScala: Option[A] = if (a.isPresent) Some(a.get()) else None
}

case class AsJavaSupplier[A](a: () => A) {
  def asJava[B >: A]: Supplier[B] = new Supplier[B] {
    override def get(): B = a()
  }
}

object JavaConverters {

  implicit def asJavaOptionalConverter[A](a: Option[A]): AsJavaOptional[A] = AsJavaOptional(a)
  implicit def asJavaSupplierConverter[A](a: () => A): AsJavaSupplier[A] = AsJavaSupplier(a)
  implicit def asScalaOptionConverter[A](a: Optional[A]): AsScalaOption[A] = AsScalaOption(a)

}
