// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.internal.util.scala

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
