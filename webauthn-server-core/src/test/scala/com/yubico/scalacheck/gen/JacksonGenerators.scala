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

package com.yubico.scalacheck.gen

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.BooleanNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.NullNode
import com.fasterxml.jackson.databind.node.NumericNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.node.TextNode
import com.upokecenter.cbor.CBORObject
import com.yubico.internal.util.JacksonCodecs
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen

import scala.jdk.CollectionConverters._

object JacksonGenerators {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  def arrayNode(g: Gen[JsonNode] = arbitrary[JsonNode]): Gen[ArrayNode] =
    Gen.listOf(g) map { values =>
      val result = jsonFactory.arrayNode()
      result.addAll(values.asJavaCollection)
      result
    }

  def booleanNode(g: Gen[Boolean] = arbitrary[Boolean]): Gen[BooleanNode] =
    g map (value => jsonFactory.booleanNode(value))

  val nullNode: Gen[NullNode] =
    Gen.const(jsonFactory.nullNode())

  def numberNode(g: Gen[Long] = arbitrary[Long]): Gen[NumericNode] =
    g map (value => jsonFactory.numberNode(value))

  def objectNode(
      names: Gen[String] = arbitrary[String],
      values: Gen[JsonNode] = arbitrary[JsonNode],
  ): Gen[ObjectNode] =
    for {
      names: List[String] <- Gen.listOf(names)
      values: LazyList[JsonNode] <- Gen.infiniteLazyList(values)
    } yield {
      val o = jsonFactory.objectNode()
      for { (name, value) <- names.zip(values) } {
        o.set[ObjectNode](name, value)
      }
      o
    }

  def textNode(g: Gen[String] = arbitrary[String]): Gen[TextNode] =
    g map (value => jsonFactory.textNode(value))

  implicit val arbitraryObjectNode: Arbitrary[ObjectNode] = Arbitrary(
    objectNode()
  )

  implicit val arbitraryJsonNode: Arbitrary[JsonNode] = Arbitrary(
    Gen.sized(size => {
      val subsize = Math.max(0, size / 2)
      Gen.oneOf(
        Gen.resize(subsize, arrayNode()),
        Gen.resize(subsize, booleanNode()),
        nullNode,
        Gen.resize(subsize, numberNode()),
        Gen.resize(subsize, objectNode()),
        Gen.resize(subsize, textNode()),
      )
    })
  )

  def cborValue(genJson: Gen[ObjectNode] = objectNode()): Gen[CBORObject] =
    for {
      jsonValue <- Gen.resize(
        4,
        genJson,
      ) // CTAP canonical CBOR allows max 4 levels of nesting
    } yield {
      val bytes = JacksonCodecs.cbor().writeValueAsBytes(jsonValue)
      CBORObject.DecodeFromBytes(bytes)
    }

}
