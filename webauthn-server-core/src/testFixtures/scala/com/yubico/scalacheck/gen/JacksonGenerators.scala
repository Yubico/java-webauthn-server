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
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.upokecenter.cbor.CBORObject
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import org.scalacheck.Arbitrary.arbitrary

import scala.collection.JavaConverters._


object JacksonGenerators {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  implicit val arbitraryJsonNode: Arbitrary[JsonNode] = Arbitrary(arbitrary[String] map (value => jsonFactory.textNode(value)))
  implicit val arbitraryObjectNode: Arbitrary[ObjectNode] = Arbitrary(arbitrary[Map[String, _ <: JsonNode]] map (exts => { val o = jsonFactory.objectNode(); o.setAll(exts.asJava); o }))

  def objectNode(names: Gen[String] = arbitrary[String], suggestedValues: Gen[JsonNode] = arbitrary[JsonNode]): Gen[ObjectNode] =
    Gen.sized { size =>
      for {
        numValues <- Gen.choose(0, size)
        names: List[String] <- Gen.listOfN(numValues, names)
        values: List[JsonNode] <- Gen.listOfN(numValues, Gen.oneOf(suggestedValues, arbitrary[JsonNode]))
      } yield {
        val o = jsonFactory.objectNode()
        for { (name, value) <- names.zip(values) } {
          o.set(name, value)
        }
        o
      }
    }

  implicit val arbitraryCborObject: Arbitrary[CBORObject] = Arbitrary(for {
    key <- arbitrary[String]
    value <- arbitrary[String]
  } yield {
    val o = CBORObject.NewMap()
    o.set(key, CBORObject.FromObject(value))
    o
  })

}
