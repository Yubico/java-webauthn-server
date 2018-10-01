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
