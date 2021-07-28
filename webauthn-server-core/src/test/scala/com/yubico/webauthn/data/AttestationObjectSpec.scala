package com.yubico.webauthn.data

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.yubico.internal.util.JacksonCodecs
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner

import scala.jdk.CollectionConverters.MapHasAsJava

@RunWith(classOf[JUnitRunner])
class AttestationObjectSpec extends FunSpec with Matchers {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  def toCbor(obj: Map[String, Any]): ByteArray = toCbor(obj.asJava)
  def toCbor(obj: Any): ByteArray =
    new ByteArray(JacksonCodecs.cbor().writeValueAsBytes(obj))

  describe("AttestationObject") {
    val GoodAuthData = Array.fill[Byte](37)(0)
    val GoodFmt = "packed"
    val GoodAttStmt = Map.empty

    describe("throws IllegalArgumentException if") {
      it("input is empty.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          new AttestationObject(ByteArray.fromHex(""))
        }
      }

      it("input is null.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          new AttestationObject(toCbor(null))
        }
        an[IllegalArgumentException] shouldBe thrownBy {
          new AttestationObject(toCbor(jsonFactory.nullNode()))
        }
      }

      it("authData is missing.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          new AttestationObject(
            toCbor(Map("fmt" -> GoodFmt, "attStmt" -> GoodAttStmt))
          )
        }
      }

      it("authData is not binary.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          new AttestationObject(
            toCbor(
              Map(
                "authData" -> "foo",
                "fmt" -> GoodFmt,
                "attStmt" -> GoodAttStmt,
              )
            )
          )
        }
      }

      it("fmt is missing.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          new AttestationObject(
            toCbor(Map("authData" -> GoodAuthData, "attStmt" -> GoodAttStmt))
          )
        }
      }

      it("fmt is not a string value.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          new AttestationObject(
            toCbor(
              Map(
                "authData" -> GoodAuthData,
                "fmt" -> 3,
                "attStmt" -> GoodAttStmt,
              )
            )
          )
        }
      }

      it("attStmt is missing.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          new AttestationObject(
            toCbor(Map("authData" -> GoodAuthData, "fmt" -> GoodFmt))
          )
        }
      }

      it("attStmt is not an object value.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          new AttestationObject(
            toCbor(
              Map(
                "authData" -> GoodAuthData,
                "fmt" -> GoodFmt,
                "attStmt" -> "foo",
              )
            )
          )
        }
      }
    }

    it("""accepts the "correct" placeholder values from above.""") {
      new AttestationObject(
        toCbor(
          Map(
            "authData" -> GoodAuthData,
            "fmt" -> GoodFmt,
            "attStmt" -> GoodAttStmt,
          )
        )
      )
    }
  }
}
