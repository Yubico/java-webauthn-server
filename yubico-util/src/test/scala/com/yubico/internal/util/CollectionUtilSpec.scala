package com.yubico.internal.util

import com.yubico.scalacheck.gen.JavaGenerators._
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner
import org.scalatest.prop.GeneratorDrivenPropertyChecks

@RunWith(classOf[JUnitRunner])
class CollectionUtilSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  describe("immutableList") {

    it("returns a List instance which throws exceptions on modification attempts.") {
      forAll { l: java.util.List[Int] =>
        val immutable = CollectionUtil.immutableList(l)
        an [UnsupportedOperationException] should be thrownBy { immutable.add(0) }
      }

      forAll(minSize(1)) { l: java.util.List[Int] =>
        val immutable = CollectionUtil.immutableList(l)
        an [UnsupportedOperationException] should be thrownBy { immutable.remove(0) }
      }
    }

    it("prevents mutations to the argument from propagating to the return value.") {
      forAll { l: java.util.List[Int] =>
        val immutable = CollectionUtil.immutableList(l)
        immutable should equal (l)

        l.add(0)
        immutable should not equal l
        immutable.size should equal (l.size - 1)
      }
    }

  }

}
