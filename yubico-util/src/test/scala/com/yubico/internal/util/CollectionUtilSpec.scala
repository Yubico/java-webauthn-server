package com.yubico.internal.util

import com.yubico.scalacheck.gen.JavaGenerators._
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

@RunWith(classOf[JUnitRunner])
class CollectionUtilSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  describe("immutableMap") {
    it(
      "returns a Map instance which throws exceptions on modification attempts."
    ) {
      forAll { m: java.util.Map[Int, Int] =>
        val immutable = CollectionUtil.immutableMap(m)
        an[UnsupportedOperationException] should be thrownBy {
          immutable.put(0, 0)
        }
      }

      forAll(minSize(1)) { m: java.util.Map[Int, Int] =>
        val immutable = CollectionUtil.immutableMap(m)
        an[UnsupportedOperationException] should be thrownBy {
          immutable.remove(0)
        }
      }
    }

    it(
      "prevents mutations to the argument from propagating to the return value."
    ) {
      forAll { m: java.util.Map[Int, Int] =>
        val immutable = CollectionUtil.immutableMap(m)
        immutable should equal(m)

        m.put(0.to(10000).find(i => !m.containsKey(i)).get, 0)
        immutable should not equal m
        immutable.size should equal(m.size - 1)
      }
    }
  }

  describe("immutableList") {
    it("returns a List instance which throws exceptions on modification attempts.") {
      forAll { l: java.util.List[Int] =>
        val immutable = CollectionUtil.immutableList(l)
        an[UnsupportedOperationException] should be thrownBy {
          immutable.add(0)
        }
      }

      forAll(minSize(1)) { l: java.util.List[Int] =>
        val immutable = CollectionUtil.immutableList(l)
        an[UnsupportedOperationException] should be thrownBy {
          immutable.remove(0)
        }
      }
    }

    it(
      "prevents mutations to the argument from propagating to the return value."
    ) {
      forAll { l: java.util.List[Int] =>
        val immutable = CollectionUtil.immutableList(l)
        immutable should equal(l)

        l.add(0)
        immutable should not equal l
        immutable.size should equal(l.size - 1)
      }
    }
  }

  describe("immutableSet") {
    it(
      "returns a Set instance which throws exceptions on modification attempts."
    ) {
      forAll { s: java.util.Set[Int] =>
        val immutable = CollectionUtil.immutableSet(s)
        an[UnsupportedOperationException] should be thrownBy {
          immutable.add(0)
        }
      }

      forAll(minSize(1)) { s: java.util.Set[Int] =>
        val immutable = CollectionUtil.immutableSet(s)
        an[UnsupportedOperationException] should be thrownBy {
          immutable.remove(0)
        }
      }
    }

    it(
      "prevents mutations to the argument from propagating to the return value."
    ) {
      forAll { s: java.util.Set[Int] =>
        val immutable = CollectionUtil.immutableSet(s)
        immutable should equal(s)

        s.add(0.to(10000).find(i => !s.contains(i)).get)
        immutable should not equal s
        immutable.size should equal(s.size - 1)
      }
    }
  }

  describe("immutableSortedSet") {
    it("returns a SortedSet instance which throws exceptions on modification attempts.") {
      forAll { s: java.util.SortedSet[Int] =>
        val immutable = CollectionUtil.immutableSortedSet(s)
        an[UnsupportedOperationException] should be thrownBy {
          immutable.add(0)
        }
      }

      forAll(minSize(1)) { s: java.util.SortedSet[Int] =>
        val immutable = CollectionUtil.immutableSortedSet(s)
        an[UnsupportedOperationException] should be thrownBy {
          immutable.remove(0)
        }
      }
    }

    it(
      "prevents mutations to the argument from propagating to the return value."
    ) {
      forAll { s: java.util.SortedSet[Int] =>
        val immutable = CollectionUtil.immutableSortedSet(s)
        immutable should equal(s)

        s.add(0.to(10000).find(i => !s.contains(i)).get)
        immutable should not equal s
        immutable.size should equal(s.size - 1)
      }
    }
  }
}
