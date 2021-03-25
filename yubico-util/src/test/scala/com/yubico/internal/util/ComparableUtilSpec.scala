package com.yubico.internal.util

import _root_.scala.jdk.CollectionConverters._
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

@RunWith(classOf[JUnitRunner])
class ComparableUtilSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  def sameSizeSets[T](implicit gent: Gen[T]): Gen[(Set[T], Set[T])] =
    for {
      n: Int <- Gen.chooseNum(0, 100)
      a: Set[T] <- Gen.containerOfN[Set, T](n, gent)
      b: Set[T] <- Gen.containerOfN[Set, T](n, gent)
    } yield (a, b)

  def toJava(s: Set[Int]): java.util.SortedSet[Integer] =
    new java.util.TreeSet[Integer](
      s.map(_.asInstanceOf[java.lang.Integer]).asJava
    )

  describe("compareComparableSets") {
    it("sorts differently-sized sets in order of cardinality.") {
      forAll { (a: Set[Int], b: Set[Int]) =>
        whenever(a.size != b.size) {
          val comp = ComparableUtil.compareComparableSets(toJava(a), toJava(b))
          if (a.size < b.size) {
            comp should be < 0
          } else {
            comp should be > 0
          }
        }
      }
    }

    it("sorts same-sized sets like sorted lists.") {
      forAll(sameSizeSets(arbitrary[Int])) {
        case (a, b) =>
          whenever(a.size == b.size) {
            val comp =
              ComparableUtil.compareComparableSets(toJava(a), toJava(b))

            val aList = a.toList.sorted
            val bList = b.toList.sorted
            val firstDiff = aList.zip(bList).find({ case (a, b) => a != b })
            firstDiff match {
              case Some((a, b)) => comp should equal(a.compareTo(b))
              case None         => comp should equal(0)
            }
          }
      }
    }
  }

}
