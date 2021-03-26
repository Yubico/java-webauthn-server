// Copyright (c) 2019, Yubico AB
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

package com.yubico.webauthn

import org.junit.runner.RunWith
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import java.net.URL
import scala.jdk.CollectionConverters._

@RunWith(classOf[JUnitRunner])
class OriginMatcherSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  private def urlWithMaybePort(
      protocol: String,
      host: String,
      port: Option[Int],
      file: String,
  ): URL =
    port
      .map(port => new URL(protocol, host, port, file))
      .getOrElse(new URL(protocol, host, file))

  private def replacePort(url: URL, port: Int): URL =
    new URL(url.getProtocol, url.getHost, port, url.getFile)

  implicit private val arbitraryUrl: Arbitrary[URL] = Arbitrary(for {
    scheme <- Gen.oneOf("http", "https")
    host <- Gen.alphaNumStr suchThat { _.nonEmpty }
    port <- Gen.option(Gen.posNum[Int])
    file = ""
  } yield urlWithMaybePort(scheme, host, port, file))

  private val urlOrArbitraryString: Gen[String] = Gen.oneOf(
    arbitrary[URL].map(_.toExternalForm),
    arbitrary[String],
  )

  private val urlWithoutPort: Gen[URL] = for {
    url <- arbitrary[URL]
  } yield new URL(url.getProtocol, url.getHost, url.getFile)

  private val urlWithPort: Gen[URL] = for {
    url <- arbitrary[URL]
    port <- Gen.posNum[Int]
  } yield replacePort(url, port)

  private val superAndSubdomain: Gen[(URL, URL)] = for {
    superdomain <- urlWithoutPort
    subdomainPrefixParts <- Gen.nonEmptyListOf(Gen.alphaNumStr suchThat {
      _.nonEmpty
    })
    subdomainPrefix = subdomainPrefixParts.reduceLeft(_ + "." + _)
    host = subdomainPrefix + "." + superdomain.getHost
    subdomain = new URL(superdomain.getProtocol, host, superdomain.getFile)
  } yield (superdomain, subdomain)

  private val superAndSubdomainWithPorts: Gen[(URL, URL)] = for {
    (superdomain, subdomain) <- superAndSubdomain
    superport <- Gen.posNum[Int]
    subport <- Gen.posNum[Int]
  } yield (replacePort(superdomain, superport), replacePort(subdomain, subport))

  private def invalidize(url: URL): String = {
    val port = if (url.getPort == -1) "" else (":" + url.getPort)
    s"htps:/${url.getHost}${port}/${url.getPath}"
  }

  describe("The origin matcher") {
    it("accepts nothing if no allowed origins are given.") {
      forAll(urlOrArbitraryString, arbitrary[Boolean], arbitrary[Boolean]) {
        (origin, allowPort, allowSubdomain) =>
          println(origin)
          OriginMatcher.isAllowed(
            origin,
            Set.empty[String].asJava,
            allowPort,
            allowSubdomain,
          ) shouldBe (false)
      }
    }

    it("always accepts string equality even for invalid URLs.") {
      forAll(urlOrArbitraryString, arbitrary[Boolean], arbitrary[Boolean]) {
        (origin, allowPort, allowSubdomain) =>
          println(origin)
          OriginMatcher.isAllowed(
            origin,
            Set(origin).asJava,
            allowPort,
            allowSubdomain,
          ) shouldBe (true)
      }
    }

    it("does not accept superdomains.") {
      forAll(superAndSubdomain) {
        case (origin: URL, allowedOrigin: URL) =>
          println(allowedOrigin, origin)
          OriginMatcher.isAllowed(
            origin.toExternalForm,
            Set(allowedOrigin.toExternalForm).asJava,
            true,
            true,
          ) shouldBe (false)
      }
    }

    describe("does not accept subdomains") {
      it("by default.") {
        forAll(superAndSubdomain, arbitrary[Boolean]) { (origins, allowPort) =>
          val (allowedOrigin: URL, origin: URL) = origins
          println(allowedOrigin, origin)

          OriginMatcher.isAllowed(
            origin.toExternalForm,
            Set(allowedOrigin.toExternalForm).asJava,
            allowPort,
            false,
          ) shouldBe (false)
        }
      }

      it("when allowed origin is an invalid URL.") {
        forAll(superAndSubdomain) {
          case (allowedOrigin: URL, origin: URL) =>
            val invalidAllowedOrigin = invalidize(allowedOrigin)
            println(allowedOrigin, origin, invalidAllowedOrigin)

            OriginMatcher.isAllowed(
              origin.toExternalForm,
              Set(invalidAllowedOrigin).asJava,
              true,
              true,
            ) shouldBe (false)
        }
      }

      it("when client data origin is an invalid URL.") {
        forAll(superAndSubdomain) {
          case (allowedOrigin: URL, origin: URL) =>
            val invalidOrigin = invalidize(origin)
            println(allowedOrigin, origin, invalidOrigin)

            OriginMatcher.isAllowed(
              invalidOrigin,
              Set(allowedOrigin.toExternalForm).asJava,
              true,
              true,
            ) shouldBe (false)
        }
      }

      it("unless configured to.") {
        forAll(superAndSubdomain, arbitrary[Boolean]) { (origins, allowPort) =>
          val (allowedOrigin: URL, origin: URL) = origins
          println(allowedOrigin, origin)

          OriginMatcher.isAllowed(
            origin.toExternalForm,
            Set(allowedOrigin.toExternalForm).asJava,
            allowPort,
            true,
          ) shouldBe (true)
        }
      }
    }

    describe("does not accept ports") {
      it("by default.") {
        forAll(urlWithoutPort, Gen.posNum[Int], arbitrary[Boolean]) {
          (allowedOrigin, port, allowSubdomain) =>
            whenever(port > 0) {
              val origin = replacePort(allowedOrigin, port)
              println(allowedOrigin, origin)

              OriginMatcher.isAllowed(
                origin.toExternalForm,
                Set(allowedOrigin.toExternalForm).asJava,
                false,
                allowSubdomain,
              ) shouldBe (false)
            }
        }
      }

      it("unless the same port is specified in an allowed origin.") {
        forAll(urlWithPort, arbitrary[Boolean]) {
          (origin: URL, allowSubdomain: Boolean) =>
            println(origin)

            OriginMatcher.isAllowed(
              origin.toExternalForm,
              Set(origin.toExternalForm).asJava,
              false,
              allowSubdomain,
            ) shouldBe (true)
        }
      }

      it("unless configured to.") {
        forAll(
          arbitrary[URL],
          Gen.option(Gen.posNum[Int]),
          arbitrary[Boolean],
        ) { (allowedOrigin, port, allowSubdomain) =>
          whenever(port.forall(_ > 0)) {
            val origin = urlWithMaybePort(
              allowedOrigin.getProtocol,
              allowedOrigin.getHost,
              port,
              allowedOrigin.getFile,
            )
            println(allowedOrigin, origin)

            OriginMatcher.isAllowed(
              origin.toExternalForm,
              Set(allowedOrigin.toExternalForm).asJava,
              true,
              allowSubdomain,
            ) shouldBe (true)
          }
        }
      }
    }

    it("accepts subdomains and arbitrary ports when configured to.") {
      forAll(superAndSubdomainWithPorts) {
        case (allowedOrigin, origin) =>
          println(allowedOrigin, origin)

          OriginMatcher.isAllowed(
            origin.toExternalForm,
            Set(allowedOrigin.toExternalForm).asJava,
            true,
            true,
          ) shouldBe (true)
      }
    }
  }

}
