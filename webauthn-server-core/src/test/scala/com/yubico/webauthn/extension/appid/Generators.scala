package com.yubico.webauthn.extension.appid

import com.yubico.scalacheck.gen.JavaGenerators._
import org.scalacheck.Arbitrary
import org.scalacheck.Gen


object Generators {

  implicit val arbitraryAppId: Arbitrary[AppId] = Arbitrary(for {
    url <- url(
      scheme = Gen.const("https"),
      path = Gen.alphaNumStr suchThat (_ != "/")
    )
  } yield new AppId(url.toExternalForm))

}
