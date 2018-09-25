package com.yubico.webauthn.attestation

import java.util.Optional

import com.yubico.scalacheck.gen.JavaGenerators._
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary


object Generators {

  implicit val arbitraryAttestation: Arbitrary[Attestation] = Arbitrary(for {
    trusted <- arbitrary[Boolean]
    deviceProperties <- arbitrary[Optional[java.util.Map[String, String]]]
    metadataIdentifier <- arbitrary[Optional[String]]
    transports <- arbitrary[Optional[java.util.Set[Transport]]]
    vendorProperties <- arbitrary[Optional[java.util.Map[String, String]]]
  } yield Attestation.builder(trusted)
    .deviceProperties(deviceProperties)
    .metadataIdentifier(metadataIdentifier)
    .transports(transports)
    .vendorProperties(vendorProperties)
    .build())

}
