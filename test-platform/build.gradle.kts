plugins {
  `java-platform`
}

description = "Dependency constraints for tests"

dependencies {
  constraints {
    api("junit:junit:4.13.2")
    api("org.mockito:mockito-core:4.7.0")
    api("org.scalacheck:scalacheck_2.13:1.16.0")
    api("org.scalatest:scalatest_2.13:3.2.13")
    api("org.scalatestplus:junit-4-13_2.13:3.2.13.0")
    api("org.scalatestplus:scalacheck-1-16_2.13:3.2.13.0")
    api("uk.org.lidalia:slf4j-test:1.2.0")
    api("org.bouncycastle:bcpkix-jdk18on:[1.62,2)")
    api("org.bouncycastle:bcprov-jdk18on:[1.62,2)")
  }
}
