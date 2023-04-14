plugins {
  `project-convention-java`
  `project-convention-scala`
  `project-convention-code-formatting`
}

description = "Yubico internal Scala utilities"

dependencies {
  implementation(platform(rootProject))
  implementation(platform(project(":test-platform")))

  implementation("org.bouncycastle:bcprov-jdk18on")
  implementation("org.scala-lang:scala-library")
  implementation("org.scalacheck:scalacheck_2.13")
  implementation("org.scalatest:scalatest_2.13")
}
