plugins {
  `java-library`
  id("me.champeau.jmh") version "0.6.8"
  `project-convention-java`
  `project-convention-scala`
  `project-convention-lombok`
  `project-convention-code-formatting`
  `project-convention-archives`
  `project-convention-publish`
  `project-convention-pitest`
}

description = "Yubico WebAuthn server core API"

dependencies {
  api(platform(rootProject))

  implementation(project(":yubico-util"))
  implementation("com.augustcellars.cose:cose-java")
  implementation("com.fasterxml.jackson.core:jackson-databind")
  implementation("com.google.guava:guava")
  implementation("com.upokecenter:cbor")
  implementation("org.apache.httpcomponents.client5:httpclient5")
  implementation("org.slf4j:slf4j-api")

  testImplementation(platform(project(":test-platform")))
  testImplementation(project(":yubico-util-scala"))
  testImplementation("com.fasterxml.jackson.core:jackson-databind")
  testImplementation("com.upokecenter:cbor")
  testImplementation("junit:junit")
  testImplementation("org.bouncycastle:bcpkix-jdk18on")
  testImplementation("org.bouncycastle:bcprov-jdk18on")
  testImplementation("org.mockito:mockito-core")
  testImplementation("org.scala-lang:scala-library")
  testImplementation("org.scalacheck:scalacheck_2.13")
  testImplementation("org.scalatest:scalatest_2.13")
  testImplementation("org.scalatestplus:junit-4-13_2.13")
  testImplementation("org.scalatestplus:scalacheck-1-16_2.13")
  testImplementation("uk.org.lidalia:slf4j-test")

  testImplementation("org.slf4j:slf4j-api") {
    version {
      strictly("[1.7.25,1.8-a)") // Pre-1.8 version required by slf4j-test
    }
  }

  jmhImplementation(platform(project(":test-platform")))
  jmhRuntimeOnly("org.slf4j:slf4j-nop")
}

configurations.jmhRuntimeClasspath {
  exclude(module = "slf4j-test")
}

tasks.withType(Jar::class) {
  manifest {
    attributes(mapOf(
      "Implementation-Title" to "Yubico Web Authentication server library",

      "Specification-Title" to "Web Authentication: An API for accessing Public Key Credentials",
      "Specification-Version" to "Level 2 Proposed Recommendation 2021-04-08",
      "Specification-Vendor" to "World Wide Web Consortium",
      "Specification-Url" to "https://www.w3.org/TR/2021/REC-webauthn-2-20210408/",
      "Specification-Url-Latest" to "https://www.w3.org/TR/webauthn-2/",
      "Specification-W3c-Status" to "recommendation",
      "Specification-Release-Date" to "2021-04-08",
    ))
  }
}
