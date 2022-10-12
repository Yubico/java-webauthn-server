plugins {
  `java-library`
  scala
  `maven-publish`
  signing
  id("info.solidsoft.pitest")
  id("io.github.cosmicsilence.scalafix")
}

description = "Yubico internal utilities"

val publishMe by extra(true)

java {
  sourceCompatibility = JavaVersion.VERSION_1_8
  targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
  api(platform(rootProject))

  api("com.fasterxml.jackson.core:jackson-databind")

  implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor")
  implementation("com.fasterxml.jackson.datatype:jackson-datatype-jdk8")
  implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
  implementation("com.google.guava:guava")
  implementation("com.upokecenter:cbor")
  implementation("org.slf4j:slf4j-api")

  testImplementation(platform(project(":test-platform")))
  testImplementation(project(":yubico-util-scala"))
  testImplementation("junit:junit")
  testImplementation("org.scala-lang:scala-library")
  testImplementation("org.scalacheck:scalacheck_2.13")
  testImplementation("org.scalatest:scalatest_2.13")
  testImplementation("org.scalatestplus:junit-4-13_2.13")
  testImplementation("org.scalatestplus:scalacheck-1-16_2.13")
}


tasks.jar {
  manifest {
    attributes(mapOf(
      "Implementation-Id" to "yubico-util",
      "Implementation-Title" to project.description,
      "Implementation-Version" to project.version,
      "Implementation-Vendor" to "Yubico",
    ))
  }
}

pitest {
  pitestVersion.set("1.9.5")
  timestampedReports.set(false)

  outputFormats.set(listOf("XML", "HTML"))

  avoidCallsTo.set(listOf(
    "java.util.logging",
    "org.apache.log4j",
    "org.slf4j",
    "org.apache.commons.logging",
    "com.google.common.io.Closeables",
  ))
}
