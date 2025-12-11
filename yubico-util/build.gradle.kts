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

dependencies {
  api(platform(rootProject))

  api("com.fasterxml.jackson.core:jackson-databind")

  implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor")
  implementation("com.fasterxml.jackson.datatype:jackson-datatype-jdk8")
  implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
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

  jmhImplementation(platform(project(":test-platform")))
  jmhRuntimeOnly("org.slf4j:slf4j-nop")
}

configurations.jmhRuntimeClasspath {
  exclude(module = "slf4j-test")
}

tasks.jar {
  manifest {
    attributes(mapOf(
      "Automatic-Module-Name" to "com.yubico.internal.util",
      "Implementation-Id" to "yubico-util",
      "Implementation-Title" to project.description,
    ))
  }
}
