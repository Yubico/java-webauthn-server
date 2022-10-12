import com.yubico.gradle.GitUtils

plugins {
  `java-library`
  scala
  `maven-publish`
  signing
  id("info.solidsoft.pitest")
  id("io.github.cosmicsilence.scalafix")
}

description = "Yubico WebAuthn attestation subsystem"

val publishMe by extra(true)

java {
  sourceCompatibility = JavaVersion.VERSION_1_8
  targetCompatibility = JavaVersion.VERSION_1_8
}

sourceSets {
  create("integrationTest") {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
  }
}

configurations["integrationTestImplementation"].extendsFrom(configurations.testImplementation.get())
configurations["integrationTestRuntimeOnly"].extendsFrom(configurations.testRuntimeOnly.get())

// Can't use test fixtures because they interfere with pitest: https://github.com/gradle/gradle/issues/12168
evaluationDependsOn(":webauthn-server-core")
val coreTestsOutput = project(":webauthn-server-core").extensions.getByType(SourceSetContainer::class).test.get().output

dependencies {
  api(platform(rootProject))

  api(project(":webauthn-server-core"))

  implementation(project(":yubico-util"))
  implementation("com.fasterxml.jackson.core:jackson-databind")
  implementation("org.slf4j:slf4j-api")

  testImplementation(platform(project(":test-platform")))
  testImplementation(coreTestsOutput)
  testImplementation(project(":yubico-util-scala"))
  testImplementation("com.fasterxml.jackson.datatype:jackson-datatype-jdk8")
  testImplementation("junit:junit")
  testImplementation("org.bouncycastle:bcpkix-jdk18on")
  testImplementation("org.eclipse.jetty:jetty-server:[9.4.9.v20180320,10)")
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
}

val integrationTest = task<Test>("integrationTest") {
  description = "Runs integration tests."
  group = "verification"

  testClassesDirs = sourceSets["integrationTest"].output.classesDirs
  classpath = sourceSets["integrationTest"].runtimeClasspath
  shouldRunAfter(tasks.test)

  // Required for processing CRL distribution points extension
  systemProperty("com.sun.security.enableCRLDP", "true")
}
tasks["check"].dependsOn(integrationTest)

tasks.jar {
  manifest {
    attributes(mapOf(
      "Implementation-Id" to "java-webauthn-server-attestation",
      "Implementation-Title" to project.description,
      "Implementation-Version" to project.version,
      "Implementation-Vendor" to "Yubico",
      "Git-Commit" to GitUtils.getGitCommitOrUnknown(projectDir),
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
