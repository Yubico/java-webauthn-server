plugins {
  `java-library`
  `project-convention-java`
  `project-convention-scala`
  `project-convention-lombok`
  `project-convention-code-formatting`
  `project-convention-archives`
  `project-convention-publish`
  `project-convention-pitest`
}

description = "Yubico WebAuthn attestation subsystem"

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

  testImplementation("org.slf4j:slf4j-api") {
    version {
      strictly("[1.7.25,1.8-a)") // Pre-1.8 version required by slf4j-test
    }
  }
  testRuntimeOnly("uk.org.lidalia:slf4j-test")
}

val integrationTest = task<Test>("integrationTest") {
  description = "Runs integration tests."
  group = "verification"

  testClassesDirs = sourceSets["integrationTest"].output.classesDirs
  classpath = sourceSets["integrationTest"].runtimeClasspath
  shouldRunAfter(tasks.test)
}
tasks["check"].dependsOn(integrationTest)

tasks.jar {
  manifest {
    attributes(mapOf(
      "Automatic-Module-Name" to "com.yubico.webauthn.attestation",
      "Implementation-Id" to "java-webauthn-server-attestation",
      "Implementation-Title" to project.description,
    ))
  }
}

// Configure cross-links from webauthn-server-attestation JavaDoc to core JavaDoc
tasks.javadoc.configure {
  val coreProj = project(":webauthn-server-core")
  val coreJavadoc = coreProj.tasks.javadoc.get()
  inputs.files(coreJavadoc.outputs.files)

  // These links won't work locally, but they will work on developers.yubico.com
  (options as StandardJavadocDocletOptions).linksOffline("../../webauthn-server-core/${coreProj.version}", "${coreJavadoc.destinationDir}")

  // Use this instead for local testing
  //(options as StandardJavadocDocletOptions).linksOffline("file://${coreJavadoc.destinationDir}", "${coreJavadoc.destinationDir}")
}
