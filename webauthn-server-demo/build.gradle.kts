plugins {
  java
  war
  application
  scala
  id("io.github.cosmicsilence.scalafix")
}

description = "WebAuthn demo"

// Can't use test fixtures because they interfere with pitest: https://github.com/gradle/gradle/issues/12168
evaluationDependsOn(":webauthn-server-core")
val coreTestsOutput = project(":webauthn-server-core").extensions.getByType(SourceSetContainer::class).test.get().output

dependencies {
  implementation(platform(rootProject))
  implementation(platform(project(":test-platform")))

  implementation(project(":webauthn-server-attestation"))
  implementation(project(":webauthn-server-core"))
  implementation(project(":yubico-util"))

  implementation("com.fasterxml.jackson.core:jackson-databind")
  implementation("com.google.guava:guava")
  implementation("com.upokecenter:cbor")
  implementation("org.bouncycastle:bcprov-jdk18on")
  implementation("org.slf4j:slf4j-api")

  implementation("org.eclipse.jetty:jetty-servlet:9.4.9.v20180320")
  implementation("org.glassfish.jersey.containers:jersey-container-servlet-core:2.36")
  implementation("javax.ws.rs:javax.ws.rs-api:2.1.1")

  runtimeOnly("ch.qos.logback:logback-classic:1.3.0")
  runtimeOnly("org.glassfish.jersey.containers:jersey-container-servlet:2.36")
  runtimeOnly("org.glassfish.jersey.inject:jersey-hk2:2.36")

  testImplementation(coreTestsOutput)
  testImplementation(project(":yubico-util-scala"))

  testImplementation("junit:junit")
  testImplementation("org.mockito:mockito-core")
  testImplementation("org.scala-lang:scala-library")
  testImplementation("org.scalacheck:scalacheck_2.13")
  testImplementation("org.scalatest:scalatest_2.13")
  testImplementation("org.scalatestplus:junit-4-13_2.13")
  testImplementation("org.scalatestplus:scalacheck-1-16_2.13")

  modules {
    module("javax.servlet:servlet-api") {
      replacedBy("javax.servlet:javax.servlet-api")
    }
  }
}

application {
  mainClass.set("demo.webauthn.EmbeddedServer")
}

for (task in listOf(tasks.installDist, tasks.distZip, tasks.distTar)) {
  val intoDir = if (task == tasks.installDist) { "/" } else { "${project.name}-${project.version}" }
  task {
    into(intoDir) {
      from("keystore.jks")
      from("src/main/webapp") {
        into("src/main/webapp")
      }
    }
  }
}
