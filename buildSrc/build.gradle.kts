plugins {
  groovy
  `kotlin-dsl`
}

repositories {
  gradlePluginPortal()
  mavenCentral()
}

dependencies {
  implementation("com.diffplug.spotless:spotless-plugin-gradle:6.13.0")
  implementation("info.solidsoft.gradle.pitest:gradle-pitest-plugin:1.9.11")
  implementation("io.github.cosmicsilence:gradle-scalafix:0.1.13")
}
