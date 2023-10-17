plugins {
  groovy
  `groovy-gradle-plugin`
  `kotlin-dsl`
}

repositories {
  gradlePluginPortal()
  mavenCentral()
}

dependencies {
  implementation("info.solidsoft.gradle.pitest:gradle-pitest-plugin:1.9.11")
  implementation("io.franzbecker:gradle-lombok:5.0.0")

  // Spotless dropped Java 8 support in version 2.33.0
  if (JavaVersion.current().isJava11Compatible) {
    implementation("com.diffplug.spotless:spotless-plugin-gradle:6.22.0")
    implementation("io.github.cosmicsilence:gradle-scalafix:0.1.15")
  }
}
