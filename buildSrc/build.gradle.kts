plugins {
  groovy
  `groovy-gradle-plugin`
  `kotlin-dsl`
}

repositories {
  mavenLocal()
  gradlePluginPortal()
  mavenCentral()
}

dependencies {
  implementation("info.solidsoft.gradle.pitest:gradle-pitest-plugin:1.19.0-rc.2")
  implementation("io.franzbecker:gradle-lombok:5.1.0-SNAPSHOT")

  // Spotless dropped Java 8 support in version 2.33.0
  // spotless-plugin-gradle dropped Java <17 support in version 8.0.0
  if (JavaVersion.current().isCompatibleWith(JavaVersion.VERSION_17)) {
    implementation("com.diffplug.spotless:spotless-plugin-gradle:8.1.0")
    implementation("io.github.cosmicsilence:gradle-scalafix:0.2.6")
  }
}
