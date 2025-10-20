plugins {
    java
}

tasks.withType(JavaCompile::class) {
    options.compilerArgs.add("-Xlint:deprecation")
    options.compilerArgs.add("-Xlint:unchecked")
    options.encoding = "UTF-8"

    if (JavaVersion.current().isJava9Compatible) {
        options.release.set(8)
    } else {
        targetCompatibility = "1.8"
        sourceCompatibility = "1.8"
    }
}

tasks.register<Test>("testJava8") {
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(8))
  })
  tasks["check"].dependsOn(this)
}

tasks.register<Test>("testJava11") {
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(11))
  })
  tasks["check"].dependsOn(this)
}

tasks.register<Test>("testJava17") {
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(17))
  })
  tasks["check"].dependsOn(this)
}

tasks.register<Test>("testJava21") {
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(21))
  })
  tasks["check"].dependsOn(this)
}

tasks.register<Test>("testJava25") {
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(25))
  })
  tasks["check"].dependsOn(this)
}
