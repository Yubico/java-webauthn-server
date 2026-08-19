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

tasks.register("testJavaAll") {
  tasks["check"].dependsOn(this)
}

tasks.register<Test>("testJava8") {
  testClassesDirs = tasks.named<Test>("test").get().testClassesDirs
  classpath = tasks.named<Test>("test").get().classpath
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(8))
  })
  tasks["testJavaAll"].dependsOn(this)
}

tasks.register<Test>("testJava11") {
  testClassesDirs = tasks.named<Test>("test").get().testClassesDirs
  classpath = tasks.named<Test>("test").get().classpath
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(11))
  })
  tasks["testJavaAll"].dependsOn(this)
}

tasks.register<Test>("testJava17") {
  testClassesDirs = tasks.named<Test>("test").get().testClassesDirs
  classpath = tasks.named<Test>("test").get().classpath
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(17))
  })
  tasks["testJavaAll"].dependsOn(this)
}

tasks.register<Test>("testJava21") {
  testClassesDirs = tasks.named<Test>("test").get().testClassesDirs
  classpath = tasks.named<Test>("test").get().classpath
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(21))
  })
  tasks["testJavaAll"].dependsOn(this)
}

tasks.register<Test>("testJava25") {
  testClassesDirs = tasks.named<Test>("test").get().testClassesDirs
  classpath = tasks.named<Test>("test").get().classpath
  javaLauncher.set(javaToolchains.launcherFor {
    languageVersion.set(JavaLanguageVersion.of(25))
  })
  tasks["testJavaAll"].dependsOn(this)
}