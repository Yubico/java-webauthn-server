plugins {
    java
}

java {
    toolchain {
        // Java 8 binaries are not reproducible
        languageVersion.set(JavaLanguageVersion.of(11))
    }
}

tasks.withType(JavaCompile::class) {
    options.compilerArgs.add("-Xlint:deprecation")
    options.compilerArgs.add("-Xlint:unchecked")
    options.encoding = "UTF-8"
    options.release.set(8)
}

tasks.withType(Test::class) {
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(8))
    })
}
