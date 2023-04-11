plugins {
    java
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.withType(JavaCompile::class) {
    options.compilerArgs.add("-Xlint:deprecation")
    options.compilerArgs.add("-Xlint:unchecked")
    options.encoding = "UTF-8"
}

tasks.withType(Test::class) {
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(8))
    })
}
