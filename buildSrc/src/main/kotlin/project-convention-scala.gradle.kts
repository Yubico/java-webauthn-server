plugins {
    scala
}

tasks.withType(ScalaCompile::class) {
    // listOf doesn't work at the moment
    // See: https://github.com/gradle/gradle/issues/23193
    // See: https://github.com/gradle/gradle/pull/23198
    // See: https://github.com/gradle/gradle/pull/23751
    scalaCompileOptions.additionalParameters = mutableListOf("-Wunused")
}
