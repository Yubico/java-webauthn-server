plugins {
    scala
}

tasks.withType(ScalaCompile::class) {
    scalaCompileOptions.additionalParameters = listOf("-Wunused")
}
