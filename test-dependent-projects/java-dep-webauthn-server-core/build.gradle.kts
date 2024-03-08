plugins {
    `java-library`
}

val coreTestsOutput = project(":webauthn-server-core").extensions.getByType(SourceSetContainer::class).test.get().output

dependencies {
    implementation(project(":webauthn-server-core"))

    testImplementation(coreTestsOutput)
    testImplementation("junit:junit:4.12")
    testImplementation("org.mockito:mockito-core:[2.27.0,3)")

    // Transitive dependencies from coreTestOutput
    testImplementation("org.scala-lang:scala-library:[2.13.1,3)")
}
