plugins {
    `java-library`
}

val coreTestsOutput = project(":webauthn-server-core").extensions.getByType(SourceSetContainer::class).test.get().output

dependencies {
    implementation(project(":webauthn-server-core"))
    implementation("org.bouncycastle:bcprov-jdk15on:[1.62,2)")

    testImplementation(coreTestsOutput)
    testImplementation("junit:junit:4.12")
    testImplementation("org.mockito:mockito-core:[2.27.0,3)")

    // Runtime-only internal dependency of webauthn-server-core
    testImplementation("com.augustcellars.cose:cose-java:[1.0.0,2)")

    testRuntimeOnly("ch.qos.logback:logback-classic:[1.2.3,2)")

    // Transitive dependencies from coreTestOutput
    testImplementation("org.scala-lang:scala-library:[2.13.1,3)")
}
