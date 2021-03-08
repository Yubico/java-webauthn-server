plugins {
    `java-library`
}

dependencies {
    implementation(project(":webauthn-server-core-minimal"))
    testImplementation("junit:junit:4.12")
    testImplementation("org.mockito:mockito-core:[2.27.0,3)")
}
