plugins {
    `java-library`
}

dependencies {
    implementation(project(":webauthn-server-attestation"))
    testImplementation("junit:junit:4.12")
}

