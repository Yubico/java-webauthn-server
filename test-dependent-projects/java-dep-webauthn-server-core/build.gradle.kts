plugins {
    `java-library`
}

dependencies {
    implementation(project(":webauthn-server-core"))
    testImplementation("junit:junit:4.12")
}

