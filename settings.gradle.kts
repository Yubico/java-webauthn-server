rootProject.name = "webauthn-server-parent"
include(":webauthn-server-attestation")
include(":webauthn-server-core")
include(":webauthn-server-demo")
include(":yubico-util")
include(":yubico-util-scala")

include(":test-dependent-projects:java-dep-webauthn-server-attestation")
include(":test-dependent-projects:java-dep-webauthn-server-core")
include(":test-dependent-projects:java-dep-webauthn-server-core-and-bouncycastle")
include(":test-dependent-projects:java-dep-yubico-util")
include(":test-platform")

dependencyResolutionManagement {
    versionCatalogs {
        create("constraintLibs") {
            val jacksonVer = version("jackson", "[2.13.2.1,3)")
            library("jackson-bom", "com.fasterxml.jackson", "jackson-bom").versionRef(jacksonVer)
        }
    }
}
