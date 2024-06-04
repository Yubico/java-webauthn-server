Developer docs
===


JDK versions
---

The project's official build JDK version is the latest LTS JDK version,
although the project may lag behind the true latest release for a while
until we can upgrade the build definition to match this target.

The official build JDK version currently in effect is encoded in the
["Reproducible binary"](https://github.com/Yubico/java-webauthn-server/blob/main/.github/workflows/release-verify-signatures.yml)
workflow,
as the JDK version is crucial for successfully reproducing released binaries.
This version is also enforced in the release process in
[`build.gradle`](https://github.com/Yubico/java-webauthn-server/blob/main/build.gradle).

The [primary build workflow](https://github.com/Yubico/java-webauthn-server/blob/main/.github/workflows/build.yml)
should run on all currently maintaned LTS JDK versions,
and ideally also the latest non-LTS JDK version if Gradle and other build dependencies are compatible.

A list of JDK versions and maintenance status can be found [here](https://en.wikipedia.org/wiki/Java_version_history).


Code formatting
---

Use `./gradlew spotlessApply` to run the automatic code formatter.
You can also run it in continuous mode as `./gradlew --continuous spotlessApply`
to reformat whenever a file changes.


Setup for publishing
---

To enable publishing to Maven Central via Sonatype Nexus, set
`yubicoPublish=true` in `$HOME/.gradle/gradle.properties` and add your Sonatype
username and password. Example:

```properties
yubicoPublish=true
ossrhUsername=8pnmjKQP
ossrhPassword=bmjuyWSIik8P3Nq/ZM2G0Xs0sHEKBg+4q4zTZ8JDDRCr
```


Publishing a release
---

See the [release checklist](./releasing.md).
