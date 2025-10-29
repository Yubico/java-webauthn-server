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

We mean to follow the [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html),
but do not enforce it comprehensively (apart from what the automatic formatter does).
Take particular note of the rules:

- [3.3.1 No wildcard imports](https://google.github.io/styleguide/javaguide.html#s3.3.1-wildcard-imports)
- [5.3 Camel case: defined](https://google.github.io/styleguide/javaguide.html#s5.3-camel-case)
  (`XmlHttpRequest` and `requestId`, not `XMLHTTPRequest` and `requestID`)

In case of disagreement on code style, defer to the style guide.


Setup for publishing
---

To enable publishing to Maven Central via Sonatype Nexus,
[generate a user token](https://central.sonatype.org/publish/generate-token/).
Set `yubicoPublish=true` in `$HOME/.gradle/gradle.properties` and add your token
username and password. Example:

```properties
yubicoPublish=true
ossrhUsername=8pnmjKQP
ossrhPassword=bmjuyWSIik8P3Nq/ZM2G0Xs0sHEKBg+4q4zTZ8JDDRCr
```

Generate a Sonatype user token: https://central.sonatype.com/usertoken
Please set an expiration date rather than unlimited validity.
Set this and `yubicoPublish=true` in `$HOME/.gradle/gradle.properties`:

```properties
yubicoPublish=true
sonatypeUsername=NaXB0g
sonatypePassword=wBbCPg2ThHhV2WpQPxt5kdTUaVQwOdnAS
```


Publishing a release
---

See the [release checklist](./releasing.md).
