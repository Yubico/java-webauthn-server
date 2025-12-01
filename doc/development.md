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

Generate a Sonatype user token: https://central.sonatype.com/usertoken .
Please set an expiration date rather than unlimited validity.

Set this token username and password in `$HOME/.jreleaser/config.properties`,
along with the fingerprint of the GPG key to use for signing artifacts.
Create the file if it does not exist.
Example:


<!-- These username and password values are meaningless random data, not real secrets -->
```properties
JRELEASER_MAVENCENTRAL_USERNAME=PYgw7b
JRELEASER_MAVENCENTRAL_PASSWORD=QxExuJ0wwfBzbXVOsaSTUTBkXH8Fa2dFo
JRELEASER_GPG_KEYNAME=2D6753CFF0B0FB32F9EEBA485B9688125FF0B636
JRELEASER_MAVENCENTRAL_STAGE=FULL
JRELEASER_GITHUB_TOKEN=nope
```

JReleaser requires `JRELEASER_GITHUB_TOKEN` to be set, but the value doesn't need to be valid.


Publishing a release
---

See the [release checklist](./releasing.md).

The first time you publish a release, request to have your PGP key added to the trusted keyring in the [`release-verify-signatures` workflow][workflow-release-src].


[workflow-release-src]: https://github.com/Yubico/java-webauthn-server/blob/main/.github/workflows/release-verify-signatures.yml
