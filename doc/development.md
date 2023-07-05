Developer docs
===


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


Code formatting
---

Use `./gradlew spotlessApply` to run the automatic code formatter.
You can also run it in continuous mode as `./gradlew --continuous spotlessApply`
to reformat whenever a file changes.
