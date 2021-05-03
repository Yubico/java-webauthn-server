Developer docs
===

Inconsistent directory naming
---

In resolving [issue #97](https://github.com/Yubico/java-webauthn-server/issues/97),
we opted to split the `webauthn-server-core` module into one `webauthn-server-core` meta-module
and one `webauthn-server-core-minimal` module with the code and all dependencies except BouncyCastle.
However, to avoid file renames and since this is intended as a temporary change,
the source code for the `webauthn-server-core` module is hosted in the `webauthn-server-core-bundle/` subproject
and the `webauthn-server-core-minimal` module is hosted in `webauthn-server-core/`.

We intend to eliminate the `webauthn-server-core-bundle` subproject in the next major version release,
and return the current `webauthn-server-core-minimal` module to the `webauthn-server-core` module name.
This naming inconsistency should be fixed along with this.


Code formatting
---

Use `./gradlew spotlessApply` to run the automatic code formatter.
You can also run it in continuous mode as `./gradlew --continuous spotlessApply`
to reformat whenever a file changes.
