Web Authentication server library (EXPERIMENTAL)
===

This is a prototype implementation of a Web Authentication Relying Party (RP).


Running
---

An example app is included in the [u2flib-server-demo](../u2flib-server-demo). To run it:

    $ cd java-u2flib-server/u2flib-server-demo
    $ ./gradlew run
    $ $BROWSER https://localhost:8443/


Implementation status
---

The following combinations of user agent and authenticator are known to work:

- Firefox Nightly 57.0a1 2017-09-15
  - YubiKey 4
  - YubiKey 4 Nano
  - YubiKey Neo - although with random failures in `credentials.get()` (login)
  - YubiKey 4C - although with random failures in `credentials.get()` (login)
  - U2F security key by Yubico

Test results generated from commit 8120cf1.

![Implementation status: Registration](test-registration.png)
![Implementation status: Authentication](test-assertion.png)
