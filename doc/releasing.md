Release procedure
====================

Release candidate versions
---

 1. Make sure release notes in `NEWS` are up to date.

 2. Make sure you're running Gradle in JDK 11.

 3. Run the tests one more time:

    ```
    $ ./gradlew clean check
    ```

 4. Tag the head commit with an `X.Y.Z-RCN` tag:

    ```
    $ git tag -a -s 1.4.0-RC1 -m "Pre-release 1.4.0-RC1"
    ```

    No tag body needed.

 5. Publish to Sonatype Nexus:

    ```
    $ ./gradlew publish closeAndReleaseRepository
    ```

 6. Wait for the artifacts to become downloadable at
    https://repo1.maven.org/maven2/com/yubico/webauthn-server-core/ . This is
    needed for one of the GitHub Actions release workflows and usually takes
    less than 30 minutes (long before the artifacts become searchable on the
    main Maven Central website).

 7. Push to GitHub:

    ```
    $ git push origin master 1.4.0-RC1
    ```

 8. Make GitHub release.

    - Use the new tag as the release tag
    - Check the pre-release checkbox
    - Copy the release notes from `NEWS` into the GitHub release notes; reformat
      from ASCIIdoc to Markdown and remove line wraps. Include only
      changes/additions since the previous release or pre-release.
    - Attach the signature files from
      `webauthn-server-attestation/build/libs/webauthn-server-attestation-X.Y.Z-RCN.jar.asc`,
      `webauthn-server-core/build/libs/webauthn-server-core-minimal-X.Y.Z-RCN.jar.asc`
      and
      `webauthn-server-core-bundle/build/libs/webauthn-server-core-X.Y.Z-RCN.jar.asc`.
    - Note which JDK version was used to build the artifacts.


Release versions
---

 1. Make sure release notes in `NEWS` are up to date.

 2. Make sure you're running Gradle in JDK 11.

 3. Make a no-fast-forward merge from the last (non release candidate) release
    to the commit to be released:

    ```
    $ git checkout 1.3.0
    $ git checkout -b release-1.4.0
    $ git merge --no-ff master
    ```

    Copy the release notes for this version from `NEWS` into the merge commit
    message; reformat it from ASCIIdoc to Markdown and re-wrap line widths at
    the conventional 72 columns (see
    [this](https://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)
    and [this](https://chris.beams.io/posts/git-commit/)). See previous release
    commits for examples.

    ```
    $ git checkout master
    $ git merge --ff-only release-1.4.0
    $ git branch -d release-1.4.0
    ```

 4. Remove the "(unreleased)" tag from `NEWS`.

 5. Update the version in the dependency snippets in the README.

 6. Amend these changes into the merge commit:

    ```
    $ git add NEWS
    $ git commit --amend --reset-author
    ```

 7. Run the tests one more time:

    ```
    $ ./gradlew clean check
    ```

 8. Tag the merge commit with an `X.Y.Z` tag:

    ```
    $ git tag -a -s 1.4.0 -m "Release 1.4.0"
    ```

    No tag body needed since that's included in the commit.

 9. Publish to Sonatype Nexus:

    ```
    $ ./gradlew publish closeAndReleaseRepository
    ```

10. Wait for the artifacts to become downloadable at
    https://repo1.maven.org/maven2/com/yubico/webauthn-server-core/ . This is
    needed for one of the GitHub Actions release workflows and usually takes
    less than 30 minutes (long before the artifacts become searchable on the
    main Maven Central website).

11. Push to GitHub:

    ```
    $ git push origin master 1.4.0
    ```

12. Make GitHub release.

    - Use the new tag as the release tag
    - Copy the release notes from `NEWS` into the GitHub release notes; reformat
      from ASCIIdoc to Markdown and remove line wraps. Include all changes since
      the previous release (not just changes since the previous pre-release).
    - Attach the signature files from
      `webauthn-server-attestation/build/libs/webauthn-server-attestation-X.Y.Z.jar.asc`,
      `webauthn-server-core/build/libs/webauthn-server-core-minimal-X.Y.Z.jar.asc`
      and
      `webauthn-server-core-bundle/build/libs/webauthn-server-core-X.Y.Z.jar.asc`.

    - Note which JDK version was used to build the artifacts.
