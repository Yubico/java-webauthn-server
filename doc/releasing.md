Release procedure
====================

Release candidate versions
---

 1. Make sure release notes in `NEWS` are up to date.

 2. Run the tests one more time:

    ```
    $ ./gradlew clean check
    ```

 3. Tag the head commit with an `X.Y.Z-RCN` tag:

    ```
    $ git tag -a -s 1.4.0-RC1 -m "Pre-release 1.4.0-RC1"
    ```

    No tag body needed.

 4. Publish to Sonatype Nexus:

    ```
    $ ./gradlew publish closeAndReleaseRepository
    ```

 5. Push to GitHub:

    ```
    $ git push origin master 1.4.0-RC1
    ```

 6. Make GitHub release.

    - Use the new tag as the release tag
    - Check the pre-release checkbox
    - Copy the release notes from `NEWS` into the GitHub release notes; reformat
      from ASCIIdoc to Markdown and remove line wraps. Include only
      changes/additions since the previous release or pre-release.
    - Attach the signature files from
      `webauthn-server-attestation/build/libs/webauthn-server-attestation-X.Y.Z-RCN.jar.asc`
      and
      `webauthn-server-core/build/libs/webauthn-server-core-X.Y.Z-RCN.jar.asc`.
    - Note which JDK version was used to build the artifacts.


Release versions
---

 1. Make sure release notes in `NEWS` are up to date.

 2. Make a no-fast-forward merge from the last release to the commit to be released:

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

 3. Remove the "(unreleased)" tag from `NEWS`.

 4. Amend this change into the merge commit:

    ```
    $ git add NEWS
    $ git commit --amend --reset-author
    ```

 5. Run the tests one more time:

    ```
    $ ./gradlew clean check
    ```

 6. Tag the merge commit with an `X.Y.Z` tag:

    ```
    $ git tag -a -s 1.4.0 -m "Release 1.4.0"
    ```

    No tag body needed since that's included in the commit.

 7. Publish to Sonatype Nexus:

    ```
    $ ./gradlew publish closeAndReleaseRepository
    ```

 8. Push to GitHub:

    ```
    $ git push origin master 1.4.0
    ```

 9. Make GitHub release.

    - Use the new tag as the release tag
    - Copy the release notes from `NEWS` into the GitHub release notes; reformat
      from ASCIIdoc to Markdown and remove line wraps. Include all changes since
      the previous release (not just changes since the previous pre-release).
    - Attach the signature files from
      `webauthn-server-attestation/build/libs/webauthn-server-attestation-X.Y.Z.jar.asc`
      and `webauthn-server-core/build/libs/webauthn-server-core-X.Y.Z.jar.asc`.
    - Note which JDK version was used to build the artifacts.
