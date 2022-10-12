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
    $ ./gradlew publishToSonatype closeAndReleaseSonatypeStagingRepository
    ```

 5. Push to GitHub.

    If the pre-release makes significant changes to the project README, such
    that the README does not accurately reflect the latest non-pre-release
    version, push the changes on a separate release branch:

    ```
    $ git checkout -b release-1.4.0
    $ git push origin release-1.4.0 1.4.0-RC1
    ```

    If the README still accurately reflects the latest non-pre-release version,
    you can simply push to main instead:

    ```
    $ git push origin main 1.4.0-RC1
    ```

 6. Make GitHub release.

    - Use the new tag as the release tag
    - Check the pre-release checkbox
    - Copy the release notes from `NEWS` into the GitHub release notes; reformat
      from ASCIIdoc to Markdown and remove line wraps. Include only
      changes/additions since the previous release or pre-release.
    - Note which JDK version was used to build the artifacts.

 7. Check that the ["Reproducible binary"
    workflow](/Yubico/java-webauthn-server/actions/workflows/release-verify-signatures.yml)
    runs and succeeds.


Release versions
---

 1. Make sure release notes in `NEWS` are up to date.

 2. Make a no-fast-forward merge from the last (non release candidate) release
    to the commit to be released:

    ```
    $ git checkout 1.3.0
    $ git checkout -b release-1.4.0
    $ git merge --no-ff main
    ```

    Copy the release notes for this version from `NEWS` into the merge commit
    message; reformat it from ASCIIdoc to Markdown and re-wrap line widths at
    the conventional 72 columns (see
    [this](https://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)
    and [this](https://chris.beams.io/posts/git-commit/)). See previous release
    commits for examples.

    ```
    $ git checkout main
    $ git merge --ff-only release-1.4.0
    $ git branch -d release-1.4.0
    ```

 3. Remove the "(unreleased)" tag from `NEWS`.

 4. Update the version in the dependency snippets in the README.

 5. Update the version in JavaDoc links in the READMEs.

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
    $ ./gradlew publishToSonatype closeAndReleaseSonatypeStagingRepository
    ```

10. Push to GitHub:

    ```
    $ git push origin main 1.4.0
    ```

11. Make GitHub release.

    - Use the new tag as the release tag
    - Copy the release notes from `NEWS` into the GitHub release notes; reformat
      from ASCIIdoc to Markdown and remove line wraps. Include all changes since
      the previous release (not just changes since the previous pre-release).
    - Note which JDK version was used to build the artifacts.

12. Check that the ["Reproducible binary"
    workflow](/Yubico/java-webauthn-server/actions/workflows/release-verify-signatures.yml)
    runs and succeeds.
