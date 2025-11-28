Release procedure
====================

Release candidate versions
---

 1. Make sure release notes in `NEWS` are up to date.

 2. Review the diff from the previous version for any changes to the public API,
    and adjust the upcoming version number accordingly.

    If any implementation dependencies have been added to method signatures in
    the public API, including `throws` declarations, change these dependencies
    from `implementation` to `api` dependency declarations in the relevant
    Gradle build script. Conversely, remove or downgrade to `implementation` any
    dependencies no longer exposed in the public API.

    Add `@since` tags to the JavaDoc for new features.

 3. Run the tests one more time:

    ```
    $ ./gradlew clean check
    ```

 4. Update the Java version in the [`release-verify-signatures` workflow][workflow-release-src].

    See the `openjdk version` line of output from `java -version`:

    ```
    $ java -version  # (example output below)
    openjdk version "17.0.7" 2023-04-18
    OpenJDK Runtime Environment (build 17.0.7+7)
    OpenJDK 64-Bit Server VM (build 17.0.7+7, mixed mode)
    ```

    Given the above output as an example, update the workflow like so:

    ```yaml
    strategy:
      matrix:
        java: ["17.0.7"]
    ```

    Check that this version is available in GitHub Actions. Commit this change,
    if any.

 5. Push the branch to GitHub.

    If the pre-release makes significant changes to the project README, such
    that the README does not accurately reflect the latest non-pre-release
    version, push the changes on a separate release branch:

    ```
    $ git checkout -b release-1.4.0
    $ git push origin release-1.4.0
    ```

    If the README still accurately reflects the latest non-pre-release version,
    you can simply push to main instead:

    ```
    $ git push origin main
    ```

 6. Wait for the ["build" workflow][workflow-build] to finish.
    Download the `artifact-checksums-java17-temurin` artifact,
    unpack it and verify that the artifact checksums match artifacts built locally:

    ```
    $ unzip artifact-checksums-java17-temurin.zip
    $ VERSION=0.1.0-SNAPSHOT ./gradlew primaryPublishJar
    $ sha256sum -c java-webauthn-server-artifacts.sha256sum
    ```

 7. Tag the head commit with an `X.Y.Z-RCN` tag:

    ```
    $ git tag -a -s 1.4.0-RC1 -m "Pre-release 1.4.0-RC1"
    ```

    No tag body needed.

 8. Publish to Sonatype Maven Central Portal:

    ```
    $ ./gradlew publish jreleaserDeploy
    ```

    If this fails, check if your user token has expired and needs to be replaced.
    See [Setup for publishing](./development.md#setup-for-publishing).

 9. Push the tag to GitHub:

    ```
    $ git push origin 1.4.0-RC1
    ```

10. Make GitHub release.

    - Use the new tag as the release tag.
    - Check the pre-release checkbox.
    - Copy the release notes from `NEWS` into the GitHub release notes; reformat
      from ASCIIdoc to Markdown and remove line wraps. Include only
      changes/additions since the previous release or pre-release.
    - Note the JDK version shown by `java -version` in step 3.
      For example: `openjdk version "17.0.7" 2023-04-18`.

11. Check that the ["Reproducible binary" workflow][workflow-release] runs and succeeds.


Release versions
---

 1. Make sure release notes in `NEWS` are up to date.

 2. Review the diff from the previous version for any changes to the public API,
    and adjust the upcoming version number accordingly.

    If any implementation dependencies have been added to method signatures in
    the public API, including `throws` declarations, change these dependencies
    from `implementation` to `api` dependency declarations in the relevant
    Gradle build script. Conversely, remove or downgrade to `implementation` any
    dependencies no longer exposed in the public API.

    Add `@since` tags to the JavaDoc for new features.

 3. Make a no-fast-forward merge from the last (non release candidate) release
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

 4. Remove the "(unreleased)" tag from `NEWS`.

 5. Update the version in the dependency snippets in the README.

 6. Update the version in JavaDoc links in the READMEs.

 7. Update the Java version in the [`release-verify-signatures` workflow][workflow-release-src].

    See the `openjdk version` line of output from `java -version`:

    ```
    $ java -version  # (example output below)
    openjdk version "17.0.7" 2023-04-18
    OpenJDK Runtime Environment (build 17.0.7+7)
    OpenJDK 64-Bit Server VM (build 17.0.7+7, mixed mode)
    ```

    Given the above output as an example, update the workflow like so:

    ```yaml
    strategy:
      matrix:
        java: ["17.0.7"]
    ```

    Check that this version is available in GitHub Actions.

 8. Amend these changes into the merge commit:

    ```
    $ git add NEWS README */README .github/workflows/release-verify-signatures.yml
    $ git commit --amend --reset-author
    ```

 9. Run the tests one more time:

    ```
    $ ./gradlew clean check
    ```

10. Push the branch to GitHub:

    ```
    $ git push origin main
    ```

11. Wait for the ["build" workflow][workflow-build] to finish.
    Download the `artifact-checksums-java17-temurin` artifact,
    unpack it and verify that the artifact checksums match artifacts built locally:

    ```
    $ unzip artifact-checksums-java17-temurin.zip
    $ VERSION=0.1.0-SNAPSHOT ./gradlew primaryPublishJar
    $ sha256sum -c java-webauthn-server-artifacts.sha256sum
    ```

12. Tag the merge commit with an `X.Y.Z` tag:

    ```
    $ git tag -a -s 1.4.0 -m "Release 1.4.0"
    ```

    No tag body needed since that's included in the commit.

 8. Publish to Sonatype Maven Central Portal:

    ```
    $ ./gradlew publish jreleaserDeploy
    ```

    If this fails, check if your user token has expired and needs to be replaced.
    See [Setup for publishing](./development.md#setup-for-publishing).

13. Push the tag to GitHub:

    ```
    $ git push origin 1.4.0
    ```

14. Make GitHub release.

    - Use the new tag as the release tag.
    - Copy the release notes from `NEWS` into the GitHub release notes; reformat
      from ASCIIdoc to Markdown and remove line wraps. Include all changes since
      the previous release (not just changes since the previous pre-release).
    - Note the JDK version shown by `java -version` in step 6.
      For example: `openjdk version "17.0.7" 2023-04-18`.

15. Check that the ["Reproducible binary" workflow][workflow-release] runs and succeeds.


[workflow-build]: https://github.com/Yubico/java-webauthn-server/actions/workflows/build.yml
[workflow-release]: https://github.com/Yubico/java-webauthn-server/actions/workflows/release-verify-signatures.yml
[workflow-release-src]: https://github.com/Yubico/java-webauthn-server/blob/main/.github/workflows/release-verify-signatures.yml#L42
