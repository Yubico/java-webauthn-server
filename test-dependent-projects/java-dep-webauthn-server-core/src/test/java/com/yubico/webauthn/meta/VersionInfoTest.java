package com.yubico.webauthn.meta;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.time.LocalDate;
import org.junit.Test;

/**
 * Since this depends on the manifest of the core jar, and the manifest is build by Gradle, this
 * test is likely to fail when run in an IDE. It works as expected when run via Gradle.
 */
public class VersionInfoTest {

  final VersionInfo versionInfo = VersionInfo.getInstance();

  @Test
  public void specPropertiesAreSet() {
    final Specification spec = versionInfo.getSpecification();
    assertTrue(spec.getLatestVersionUrl().toExternalForm().startsWith("https://"));
    assertTrue(spec.getUrl().toExternalForm().startsWith("https://"));
    assertTrue(spec.getReleaseDate().isAfter(LocalDate.of(2021, 2, 24)));
    assertNotNull(spec.getStatus());
  }

  @Test
  public void implementationPropertiesAreSet() {
    final Implementation impl = versionInfo.getImplementation();
    assertTrue(impl.getSourceCodeUrl().toExternalForm().startsWith("https://"));
    assertTrue(impl.getVersion().matches("^\\d+\\.\\d+\\.\\d+(-.*)?"));
    assertTrue(
        impl.getGitCommit().matches("^[a-f0-9]{40}$") || impl.getGitCommit().equals("UNKNOWN"));
  }

  @Test
  public void majorVersionIsUnknownOrAtLeast1() {
    final String version = versionInfo.getImplementation().getVersion();
    if (!"0.1.0-SNAPSHOT".equals(version)) {
      String[] splits = version.split("\\.");
      final int majorVersion = Integer.parseInt(splits[0]);
      assertTrue(majorVersion >= 1);
    }
  }
}
