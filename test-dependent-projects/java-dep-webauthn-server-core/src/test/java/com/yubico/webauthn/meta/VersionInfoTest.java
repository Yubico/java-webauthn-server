package com.yubico.webauthn.meta;

import java.time.LocalDate;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Since this depends on the manifest of the core jar, and the manifest is build by Gradle, this test is likely to fail
 * when run in an IDE. It works as expected when run via Gradle.
 */
public class VersionInfoTest {

    final VersionInfo versionInfo = VersionInfo.getInstance();

    @Test
    public void specPropertiesAreSet() {
        final Specification spec = versionInfo.getSpecification();
        assertTrue(spec.getLatestVersionUrl().toExternalForm().startsWith("https://"));
        assertTrue(spec.getUrl().toExternalForm().startsWith("https://"));
        assertTrue(spec.getReleaseDate().isAfter(LocalDate.of(2019, 3, 3)));
        assertNotNull(spec.getStatus());
    }

    @Test
    public void implementationPropertiesAreSet() {
        final Implementation impl = versionInfo.getImplementation();
        assertTrue(impl.getSourceCodeUrl().toExternalForm().startsWith("https://"));
        assertTrue(impl.getVersion().get().matches("^\\d+\\.\\d+\\.\\d+(-.*)?"));
    }

    @Test
    public void majorVersionIsAtLeast1() {
        final String version = versionInfo.getImplementation().getVersion().get();
        String[] splits = version.split("\\.");
        final int majorVersion = Integer.parseInt(splits[0]);
        assertTrue(majorVersion >= 1);
    }

}
