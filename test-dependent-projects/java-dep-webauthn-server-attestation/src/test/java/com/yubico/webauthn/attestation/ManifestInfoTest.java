package com.yubico.webauthn.attestation;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.util.jar.Manifest;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ManifestInfoTest {

    private static String lookup(String key) throws IOException {
        final Enumeration<URL> resources = AttestationResolver.class.getClassLoader().getResources("META-INF/MANIFEST.MF");

        while (resources.hasMoreElements()) {
            final URL resource = resources.nextElement();
            final Manifest manifest = new Manifest(resource.openStream());
            if ("java-webauthn-server-attestation".equals(manifest.getMainAttributes().getValue("Implementation-Id"))) {
                return manifest.getMainAttributes().getValue(key);
            }
        }
        throw new NoSuchElementException("Could not find \"" + key + "\" in manifest.");
    }

    @Test
    public void standardImplementationPropertiesAreSet() throws IOException {
        assertTrue(lookup("Implementation-Title").contains("attestation"));
        assertTrue(lookup("Implementation-Version").matches("^\\d+\\.\\d+\\.\\d+(-.*)?"));
        assertEquals("Yubico", lookup("Implementation-Vendor"));
    }

}
