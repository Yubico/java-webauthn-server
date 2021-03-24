package com.yubico.webauthn.meta;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.yubico.webauthn.RelyingParty;
import java.io.IOException;
import java.net.URL;
import java.time.LocalDate;
import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.util.jar.Manifest;
import org.junit.Test;

public class ManifestInfoTest {

  private static String lookup(String key) throws IOException {
    final Enumeration<URL> resources =
        RelyingParty.class.getClassLoader().getResources("META-INF/MANIFEST.MF");

    while (resources.hasMoreElements()) {
      final URL resource = resources.nextElement();
      final Manifest manifest = new Manifest(resource.openStream());
      if ("java-webauthn-server"
          .equals(manifest.getMainAttributes().getValue("Implementation-Id"))) {
        return manifest.getMainAttributes().getValue(key);
      }
    }
    throw new NoSuchElementException("Could not find \"" + key + "\" in manifest.");
  }

  @Test
  public void standardSpecPropertiesAreSet() throws IOException {
    assertTrue(lookup("Specification-Title").startsWith("Web Authentication"));
    assertTrue(lookup("Specification-Version").startsWith("Level"));
    assertEquals("World Wide Web Consortium", lookup("Specification-Vendor"));
  }

  @Test
  public void customSpecPropertiesAreSet() throws IOException {
    assertTrue(lookup("Specification-Url").startsWith("https://"));
    assertTrue(lookup("Specification-Url-Latest").startsWith("https://"));
    assertTrue(DocumentStatus.fromString(lookup("Specification-W3c-Status")).isPresent());
    assertTrue(
        LocalDate.parse(lookup("Specification-Release-Date")).isAfter(LocalDate.of(2019, 3, 3)));
  }

  @Test
  public void standardImplementationPropertiesAreSet() throws IOException {
    assertTrue(lookup("Implementation-Title").contains("Web Authentication"));
    assertTrue(lookup("Implementation-Version").matches("^\\d+\\.\\d+\\.\\d+(-.*)?"));
    assertEquals("Yubico", lookup("Implementation-Vendor"));
  }

  @Test
  public void customImplementationPropertiesAreSet() throws IOException {
    assertTrue(lookup("Git-Commit").matches("^[a-f0-9]{40}$"));
  }
}
