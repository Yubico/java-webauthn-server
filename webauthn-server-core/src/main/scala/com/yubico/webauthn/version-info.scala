package com.yubico.webauthn

import java.net.URL
import java.time.LocalDate
import java.util.Optional

import com.yubico.webauthn.meta.Implementation
import com.yubico.webauthn.meta.Specification








/**
  * Contains version information for the com.yubico.webauthn package.
  *
  * @see [[Specification]]
  */
object VersionInfo {

  /**
    * Represents the specification this implementation is based on
    */
  val specification = Specification.builder()
    .url(new URL("https://www.w3.org/TR/2018/CR-webauthn-20180320/"))
    .latestVersionUrl(new URL("https://www.w3.org/TR/webauthn/"))
    .status(DocumentStatus.CANDIDATE_RECOMMENDATION)
    .releaseDate(LocalDate.parse("2018-03-20"))
    .build()

  /**
    * Represents the specification this implementation is based on
    */
  val implementation = new Implementation(
    findImplementationVersionInManifest(),
    new URL("https://github.com/Yubico/java-webauthn-server")
  )

  private def findImplementationVersionInManifest(): Optional[String] = {
    val resources = getClass.getClassLoader.getResources("META-INF/MANIFEST.MF")

    while (resources.hasMoreElements) {
      val resource = resources.nextElement()
      val manifest = new java.util.jar.Manifest(resource.openStream())
      if (manifest.getMainAttributes.getValue("Implementation-Id") == "java-webauthn-server") {
        return Optional.ofNullable(manifest.getMainAttributes.getValue("Implementation-Version"))
      }
    }

    return Optional.empty()
  }

}
