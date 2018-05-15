package com.yubico.webauthn

import java.net.URL
import java.time.LocalDate
import java.util.Optional

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.JsonSerializer
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonSerialize


private class LocalDateJsonSerializer extends JsonSerializer[LocalDate] {
  override def serialize(t: LocalDate, jsonGenerator: JsonGenerator, serializerProvider: SerializerProvider): Unit = {
    jsonGenerator.writeString(t.toString)
  }
}

/**
  * Description of this version of this library
  *
  * @param version The version number of this release of the library.
  * @param sourceCodeUrl Address to where the source code for this library can be found.
  */
case class Implementation(
  version: Optional[String],
  sourceCodeUrl: URL
)

/**
  * Reference to a particular version of a specification document.
  *
  * @param url Address to this version of the specification.
  * @param latestVersionUrl Address to the latest version of this specification.
  * @param status An object indicating the status of the specification document.
  * @param releaseDate The release date of the specification document.
  */
case class Specification(
  url: URL,
  latestVersionUrl: URL,
  status: DocumentStatus,
  @JsonSerialize(using = classOf[LocalDateJsonSerializer])
  releaseDate: LocalDate
)

/**
  * Contains version information for the com.yubico.webauthn package.
  *
  * @see [[Specification]]
  */
object VersionInfo {

  /**
    * Represents the specification this implementation is based on
    */
  val specification = Specification(
    url = new URL("https://www.w3.org/TR/2018/CR-webauthn-20180320/"),
    latestVersionUrl = new URL("https://www.w3.org/TR/webauthn/"),
    status = DocumentStatus.CANDIDATE_RECOMMENDATION,
    releaseDate = LocalDate.parse("2018-03-20")
  )

  /**
    * Represents the specification this implementation is based on
    */
  val implementation = Implementation(
    version = findImplementationVersionInManifest(),
    sourceCodeUrl = new URL("https://github.com/Yubico/java-webauthn-server")
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
