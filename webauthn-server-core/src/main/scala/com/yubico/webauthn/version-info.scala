package com.yubico.webauthn

import java.net.URL
import java.time.LocalDate

sealed trait DocumentStatus
case object WorkingDraft extends DocumentStatus
case object CandidateRelease extends DocumentStatus

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
    status = CandidateRelease,
    releaseDate = LocalDate.parse("2018-03-20")
  )

}
