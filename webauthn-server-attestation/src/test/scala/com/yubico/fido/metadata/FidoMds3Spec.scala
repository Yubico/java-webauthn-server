package com.yubico.fido.metadata

import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.tags.Network
import org.scalatest.tags.Slow
import org.scalatestplus.junit.JUnitRunner

@Slow
@Network
@RunWith(classOf[JUnitRunner])
class FidoMds3Spec extends FunSpec with Matchers {

  describe("§3.2. Metadata BLOB object processing rules") {
    describe("8. Iterate through the individual entries (of type MetadataBLOBPayloadEntry). For each entry:") {
      ignore("1. Ignore the entry if the AAID, AAGUID or attestationCertificateKeyIdentifiers is not relevant to the relying party (e.g. not acceptable by any policy)") {
        fail("Test not implemented.")
      }

      describe("2.1. Check whether the status report of the authenticator model has changed compared to the cached entry by looking at the fields timeOfLastStatusChange and statusReport.") {
        it("Nothing to test - cache is implemented on the metadata BLOB as a whole.") {}
      }

      describe("2.2. Update the status of the cached entry. It is up to the relying party to specify behavior for authenticators with status reports that indicate a lack of certification, or known security issues. However, the status REVOKED indicates significant security issues related to such authenticators.") {
        it("Nothing to test for caching - cache is implemented on the metadata BLOB as a whole.") {}

        ignore("REVOKED authenticators are untrusted by default") {
          fail("Test not implemented.")
        }
      }

      describe("2.3. Note: Authenticators with an unacceptable status should be marked accordingly. This information is required for building registration and authentication policies included in the registration request and the authentication request [UAFProtocol].") {
        it("Nothing to test - status processing is left for library users to implement.") {}
      }

      describe("3. Update the cached metadata statement.") {
        it("Nothing to test - cache is implemented on the metadata BLOB as a whole.") {}
      }
    }
  }

}
