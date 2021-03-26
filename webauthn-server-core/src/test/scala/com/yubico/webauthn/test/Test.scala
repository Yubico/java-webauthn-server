// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn.test

import COSE.OneKey
import com.fasterxml.jackson.databind.JsonNode
import com.upokecenter.cbor.CBORObject
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.RegistrationTestData
import com.yubico.webauthn.WebAuthnTestCodecs
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.AuthenticatorDataFlags
import com.yubico.webauthn.data.ByteArray
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.util.ASN1Dump

import java.security.interfaces.ECPublicKey
import java.util.Base64
import scala.jdk.CollectionConverters._

object Test extends App {

  // val attestationObject: ByteArray = ByteArray.fromBase64Url("o2NmbXRmcGFja2VkaGF1dGhEYXRhWLhsce9f2O4QMCXrg1cu1lwknOxtXBryURzsRWDk8tD7pkEAAAAAAAAAAAAAAAAAAAAAAAAAAABAawIjwBjPgvsbJe-gqVwMFEQeZ0zTgj93jw3fFdOTLTshl3F2qwb6O35qI520Iw53fXcsNMoFWL767oiSpHB4ggQ0PVe2C-FLegMiA73oT8Tbd-R7wB7HOrYY5FOQdmCN2aGm5dT2RrmsRHq_EhEUF6L_X4aY2zIkXH7-UlI0MtQMZ2F0dFN0bXSjY2FsZ2VFUzI1NmNzaWdYRzBFAiBgPH9xOEVrf3XqFbYkn78oHbBu-c8-0z0g6sT00MzcJAIhAJdwAJuhzS_SqJm8q8R--yc_YXj4VvNLlCVWnFlycIIXY3g1Y4FZAlMwggJPMIIBN6ADAgECAgQSNtF_MA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAxMS8wLQYDVQQDDCZZdWJpY28gVTJGIEVFIFNlcmlhbCAyMzkyNTczNDEwMzI0MTA4NzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNNlqR5emeDVtDnA2a-7h_QFjkfdErFE7bFNKzP401wVE-QNefD5maviNnGVk4HJ3CsHhYuCrGNHYgTM9zTWriGjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMA0GCSqGSIb3DQEBCwUAA4IBAQAiG5uzsnIk8T6-oyLwNR6vRklmo29yaYV8jiP55QW1UnXdTkEiPn8mEQkUac-Sn6UmPmzHdoGySG2q9B-xz6voVQjxP2dQ9sgbKd5gG15yCLv6ZHblZKkdfWSrUkrQTrtaziGLFSbxcfh83vUjmOhDLFC5vxV4GXq2674yq9F2kzg4nCS4yXrO4_G8YWR2yvQvE2ffKSjQJlXGO5080Ktptplv5XN4i5lS-AKrT5QRVbEJ3B4g7G0lQhdYV-6r4ZtHil8mF4YNMZ0-RaYPxAaYNWkFYdzOZCaIdQbXRZefgGfbMUiAC2gwWN7fiPHV9eu82NYypGU32OijG9BjhGt_")
  // val attestationObject: ByteArray = ByteArray.fromBase64Url("o2hhdXRoRGF0YVjKbHHvX9juEDAl64NXLtZcJJzsbVwa8lEc7EVg5PLQ-6ZBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOiUTsFEO0Ng5k3_k2diNEWJw8PDfXUMm9dPQ6piFAgN2ZqYXc2edf-nm9qYcznSHZ7My05HRWC8b15UdtpNYHWjY2FsZ2VFUzI1NmF4WCDS7Esl2DRo9RpWifrwLuAwCx-x5JN5Vl5RNla0xeBf0mF5WCDXSTYlDGlsKid4rRm6wi6NY5FDLiCOXJQpzkC8l2guKGNmbXRoZmlkby11MmZnYXR0U3RtdKJjeDVjgVkCUzCCAk8wggE3oAMCAQICBCrZavMwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMDExLzAtBgNVBAMMJll1YmljbyBVMkYgRUUgU2VyaWFsIDIzOTI1NzM0NTE2NTUwMzg3MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEL-GiPr-lWz5GHVmkNSLXl0iYHLptKJqY8b19_2VmgNu77bwrrmB-bvdy9XawTVTE5fMvWW8m5hEVxycs9sp1lKM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjIwEwYLKwYBBAGC5RwCAQEEBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAIVq-ovPTz9iXykbwRWOPH69JVK891cHU_USHaalTSTMz64nztarMRKMKX5bW4kF3aAgF5MfH19ZJZNZUfwAS8viCt19jQUvlUOzSWwVuDEOEMvZuwU4J09YPq0fRRKIw-p20HCtROU6_qjyLR9zYl_y1Yn-MN8mYst8u3yZYYCtz6mKTQEs8xNGzRF0alhI6L7t8-MMy9nB3SIWcbKDiGH2WkU2I7UY1VZ_qPCjzhBd9PE5U-EU6lngp_L-ZohnQy5S_WovZPc8SM2bOPLfuix6SzsRKN8m1mok-JXdoLYRgPQUT2twdcMYpJrgi1jTatseMFNnKxfFoZ9_CiLxDpRjc2lnWEcwRQIhAOdPkMJhSa5IQ8nOA4BYUjYMA6d5WGEA3sDuEBnkXxm6AiAJ_vfKhJdC5WGcMxZfgnz4I9JJ_-D-VHSHljEvDyUS7w")

  // println(JacksonCodecs.cbor.readTree(attestationObject.getBytes))

  // val attObj = JacksonCodecs.cbor.readTree(attestationObject.getBytes)

  // println(attObj.get("authData").getNodeType)
  // println(attObj.get("fmt").getNodeType)
  // println(attObj.get("attStmt").getNodeType)

  // val attStmt = attObj.get("attStmt")

  // println(attStmt)
  // println(attStmt.fieldNames)

  // println(attStmt.get("x5c").getNodeType)
  // println(attStmt.get("x5c"))

  // println(attStmt.get("x5c").get(0).getNodeType)
  // println(attStmt.get("x5c").get(0).isBinary)
  // println(attStmt.get("x5c").get(0))

  runWith(RegistrationTestData.AndroidSafetynet.RealExample.attestationObject)

  val attestationObjectFirefox58 =
    ByteArray.fromBase64Url("o2hhdXRoRGF0YVjKlJKaCrOPLCdHaydNzfSylZWY-KV_PzorqW39Kb9p5mdBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAixHvZmRdDp0DhMTCfB9dHQF9frTlVXNqXGJ3tGfVV0hR6mIk9ioAbK4AK9VkoxdIE04kjemwBHc5Yaz8BrZ9ujY2FsZ2VFUzI1NmF4WCD7ESIYejaHqAg9C9hTMy1hQafvKmy1KIuXW6Artariq2F5WCCpWfXbnYPAUpTL18oD9A_BUFR7z9IhodehhSYlN_Y2mWNmbXRoZmlkby11MmZnYXR0U3RtdKJjeDVjgVkCTjCCAkowggEyoAMCAQICBFcW98AwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCwxKjAoBgNVBAMMIVl1YmljbyBVMkYgRUUgU2VyaWFsIDI1MDU2OTIyNjE3NjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGTZHFTW2VeN07BgeExGNtVIo5g6rzUnzustxuMrZ54z_OnoYxStvPhXUhsvTEmflK9wVWW-IhlbKbZOTa0N0GKjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMA0GCSqGSIb3DQEBCwUAA4IBAQB4mxjKm6TbdiDi-IuM_elRJm0qInfV4_vptoyaoOkaakjqdUzvC95ZhANtrn-Lo_3mS1F2BMOhGy5tdU1KNxnvqHaTD6Dg8wY_WkygvKAxT38Fo-pdTt2R00pmtV1cj6huAOe_X92AI36z24I-NOMSZ7NJqsecJKcSpZ6ASqqNa6klJqJ3p3HeMWpzvzxxH8VNImYn-teV5PROG3ADTwn8_ji33il4k_tZrIscM8_Fxr5djkzCf0ofRvb4RPh4wHKL3B37pnHaEIf1jOOOWWuj8p_QWUFdxQqjL4kUfNPbCAE31OZbvOsLv-VBiBiOzBQxGHlRkqs6c4eppXJ_EEiGY3NpZ1hHMEUCIEMdeuTafyyaQFAjrZv0ANFt6mHzqjABJBwtUPFfbU0BAiEAvHJuqQCMUoNErDJFR928WnJnykwmoEi5XxdvsjtbDIw")
  // val attestationObjectFirefoxNightly = ByteArray.fromBase64Url("o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAMN34Lky1H00Yio4AJcCVh-cIbw__8fOgVPacfZqQMtSAiAHLWI6GKHAi7pmRMEljNuWBq_BHrKObzzzui9Duqmo7GN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxJSSmgqzjywnR2snTc30spWVmPilfz86K6lt_Sm_aeZnQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEBsMp3vlrdYz8qUyb6o0J9M9l7FLS6XI70p9Txx0LIDuG87doFwc-9Tu6pW0njfyIISSif4kXZkF87vrgCcDp3UpQECAyYgASFYIKjQ7ovDDFsXm-I3q1vX8WUtU2CQ5IwX0cPfgR1KxBZLIlggQR9CYSfpMsRLoL9Y1ADVV_rKHMStoipUywjOct0g7cA")
  val attestationObjectFirefoxNightly = new ByteArray(
    Base64.getMimeDecoder.decode("o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAMN34Lky1H00Yio4AJcCVh+cIbw//8fOgVPacfZqQMtSAiAHLWI6GKHAi7pmRMEljNuWBq/BHrKObzzzui9Duqmo7GN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28+FdSGy9MSZ+Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj++m2jJqg6RpqSOp1TO8L3lmEA22uf4uj/eZLUXYEw6EbLm11TUo3Ge+odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO/PHEfxU0iZif615Xk9E4bcANPCfz+OLfeKXiT+1msixwzz8XGvl2OTMJ/Sh9G9vhE+HjAcovcHfumcdoQh/WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu/5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxJSSmgqzjywnR2snTc30spWVmPilfz86K6lt/Sm/aeZnQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEBsMp3vlrdYz8qUyb6o0J9M9l7FLS6XI70p9Txx0LIDuG87doFwc+9Tu6pW0njfyIISSif4kXZkF87vrgCcDp3UpQECAyYgASFYIKjQ7ovDDFsXm+I3q1vX8WUtU2CQ5IwX0cPfgR1KxBZLIlggQR9CYSfpMsRLoL9Y1ADVV/rKHMStoipUywjOct0g7cA=")
  )

  runWith(attestationObjectFirefoxNightly)

  def runWith(attestationObject: ByteArray): Unit = {
    println(attestationObject)
    println(attestationObject.getHex)

    val parsedAttObj = new AttestationObject(attestationObject)
    println(parsedAttObj)
    println(parsedAttObj.getAuthenticatorData.getBytes.getHex)
    println(
      WebAuthnTestCodecs.importCosePublicKey(
        parsedAttObj.getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
      )
    )

    val attestationObjectCbor =
      JacksonCodecs.cbor.readTree(attestationObject.getBytes)
    println(attestationObjectCbor)
    println(attestationObjectCbor.get("authData"))

    val authDataBytes: ByteArray = new ByteArray(
      attestationObjectCbor.get("authData").binaryValue
    )
    println(authDataBytes)

    doAuthData(authDataBytes)

    println("Manually extracted public key:")
    val manuallyExtractedPubKeyBytes = new ByteArray(
      attestationObject.getBytes.drop(32 + 1 + 4 + 16 + 2 + 64)
    )
    println(manuallyExtractedPubKeyBytes)
    println(JacksonCodecs.cbor.readTree(manuallyExtractedPubKeyBytes.getBytes))

    println("Attestation statement:")
    println(parsedAttObj.getAttestationStatement)

    if (parsedAttObj.getFormat == "android-safetynet") {
      println("Attestation statement \"response\" field:")
      println(
        parsedAttObj.getAttestationStatement
          .get("response")
          .binaryValue
          .toVector
      )
      val safetynetJwsCompact = new String(
        parsedAttObj.getAttestationStatement.get("response").binaryValue,
        "UTF-8",
      )

      println(safetynetJwsCompact)

      println(safetynetJwsCompact.split('.').toVector)
      val Array(jwsHeaderBase64, jwsPayloadBase64, jwsSigBase64) =
        safetynetJwsCompact.split('.')

      println(ByteArray.fromBase64Url(jwsHeaderBase64))
      println(
        prettifyJson(
          new String(ByteArray.fromBase64Url(jwsHeaderBase64).getBytes, "UTF-8")
        )
      )
      for {
        x5cNode: JsonNode <-
          JacksonCodecs
            .json()
            .readTree(ByteArray.fromBase64Url(jwsHeaderBase64).getBytes)
            .get("x5c")
            .elements()
            .asScala
      } {
        val x5cBytes = ByteArray.fromBase64(x5cNode.textValue())
        val cert = CertificateParser.parseDer(x5cBytes.getBytes)
        println(cert)
      }

      println(ByteArray.fromBase64Url(jwsPayloadBase64))
      println(
        prettifyJson(
          new String(
            ByteArray.fromBase64Url(jwsPayloadBase64).getBytes,
            "UTF-8",
          )
        )
      )
      println(ByteArray.fromBase64Url(jwsSigBase64))
    }

    println()
    println()
  }

  def prettifyJson(json: String): String =
    JacksonCodecs
      .json()
      .writerWithDefaultPrettyPrinter()
      .writeValueAsString(JacksonCodecs.json().readTree(json))

  def doAuthData(authDataBytes: ByteArray) = {
    val rpidBytes: Array[Byte] = authDataBytes.getBytes.slice(0, 32)
    val flagsByte: Byte = authDataBytes.getBytes()(32)
    val flags = new AuthenticatorDataFlags(flagsByte)
    val counterBytes: Array[Byte] =
      authDataBytes.getBytes.slice(32 + 1, 32 + 1 + 4)
    val attestedCredData: Array[Byte] = authDataBytes.getBytes.drop(32 + 1 + 4)

    println("Authenticator data:")
    println(s"RP ID: ${rpidBytes}")
    println(s"flags: ${flagsByte.toBinaryString}")
    println(s"flags: AT=${flags.AT}, ED=${flags.ED}")
    println(s"counter: ${BinaryUtil.getUint32(counterBytes)}")

    val aaguid = attestedCredData.slice(0, 16)
    val Lbytes = attestedCredData.slice(16, 16 + 2)
    val L = BinaryUtil.getUint16(Lbytes)
    val credentialIdBytes = attestedCredData.slice(16 + 2, 16 + 2 + L)
    val credentialPublicKeyBytes = attestedCredData.drop(16 + 2 + L)
    val credentialPublicKeyCbor =
      JacksonCodecs.cbor.readTree(credentialPublicKeyBytes)
    val credentialPublicKeyCbor2 =
      CBORObject.DecodeFromBytes(credentialPublicKeyBytes)
    val credentialPublicKeyDecoded: ECPublicKey = new OneKey(
      CBORObject.DecodeFromBytes(credentialPublicKeyBytes)
    ).AsPublicKey().asInstanceOf[ECPublicKey]

    println("Attested credential data:")
    println(s"AAGUID: ${aaguid}")
    println(s"Lbytes: ${Lbytes}")
    println(s"L: ${L}")
    println(s"credentialId: ${BinaryUtil.toHex(credentialIdBytes)}")
    println(
      s"credentialPublicKeyBytes: ${BinaryUtil.toHex(credentialPublicKeyBytes)}"
    )
    println(
      s"credentialPublicKeyBytes length: ${credentialPublicKeyBytes.length}"
    )
    println(s"credentialPublicKeyCbor: ${credentialPublicKeyCbor}")
    println(s"credentialPublicKeyCbor2: ${credentialPublicKeyCbor2}")
    println(s"credentialPublicKeyDecoded: ${credentialPublicKeyDecoded}")
    println(s"raw credential public key: ${WebAuthnTestCodecs.ecPublicKeyToRaw(credentialPublicKeyDecoded)}")
    println(s"raw credential public key: ${WebAuthnTestCodecs.ecPublicKeyToRaw(credentialPublicKeyDecoded).getHex}")
    println(s"raw credential public key length: ${WebAuthnTestCodecs.ecPublicKeyToRaw(credentialPublicKeyDecoded).getBytes.length}")

    // asn1dump(credentialPublicKeyBytes)
  }

  def asn1dump(bytes: ByteArray) = {
    val input = new ASN1InputStream(bytes.getBytes)
    var p: ASN1Primitive = null
    p = input.readObject()
    while (p != null) {
      println(ASN1Dump.dumpAsString(p))
      p = input.readObject()
    }
  }

  // doAuthData(authDataBytes)
  val cbormeAuthDataBytes =
    ByteArray.fromHex("94929A0AB38F2C27476B274DCDF4B2959598F8A57F3F3A2BA96DFD29BF69E66741000000000000000000000000000000000000000000406C329DEF96B758CFCA94C9BEA8D09F4CF65EC52D2E9723BD29F53C71D0B203B86F3B76817073EF53BBAA56D278DFC882124A27F891766417CEEFAE009C0E9DD4A5010203262001215820A8D0EE8BC30C5B179BE237AB5BD7F1652D536090E48C17D1C3DF811D4AC4164B225820411F426127E932C44BA0BF58D400D557FACA1CC4ADA22A54CB08CE72DD20EDC0")
  // val cbormeAuthDataBytes = ByteArray.fromHex("94929A0AB38F2C27476B274DCDF4B2959598F8A57F3F3A2BA96DFD29BF69E667410000000000000000000000000000000000000000004008B11EF66645D0E9D0384C4C27C1F5D1D017D7EB4E555736A5C6277B467D5574851EA6224F62A006CAE002BD564A31748134E248DE9B004773961ACFC06B67DBA363616C6765455332353661785820FB1122187A3687A8083D0BD853332D6141A7EF2A6CB5288B975BA02BB5AAE2AB61795820A959F5DB9D83C05294CBD7CA03F40FC150547BCFD221A1D7A185262537F63699")
  doAuthData(cbormeAuthDataBytes)

  // val parsedAuthData = AuthenticatorData(authDataBytes)
  // println(parsedAuthData)
  // println(parsedAuthData.attestedCredentialData)
  // println(parsedAuthData.attestedCredentialData.get)
  // println(parsedAuthData.attestedCredentialData.get.credentialPublicKey)

}
