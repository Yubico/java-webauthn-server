package com.yubico.webauthn.impl

import java.security.Signature
import java.security.cert.X509Certificate
import java.util.Locale

import com.upokecenter.cbor.CBORObject
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.webauthn.AttestationStatementVerifier
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.Basic
import com.yubico.webauthn.data.Ecdaa
import com.yubico.webauthn.data.SelfAttestation
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import javax.naming.ldap.LdapName
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DEROctetString

import scala.collection.JavaConverters._
import scala.util.Try


object PackedAttestationStatementVerifier extends AttestationStatementVerifier with X5cAttestationStatementVerifier {

  override def getAttestationType(attestation: AttestationObject): AttestationType =
    if (attestation.attestationStatement.hasNonNull("x5c"))
      Basic // TODO or Privacy CA
    else if (attestation.attestationStatement.hasNonNull("ecdaaKeyId"))
      Ecdaa
    else
      SelfAttestation

  private[webauthn] def _verifyAttestationSignature(attestationObject: AttestationObject, clientDataJsonHash: ArrayBuffer): Try[Boolean] =
    Try(verifyAttestationSignature(attestationObject, clientDataJsonHash))

  override def verifyAttestationSignature(attestationObject: AttestationObject, clientDataJsonHash: ArrayBuffer): Boolean = {
    val signatureNode = attestationObject.attestationStatement.get("sig")
    assert(
      signatureNode != null && signatureNode.isBinary,
      "attStmt.sig must be set to a binary value."
    )

    if (attestationObject.attestationStatement.has("x5c"))
      verifyX5cSignature(attestationObject, clientDataJsonHash)
    else if (attestationObject.attestationStatement.has("ecdaaKeyId"))
      verifyEcdaaSignature(attestationObject, clientDataJsonHash)
    else
      verifySelfAttestationSignature(attestationObject, clientDataJsonHash)
  }

  private def verifyEcdaaSignature(attestationObject: AttestationObject, clientDataJsonHash: ArrayBuffer): Boolean = ???

  private def verifySelfAttestationSignature(attestationObject: AttestationObject, clientDataJsonHash: ArrayBuffer): Boolean = {
    val pubkey = attestationObject.authenticatorData.attestationData.get.parsedCredentialPublicKey

    val keyAlg: COSEAlgorithmIdentifier = CBORObject.DecodeFromBytes(attestationObject.authenticatorData.attestationData.get.credentialPublicKey.toArray).get(CBORObject.FromObject(3)).AsInt64
    val sigAlg: COSEAlgorithmIdentifier = attestationObject.attestationStatement.get("alg").asLong

    assert(keyAlg == sigAlg, s"Key algorithm and signature algorithm must be equal, was: Key: ${keyAlg}, Sig: ${sigAlg}")

    val signedData: ArrayBuffer = attestationObject.authenticatorData.authData ++ clientDataJsonHash
    val signature = attestationObject.attestationStatement.get("sig").binaryValue.toVector
    Try(new BouncyCastleCrypto().checkSignature(pubkey, signedData.toArray, signature.toArray)).isSuccess
  }

  private[webauthn] def _verifyX5cSignature(attestationObject: AttestationObject, clientDataHash: ArrayBuffer): Try[Boolean] =
    Try(verifyX5cSignature(attestationObject, clientDataHash))

  private def verifyX5cSignature(attestationObject: AttestationObject, clientDataHash: ArrayBuffer): Boolean =
    getX5cAttestationCertificate(attestationObject) match {
      case Some(attestationCertificate) => {
        attestationObject.attestationStatement.get("sig") match {
          case null =>
            throw new IllegalArgumentException("""Packed attestation statement must have field "sig".""")

          case signatureNode if signatureNode.isBinary => {
            val signature: ArrayBuffer = signatureNode.binaryValue.toVector
            val signedData: ArrayBuffer = attestationObject.authenticatorData.authData ++ clientDataHash

            val ecdsaSignature: Signature = Signature.getInstance("SHA256withECDSA") // TODO support other signature algorithms
            ecdsaSignature.initVerify(attestationCertificate.getPublicKey)
            ecdsaSignature.update(signedData.toArray)

            (ecdsaSignature.verify(signature.toArray)
              && verifyX5cRequirements(attestationCertificate, attestationObject.authenticatorData.attestationData.get.aaguid)
            )
          }

          case _ =>
            throw new IllegalArgumentException("""Field "sig" in packed attestation statement must be a binary value.""")
        }
      }

      case _ => throw new IllegalArgumentException(
        """If "x5c" property is present in "packed" attestation format it must be an array containing at least one DER encoded X.509 cerficicate."""
      )
    }

  private[webauthn] def _verifyX5cRequirements(cert: X509Certificate, aaguid: ArrayBuffer = Vector()): Try[Boolean] =
    Try(verifyX5cRequirements(cert, aaguid))

  private def getDnField(field: String, cert: X509Certificate): Option[AnyRef] = {
    val ldap: LdapName = new LdapName(cert.getSubjectX500Principal.getName)
    ldap.getRdns.asScala
      .find(_.getType == field)
      .map(_.getValue)
  }

  private def verifyX5cRequirements(cert: X509Certificate, aaguid: ArrayBuffer): Boolean = {
    assert(cert.getVersion == 3, s"Wrong attestation certificate X509 version: ${cert.getVersion}, expected: 3")

    val ouValue = "Authenticator Attestation"
    val idFidoGenCeAaguid = "1.3.6.1.4.1.45724.1.1.4"

    assert(getDnField("C", cert) exists { Locale.getISOCountries contains _ }, s"Invalid attestation certificate country code: ${getDnField("C", cert)}")
    assert(getDnField("O", cert) exists { _ != "" }, "Organization (O) field of attestation certificate DN must be present.")
    assert(getDnField("OU", cert) contains ouValue, s"""Organization Unit (OU) field of attestation certificate DN must be exactly "${ouValue}", was: ${getDnField("OU", cert)}""")

    Option(cert.getExtensionValue(idFidoGenCeAaguid))
      .map { ext =>
        ASN1Primitive.fromByteArray(
          ASN1Primitive.fromByteArray(ext)
          .asInstanceOf[DEROctetString]
          .getOctets
        )
          .asInstanceOf[DEROctetString]
          .getOctets
      }
      .foreach { value: Array[Byte] =>
        assert(value.toVector == aaguid, s"X.509 extension ${idFidoGenCeAaguid} (id-fido-gen-ce-aaguid) is present but does not match the authenticator AAGUID.")
      }

    assert(cert.getBasicConstraints == -1, "Attestation certificate must not be a CA certificate.")

    true
  }

}
