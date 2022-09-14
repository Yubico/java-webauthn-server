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

package com.yubico.webauthn;

import COSE.CoseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import com.yubico.internal.util.BinaryUtil;
import com.yubico.internal.util.ByteInputStream;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

@Slf4j
final class TpmAttestationStatementVerifier
    implements AttestationStatementVerifier, X5cAttestationStatementVerifier {

  private static final String TPM_VER = "2.0";
  static final ByteArray TPM_GENERATED_VALUE = ByteArray.fromBase64("/1RDRw==");
  static final ByteArray TPM_ST_ATTEST_CERTIFY = ByteArray.fromBase64("gBc=");

  static final int TPM_ALG_NULL = 0x0010;

  private static final String OID_TCG_AT_TPM_MANUFACTURER = "2.23.133.2.1";
  private static final String OID_TCG_AT_TPM_MODEL = "2.23.133.2.2";
  private static final String OID_TCG_AT_TPM_VERSION = "2.23.133.2.3";

  /**
   * Object attributes
   *
   * <p>see section 8.3 of
   * https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
   */
  static final class Attributes {
    static final int SIGN_ENCRYPT = 1 << 18;

    private static final int SHALL_BE_ZERO =
        (1 << 0) // 0 Reserved
            | (1 << 3) // 3 Reserved
            | (0x3 << 8) // 9:8 Reserved
            | (0xF << 12) // 15:12 Reserved
            | ((0xFFFFFFFF << 19) & ((1 << 32) - 1)) // 31:19 Reserved
        ;
  }

  @Override
  public AttestationType getAttestationType(AttestationObject attestation) {
    return AttestationType.ATTESTATION_CA;
  }

  @Override
  public boolean verifyAttestationSignature(
      AttestationObject attestationObject, ByteArray clientDataJsonHash) {

    // Step 1: Verify that attStmt is valid CBOR conforming to the syntax defined above and perform
    // CBOR decoding on it to extract the contained fields.

    ObjectNode attStmt = attestationObject.getAttestationStatement();

    JsonNode verNode = attStmt.get("ver");
    ExceptionUtil.assure(
        verNode != null && verNode.isTextual() && verNode.textValue().equals(TPM_VER),
        "attStmt.ver must equal \"%s\", was: %s",
        TPM_VER,
        verNode);

    JsonNode algNode = attStmt.get("alg");
    ExceptionUtil.assure(
        algNode != null && algNode.canConvertToLong(),
        "attStmt.alg must be set to an integer value, was: %s",
        algNode);
    final COSEAlgorithmIdentifier alg =
        COSEAlgorithmIdentifier.fromId(algNode.longValue())
            .orElseThrow(
                () ->
                    new IllegalArgumentException("Unknown COSE algorithm identifier: " + algNode));

    JsonNode x5cNode = attStmt.get("x5c");
    ExceptionUtil.assure(
        x5cNode != null && x5cNode.isArray(),
        "attStmt.x5c must be set to an array value, was: %s",
        x5cNode);
    final List<X509Certificate> x5c;
    try {
      x5c =
          getAttestationTrustPath(attestationObject)
              .orElseThrow(
                  () ->
                      new IllegalArgumentException(
                          "Failed to parse \"x5c\" attestation certificate chain in \"tpm\" attestation statement."));
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
    final X509Certificate aikCert = x5c.get(0);

    JsonNode sigNode = attStmt.get("sig");
    ExceptionUtil.assure(
        sigNode != null && sigNode.isBinary(),
        "attStmt.sig must be set to a binary value, was: %s",
        sigNode);
    final ByteArray sig;
    try {
      sig = new ByteArray(sigNode.binaryValue());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    JsonNode certInfoNode = attStmt.get("certInfo");
    ExceptionUtil.assure(
        certInfoNode != null && certInfoNode.isBinary(),
        "attStmt.certInfo must be set to a binary value, was: %s",
        certInfoNode);

    JsonNode pubAreaNode = attStmt.get("pubArea");
    ExceptionUtil.assure(
        pubAreaNode != null && pubAreaNode.isBinary(),
        "attStmt.pubArea must be set to a binary value, was: %s",
        pubAreaNode);

    final TpmtPublic pubArea;
    try {
      pubArea = TpmtPublic.parse(pubAreaNode.binaryValue());
    } catch (IOException e) {
      throw new RuntimeException("Failed to parse TPMT_PUBLIC data structure.", e);
    }

    final TpmsAttest certInfo;
    try {
      certInfo = TpmsAttest.parse(certInfoNode.binaryValue());
    } catch (IOException e) {
      throw new RuntimeException("Failed to parse TPMS_ATTEST data structure.", e);
    }

    // Step 2: Verify that the public key specified by the parameters and unique fields of pubArea
    // is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
    try {
      verifyPublicKeysMatch(attestationObject, pubArea);
    } catch (CoseException | IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new RuntimeException(
          "Failed to verify that public key in TPM attestation matches public key in authData.", e);
    }

    // Step 3: Concatenate authenticatorData and clientDataHash to form attToBeSigned.
    final ByteArray attToBeSigned =
        attestationObject.getAuthenticatorData().getBytes().concat(clientDataJsonHash);

    // Step 4: Validate that certInfo is valid:
    try {
      validateCertInfo(alg, aikCert, sig, pubArea, certInfo, attToBeSigned, attestationObject);
    } catch (CertificateParsingException e) {
      throw new RuntimeException("Failed to verify TPM attestation.", e);
    }

    return true;
  }

  private void validateCertInfo(
      COSEAlgorithmIdentifier alg,
      X509Certificate aikCert,
      ByteArray sig,
      TpmtPublic pubArea,
      TpmsAttest certInfo,
      ByteArray attToBeSigned,
      AttestationObject attestationObject)
      throws CertificateParsingException {
    // Sub-steps 1-2 handled in TpmsAttest.parse()
    // Sub-step 3: Verify that extraData is set to the hash of attToBeSigned using the hash
    // algorithm employed in "alg".
    final ByteArray expectedExtraData;
    switch (alg) {
      case ES256:
      case RS256:
        expectedExtraData = Crypto.sha256(attToBeSigned);
        break;

      case ES384:
        expectedExtraData = Crypto.sha384(attToBeSigned);
        break;

      case ES512:
        expectedExtraData = Crypto.sha512(attToBeSigned);
        break;

      case RS1:
        try {
          expectedExtraData = Crypto.sha1(attToBeSigned);
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException("Failed to hash attToBeSigned to verify TPM attestation.", e);
        }
        break;

      default:
        throw new UnsupportedOperationException("Signing algorithm not implemented: " + alg);
    }
    ExceptionUtil.assure(
        certInfo.extraData.equals(expectedExtraData), "Incorrect certInfo.extraData.");

    // Sub-step 4: Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in
    // [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea, as
    // computed using the algorithm in the nameAlg field of pubArea using the procedure specified in
    // [TPMv2-Part1] section 16.
    ExceptionUtil.assure(
        certInfo.attestedName.equals(pubArea.name()), "Incorrect certInfo.attestedName.");

    // Sub-step 5 handled by parsing above
    // Sub-step 6: Nothing to do

    // Sub-step 7: Verify the sig is a valid signature over certInfo using the attestation public
    // key in aikCert with the algorithm specified in alg.
    ExceptionUtil.assure(
        Crypto.verifySignature(aikCert, certInfo.getRawBytes(), sig, alg),
        "Incorrect TPM attestation signature.");

    // Sub-step 8: Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation Statement
    // Certificate Requirements.
    // Sub-step 9: If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4
    // (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in
    // authenticatorData.
    verifyX5cRequirements(
        aikCert,
        attestationObject.getAuthenticatorData().getAttestedCredentialData().get().getAaguid());
  }

  private void verifyPublicKeysMatch(AttestationObject attestationObject, TpmtPublic pubArea)
      throws CoseException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
    final PublicKey credentialPubKey =
        WebAuthnCodecs.importCosePublicKey(
            attestationObject
                .getAuthenticatorData()
                .getAttestedCredentialData()
                .get()
                .getCredentialPublicKey());

    final PublicKey signedCredentialPublicKey;
    switch (pubArea.signAlg) {
      case TpmAlgAsym.RSA:
        {
          TpmsRsaParms params = (TpmsRsaParms) pubArea.parameters;
          Tpm2bPublicKeyRsa unique = (Tpm2bPublicKeyRsa) pubArea.unique;
          RSAPublicKeySpec spec =
              new RSAPublicKeySpec(
                  new BigInteger(1, unique.bytes.getBytes()), BigInteger.valueOf(params.exponent));
          KeyFactory kf = KeyFactory.getInstance("RSA");
          signedCredentialPublicKey = kf.generatePublic(spec);
        }

        ExceptionUtil.assure(
            Arrays.equals(credentialPubKey.getEncoded(), signedCredentialPublicKey.getEncoded()),
            "Signed public key in TPM attestation is not identical to credential public key in authData.");
        break;

      case TpmAlgAsym.ECC:
        {
          TpmsEccParms params = (TpmsEccParms) pubArea.parameters;
          TpmsEccPoint unique = (TpmsEccPoint) pubArea.unique;

          final COSEAlgorithmIdentifier algId =
              COSEAlgorithmIdentifier.fromPublicKey(
                      attestationObject
                          .getAuthenticatorData()
                          .getAttestedCredentialData()
                          .get()
                          .getCredentialPublicKey())
                  .get();
          final COSEAlgorithmIdentifier tpmAlgId;
          final CBORObject cosePubkey =
              CBORObject.DecodeFromBytes(
                  attestationObject
                      .getAuthenticatorData()
                      .getAttestedCredentialData()
                      .get()
                      .getCredentialPublicKey()
                      .getBytes());

          switch (params.curve_id) {
            case TpmEccCurve.NIST_P256:
              tpmAlgId = COSEAlgorithmIdentifier.ES256;
              break;

            case TpmEccCurve.NIST_P384:
              tpmAlgId = COSEAlgorithmIdentifier.ES384;
              break;

            case TpmEccCurve.NIST_P521:
              tpmAlgId = COSEAlgorithmIdentifier.ES512;
              break;

            default:
              throw new UnsupportedOperationException(
                  "Unsupported elliptic curve: " + params.curve_id);
          }

          ExceptionUtil.assure(
              algId.equals(tpmAlgId),
              "Signed public key in TPM attestation is not identical to credential public key in authData; elliptic curve differs: %s != %s",
              tpmAlgId,
              algId);
          byte[] cosePubkeyX = cosePubkey.get(CBORObject.FromObject(-2)).GetByteString();
          byte[] cosePubkeyY = cosePubkey.get(CBORObject.FromObject(-3)).GetByteString();
          ExceptionUtil.assure(
              new BigInteger(1, unique.x.getBytes()).equals(new BigInteger(1, cosePubkeyX)),
              "Signed public key in TPM attestation is not identical to credential public key in authData; EC X coordinate differs: %s != %s",
              unique.x,
              new ByteArray(cosePubkeyX));
          ExceptionUtil.assure(
              new BigInteger(1, unique.y.getBytes()).equals(new BigInteger(1, cosePubkeyY)),
              "Signed public key in TPM attestation is not identical to credential public key in authData; EC Y coordinate differs: %s != %s",
              unique.y,
              new ByteArray(cosePubkeyY));
        }
        break;

      default:
        throw new UnsupportedOperationException(
            "Unsupported algorithm for credential public key: " + pubArea.signAlg);
    }
  }

  static final class TpmAlgAsym {
    static final int RSA = 0x0001;
    static final int ECC = 0x0023;
  }

  private interface Parameters {}

  private interface Unique {}

  @Value
  private static class TpmtPublic {
    int signAlg;
    int nameAlg;
    Parameters parameters;
    Unique unique;
    ByteArray rawBytes;

    private static TpmtPublic parse(byte[] pubArea) throws IOException {
      try (ByteInputStream reader = new ByteInputStream(pubArea)) {
        final int signAlg = reader.readUnsignedShort();
        final int nameAlg = reader.readUnsignedShort();

        final int attributes = reader.readInt();
        ExceptionUtil.assure(
            (attributes & Attributes.SHALL_BE_ZERO) == 0,
            "Attributes contains 1 bits in reserved position(s): 0x%08x",
            attributes);

        // authPolicy is not used by this implementation
        reader.skipBytes(reader.readUnsignedShort());

        final Parameters parameters;
        final Unique unique;

        ExceptionUtil.assure(
            (attributes & Attributes.SIGN_ENCRYPT) == Attributes.SIGN_ENCRYPT,
            "Public key is expected to have the SIGN_ENCRYPT attribute set, attributes were: 0x%08x",
            attributes);

        if (signAlg == TpmAlgAsym.RSA) {
          parameters = TpmsRsaParms.parse(reader);
          unique = Tpm2bPublicKeyRsa.parse(reader);
        } else if (signAlg == TpmAlgAsym.ECC) {
          parameters = TpmsEccParms.parse(reader);
          unique = TpmsEccPoint.parse(reader);
        } else {
          throw new UnsupportedOperationException("Signing algorithm not implemented: " + signAlg);
        }

        ExceptionUtil.assure(
            reader.available() == 0,
            "%d remaining bytes in TPMT_PUBLIC buffer",
            reader.available());

        return new TpmtPublic(signAlg, nameAlg, parameters, unique, new ByteArray(pubArea));
      }
    }

    /**
     * Computing Entity Names
     *
     * <p>see:
     * https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.38.pdf
     * section 16 Names
     *
     * <pre>
     * Name ≔ nameAlg || HnameAlg (handle→nvPublicArea)
     * where
     * nameAlg algorithm used to compute Name
     * HnameAlg hash using the nameAlg parameter in the NV Index location
     * associated with handle
     * nvPublicArea contents of the TPMS_NV_PUBLIC associated with handle
     * </pre>
     */
    private ByteArray name() {
      final ByteArray hash;
      switch (this.nameAlg) {
        case TpmAlgHash.SHA1:
          try {
            hash = Crypto.sha1(this.rawBytes);
          } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash TPMU_ATTEST name.", e);
          }
          break;

        case TpmAlgHash.SHA256:
          hash = Crypto.sha256(this.rawBytes);
          break;

        case TpmAlgHash.SHA384:
          hash = Crypto.sha384(this.rawBytes);
          break;

        case TpmAlgHash.SHA512:
          hash = Crypto.sha512(this.rawBytes);
          break;

        default:
          throw new IllegalArgumentException("Unknown hash algorithm identifier: " + this.nameAlg);
      }
      return new ByteArray(BinaryUtil.encodeUint16(this.nameAlg)).concat(hash);
    }
  }

  static class TpmAlgHash {
    static final int SHA1 = 0x0004;
    static final int SHA256 = 0x000B;
    static final int SHA384 = 0x000C;
    static final int SHA512 = 0x000D;
  }

  private void verifyX5cRequirements(X509Certificate cert, ByteArray aaguid)
      throws CertificateParsingException {
    ExceptionUtil.assure(
        cert.getVersion() == 3,
        "Invalid TPM attestation certificate: Version MUST be 3, but was: %s",
        cert.getVersion());

    ExceptionUtil.assure(
        cert.getSubjectX500Principal().getName().isEmpty(),
        "Invalid TPM attestation certificate: subject MUST be empty, but was: %s",
        cert.getSubjectX500Principal());

    boolean foundManufacturer = false;
    boolean foundModel = false;
    boolean foundVersion = false;
    for (List<?> n : cert.getSubjectAlternativeNames()) {
      if ((Integer) n.get(0) == 4) { // GeneralNames CHOICE 4: directoryName
        if (n.get(1) instanceof String) {
          try {
            javax.naming.directory.Attributes attrs =
                new LdapName((String) n.get(1)).getRdns().get(0).toAttributes();
            foundManufacturer = foundManufacturer || attrs.get(OID_TCG_AT_TPM_MANUFACTURER) != null;
            foundModel = foundModel || attrs.get(OID_TCG_AT_TPM_MODEL) != null;
            foundVersion = foundVersion || attrs.get(OID_TCG_AT_TPM_VERSION) != null;
          } catch (InvalidNameException e) {
            throw new RuntimeException(
                "Failed to decode subject alternative name in TPM attestation cert", e);
          }
        } else {
          log.debug("Unknown type of SubjectAlternativeNames entry: {}", n.get(1));
        }
      }
    }
    ExceptionUtil.assure(
        foundManufacturer && foundModel && foundVersion,
        "Invalid TPM attestation certificate: The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.%s%s%s",
        foundManufacturer ? "" : " Missing TPM manufacturer.",
        foundModel ? "" : " Missing TPM model.",
        foundVersion ? "" : " Missing TPM version.");

    ExceptionUtil.assure(
        cert.getExtendedKeyUsage() != null && cert.getExtendedKeyUsage().contains("2.23.133.8.3"),
        "Invalid TPM attestation certificate: extended key usage extension MUST contain the OID 2.23.133.8.3, but was: %s",
        cert.getExtendedKeyUsage());

    ExceptionUtil.assure(
        cert.getBasicConstraints() == -1,
        "Invalid TPM attestation certificate: MUST NOT be a CA certificate, but was.");

    CertificateParser.parseFidoAaguidExtension(cert)
        .ifPresent(
            extensionAaguid -> {
              ExceptionUtil.assure(
                  Arrays.equals(aaguid.getBytes(), extensionAaguid),
                  "Invalid TPM attestation certificate: X.509 extension \"id-fido-gen-ce-aaguid\" is present but does not match the authenticator AAGUID.");
            });
  }

  static final class TpmRsaScheme {
    static final int RSASSA = 0x0014;
  }

  /**
   * See:
   * https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
   * section 12.2.3.5
   */
  @Value
  private static class TpmsRsaParms implements Parameters {

    long exponent;

    private static TpmsRsaParms parse(ByteInputStream reader) throws IOException {
      final int symmetric = reader.readUnsignedShort();
      ExceptionUtil.assure(
          symmetric == TPM_ALG_NULL,
          "RSA key is expected to have \"symmetric\" set to TPM_ALG_NULL, was: 0x%04x",
          symmetric);

      final int scheme = reader.readUnsignedShort();
      ExceptionUtil.assure(
          scheme == TpmRsaScheme.RSASSA || scheme == TPM_ALG_NULL,
          "RSA key is expected to have \"scheme\" set to TPM_ALG_RSASSA or TPM_ALG_NULL, was: 0x%04x",
          scheme);

      reader.skipBytes(2); // key_bits is not used by this implementation

      int exponent = reader.readInt();
      ExceptionUtil.assure(
          exponent >= 0, "Exponent is too large and wrapped around to negative: %d", exponent);
      if (exponent == 0) {
        // When zero,  indicates  that  the  exponent  is  the  default  of 2^16 + 1
        exponent = (1 << 16) + 1;
      }

      return new TpmsRsaParms(exponent);
    }
  }

  @Value
  private static class Tpm2bPublicKeyRsa implements Unique {
    ByteArray bytes;

    private static Tpm2bPublicKeyRsa parse(ByteInputStream reader) throws IOException {
      return new Tpm2bPublicKeyRsa(new ByteArray(reader.read(reader.readUnsignedShort())));
    }
  }

  @Value
  private static class TpmsEccParms implements Parameters {
    int curve_id;

    private static TpmsEccParms parse(ByteInputStream reader) throws IOException {
      final int symmetric = reader.readUnsignedShort();
      final int scheme = reader.readUnsignedShort();
      ExceptionUtil.assure(
          symmetric == TPM_ALG_NULL,
          "ECC key is expected to have \"symmetric\" set to TPM_ALG_NULL, was: 0x%04x",
          symmetric);
      ExceptionUtil.assure(
          scheme == TPM_ALG_NULL,
          "ECC key is expected to have \"scheme\" set to TPM_ALG_NULL, was: 0x%04x",
          scheme);

      final int curve_id = reader.readUnsignedShort();
      reader.skipBytes(2); // kdf_scheme is not used by this implementation

      return new TpmsEccParms(curve_id);
    }
  }

  /**
   * TPMS_ECC_POINT
   *
   * <p>See
   * https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
   * Section 11.2.5.2
   */
  @Value
  private static class TpmsEccPoint implements Unique {

    ByteArray x;
    ByteArray y;

    private static TpmsEccPoint parse(ByteInputStream reader) throws IOException {
      final ByteArray x = new ByteArray(reader.read(reader.readUnsignedShort()));
      final ByteArray y = new ByteArray(reader.read(reader.readUnsignedShort()));

      return new TpmsEccPoint(x, y);
    }
  }

  /**
   * TPM_ECC_CURVE
   *
   * <p>https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
   * section 6.4
   */
  private static class TpmEccCurve {

    private static final int NONE = 0x0000;
    private static final int NIST_P256 = 0x0003;
    private static final int NIST_P384 = 0x0004;
    private static final int NIST_P521 = 0x0005;
  }

  /**
   * the signature data is defined by [TPMv2-Part2] Section 10.12.8 (TPMS_ATTEST) as:
   * TPM_GENERATED_VALUE (0xff544347 aka "\xffTCG") TPMI_ST_ATTEST - always TPM_ST_ATTEST_CERTIFY
   * (0x8017) because signing procedure defines it should call TPM_Certify [TPMv2-Part3] Section
   * 18.2 TPM2B_NAME size (uint16) name (size long) TPM2B_DATA size (uint16) name (size long)
   * TPMS_CLOCK_INFO clock (uint64) resetCount (uint32) restartCount (uint32) safe (byte) 1 yes, 0
   * no firmwareVersion uint64 attested TPMS_CERTIFY_INFO (because TPM_ST_ATTEST_CERTIFY) name
   * TPM2B_NAME qualified_name TPM2B_NAME See:
   * https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
   * https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
   */
  @Value
  private static class TpmsAttest {

    ByteArray rawBytes;
    ByteArray extraData;
    ByteArray attestedName;

    private static TpmsAttest parse(byte[] certInfo) throws IOException {
      try (ByteInputStream reader = new ByteInputStream(certInfo)) {
        final ByteArray magic = new ByteArray(reader.read(4));

        // Verify that magic is set to TPM_GENERATED_VALUE.
        // see https://w3c.github.io/webauthn/#sctn-tpm-attestation
        // verification procedure
        ExceptionUtil.assure(
            magic.equals(TPM_GENERATED_VALUE), "magic field is invalid: %s", magic);

        // Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        // see https://w3c.github.io/webauthn/#sctn-tpm-attestation
        // verification procedure
        final ByteArray type = new ByteArray(reader.read(2));
        ExceptionUtil.assure(type.equals(TPM_ST_ATTEST_CERTIFY), "type field is invalid: %s", type);

        // qualifiedSigner is not used by this implementation
        reader.skipBytes(reader.readUnsignedShort());

        final ByteArray extraData = new ByteArray(reader.read(reader.readUnsignedShort()));

        // clockInfo is not used by this implementation
        reader.skipBytes(8 + 4 + 4 + 1);

        // firmwareVersion is not used by this implementation
        reader.skipBytes(8);

        final ByteArray attestedName = new ByteArray(reader.read(reader.readUnsignedShort()));

        // attestedQualifiedName is not used by this implementation

        return new TpmsAttest(new ByteArray(certInfo), extraData, attestedName);
      }
    }
  }
}
