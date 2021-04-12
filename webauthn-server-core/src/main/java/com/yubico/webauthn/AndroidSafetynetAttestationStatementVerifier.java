package com.yubico.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLException;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;

@Slf4j
class AndroidSafetynetAttestationStatementVerifier
    implements AttestationStatementVerifier, X5cAttestationStatementVerifier {

  private static final DefaultHostnameVerifier HOSTNAME_VERIFIER = new DefaultHostnameVerifier();

  @Override
  public AttestationType getAttestationType(AttestationObject attestation) {
    return AttestationType.BASIC;
  }

  @Override
  public JsonNode getX5cArray(AttestationObject attestationObject) {
    JsonNodeFactory jsonFactory = JsonNodeFactory.instance;
    ArrayNode array = jsonFactory.arrayNode();
    for (JsonNode cert : parseJws(attestationObject).getHeader().get("x5c")) {
      array.add(jsonFactory.binaryNode(ByteArray.fromBase64(cert.textValue()).getBytes()));
    }
    return array;
  }

  @Override
  public boolean verifyAttestationSignature(
      AttestationObject attestationObject, ByteArray clientDataJsonHash) {
    final JsonNode ver = attestationObject.getAttestationStatement().get("ver");

    if (ver == null || !ver.isTextual()) {
      throw new IllegalArgumentException(
          "Property \"ver\" of android-safetynet attestation statement must be a string, was: "
              + ver);
    }

    JsonWebSignatureCustom jws = parseJws(attestationObject);

    if (!verifySignature(jws)) {
      return false;
    }

    JsonNode payload = jws.getPayload();

    ByteArray signedData =
        attestationObject.getAuthenticatorData().getBytes().concat(clientDataJsonHash);
    ByteArray hashSignedData = Crypto.sha256(signedData);
    ByteArray nonceByteArray = ByteArray.fromBase64(payload.get("nonce").textValue());
    ExceptionUtil.assure(
        hashSignedData.equals(nonceByteArray),
        "Nonce does not equal authenticator data + client data. Expected nonce: %s, was nonce: %s",
        hashSignedData.getBase64Url(),
        nonceByteArray.getBase64Url());

    ExceptionUtil.assure(
        payload.get("ctsProfileMatch").booleanValue(),
        "Expected ctsProfileMatch to be true, was: %s",
        payload.get("ctsProfileMatch"));

    return true;
  }

  private static JsonWebSignatureCustom parseJws(AttestationObject attestationObject) {
    return new JsonWebSignatureCustom(
        new String(getResponseBytes(attestationObject).getBytes(), StandardCharsets.UTF_8));
  }

  private static ByteArray getResponseBytes(AttestationObject attestationObject) {
    final JsonNode response = attestationObject.getAttestationStatement().get("response");
    if (response == null || !response.isBinary()) {
      throw new IllegalArgumentException(
          "Property \"response\" of android-safetynet attestation statement must be a binary value, was: "
              + response);
    }

    try {
      return new ByteArray(response.binaryValue());
    } catch (IOException ioe) {
      throw ExceptionUtil.wrapAndLog(
          log, "response.isBinary() was true but response.binaryValue failed: " + response, ioe);
    }
  }

  private boolean verifySignature(JsonWebSignatureCustom jws) {
    // Verify the signature of the JWS and retrieve the signature certificate.
    X509Certificate attestationCertificate = jws.getX5c().get(0);

    String signatureAlgorithmName =
        WebAuthnCodecs.jwsAlgorithmNameToJavaAlgorithmName(jws.getAlgorithm());

    Signature signatureVerifier;
    try {
      signatureVerifier = Crypto.getSignature(signatureAlgorithmName);
    } catch (NoSuchAlgorithmException e) {
      throw ExceptionUtil.wrapAndLog(
          log, "Failed to get a Signature instance for " + signatureAlgorithmName, e);
    }
    try {
      signatureVerifier.initVerify(attestationCertificate.getPublicKey());
    } catch (InvalidKeyException e) {
      throw ExceptionUtil.wrapAndLog(
          log, "Attestation key is invalid: " + attestationCertificate, e);
    }
    try {
      signatureVerifier.update(jws.getSignedBytes().getBytes());
    } catch (SignatureException e) {
      throw ExceptionUtil.wrapAndLog(
          log, "Signature object in invalid state: " + signatureVerifier, e);
    }

    // Verify the hostname of the certificate.
    ExceptionUtil.assure(
        verifyHostname(attestationCertificate),
        "Certificate isn't issued for the hostname attest.android.com: %s",
        attestationCertificate);

    try {
      return signatureVerifier.verify(jws.getSignature().getBytes());
    } catch (SignatureException e) {
      throw ExceptionUtil.wrapAndLog(log, "Failed to verify signature of JWS: " + jws, e);
    }
  }

  @Value
  private static class JsonWebSignatureCustom {
    public final JsonNode header;
    public final JsonNode payload;
    public final ByteArray signedBytes;
    public final ByteArray signature;
    public final List<X509Certificate> x5c;
    public final String algorithm;

    JsonWebSignatureCustom(String jwsCompact) {
      String[] parts = jwsCompact.split("\\.");
      ObjectMapper json = JacksonCodecs.json();

      try {
        final ByteArray header = ByteArray.fromBase64Url(parts[0]);
        final ByteArray payload = ByteArray.fromBase64Url(parts[1]);

        this.header = json.readTree(header.getBytes());
        this.payload = json.readTree(payload.getBytes());
        this.signedBytes =
            new ByteArray((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        this.signature = ByteArray.fromBase64Url(parts[2]);
        this.x5c = getX5c(this.header);
        this.algorithm = this.header.get("alg").textValue();
      } catch (IOException | Base64UrlException e) {
        throw ExceptionUtil.wrapAndLog(log, "Failed to parse JWS: " + jwsCompact, e);
      } catch (CertificateException e) {
        throw ExceptionUtil.wrapAndLog(
            log, "Failed to parse attestation certificates in JWS header: " + jwsCompact, e);
      }
    }

    private static List<X509Certificate> getX5c(JsonNode header)
        throws IOException, CertificateException {
      List<X509Certificate> result = new ArrayList<>();
      for (JsonNode jsonNode : header.get("x5c")) {
        result.add(CertificateParser.parseDer(jsonNode.binaryValue()));
      }
      return result;
    }
  }

  /** Verifies that the certificate matches the hostname "attest.android.com". */
  private static boolean verifyHostname(X509Certificate leafCert) {
    try {
      HOSTNAME_VERIFIER.verify("attest.android.com", leafCert);
      return true;
    } catch (SSLException e) {
      return false;
    }
  }
}
