package com.yubico.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.ByteArray;
import java.nio.charset.Charset;
import java.io.IOException;
import javax.net.ssl.SSLException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;

@Slf4j
class AndroidSafetynetAttestationStatementVerifier implements AttestationStatementVerifier, X5cAttestationStatementVerifier {

    private final BouncyCastleCrypto crypto = new BouncyCastleCrypto();

    private static final DefaultHostnameVerifier HOSTNAME_VERIFIER = new DefaultHostnameVerifier();

    private X509Certificate mX5cCert = null;

    public Optional<List<X509Certificate>> getAttestationTrustPath() {
        if (mX5cCert != null) {
            List<X509Certificate> certs = new ArrayList<>(1);
            certs.add(mX5cCert);
            return Optional.of(certs);
        }
        return Optional.empty();
    }

    @Override
    public AttestationType getAttestationType(AttestationObject attestation) {
        return AttestationType.BASIC;
    }

    @Override
    public boolean verifyAttestationSignature(AttestationObject attestationObject, ByteArray clientDataJsonHash) {
        final JsonNode ver = attestationObject.getAttestationStatement().get("ver");
        final JsonNode response = attestationObject.getAttestationStatement().get("response");

        if (ver == null || !ver.isTextual() ) {
            throw new IllegalArgumentException("attStmt.ver must be set as text! " + ver.toString());
        }

        if (response == null || !response.isBinary() ) {
            throw new IllegalArgumentException("attStmt.response must be set to a binary value.");
        }

        String attStmtString;
        try {
            attStmtString = new String(response.binaryValue(), Charset.forName("UTF-8"));
        } catch (IOException ioe) {
            throw ExceptionUtil.wrapAndLog(log, "reponseNode.isBinary() was true but reponseNode.binaryValue() failed", ioe);
        }

        if (attStmtString != null && !attStmtString.isEmpty()) {
            final AndroidSafetynetAttestationStatement attStmtObj = parseAndVerify(attStmtString);
            if (attStmtObj != null) {
                final byte[] nonce = attStmtObj.getNonce();
                final boolean isCtsProfileMatch = attStmtObj.isCtsProfileMatch();

                if (isCtsProfileMatch) {
                    // Verify that the nonce in the response is identical to the SHA-256 hash of 
                    // the concatenation of authenticatorData and clientDataHash.
                    ByteArray signedData = attestationObject.getAuthenticatorData().getBytes().concat(clientDataJsonHash);
                    ByteArray hashSignedData = crypto.hash(signedData);
                    ByteArray nonceByteArray = new ByteArray(nonce);

                    final int compareResult = hashSignedData.compareTo(nonceByteArray);
                    return (compareResult == 0);
                }
            }
        }

        return false;
    }

    /**
     * This code is copied from android-play-saftynet attestion sample.
     * @param signedAttestationStatment
     * @return
     */
    private AndroidSafetynetAttestationStatement parseAndVerify(String signedAttestationStatment) {
        // Parse JSON Web Signature format.
        JsonWebSignature jws;
        try {
            jws = JsonWebSignature.parser(JacksonFactory.getDefaultInstance())
                    .setPayloadClass(AndroidSafetynetAttestationStatement.class).parse(signedAttestationStatment);
        } catch (IOException e) {
            System.err.println("Failure: " + signedAttestationStatment + " is not valid JWS " +
                    "format.");
            return null;
        }

        // Verify the signature of the JWS and retrieve the signature certificate.
        X509Certificate cert;
        try {
            cert = jws.verifySignature();
            if (cert == null) {
                System.err.println("Failure: Signature verification failed.");
                return null;
            }
        } catch (GeneralSecurityException e) {
            System.err.println(
                    "Failure: Error during cryptographic verification of the JWS signature.");
            return null;
        }

        // Verify the hostname of the certificate.
        if (!verifyHostname("attest.android.com", cert)) {
            System.err.println("Failure: Certificate isn't issued for the hostname attest.android" +
                    ".com.");
            return null;
        }

        // Save the cefrtificate
        mX5cCert = cert;

        // Extract and use the payload data.
        AndroidSafetynetAttestationStatement stmt = (AndroidSafetynetAttestationStatement) jws.getPayload();
        return stmt;
    }

    /**
     * Verifies that the certificate matches the specified hostname.
     * Uses the {@link DefaultHostnameVerifier} from the Apache HttpClient library
     * to confirm that the hostname matches the certificate.
     *
     * @param hostname
     * @param leafCert
     * @return
     */
    private static boolean verifyHostname(String hostname, X509Certificate leafCert) {
        try {
            // Check that the hostname matches the certificate. This method throws an exception if
            // the cert could not be verified.
            HOSTNAME_VERIFIER.verify(hostname, leafCert);
            return true;
        } catch (SSLException e) {
            e.printStackTrace();
        }

        return false;
    }
}