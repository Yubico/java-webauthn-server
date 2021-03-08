package com.yubico.webauthn;

import COSE.CoseException;
import com.yubico.webauthn.data.AttestationObject;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CryptoAlgorithmsTest {

    @Test
    public void generateRsa() {
        TestAuthenticator.generateRsaKeypair();
    }

    @Test
    public void importRsa() throws IOException, CoseException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey key = WebAuthnCodecs.importCosePublicKey(
            new AttestationObject(RegistrationTestData.Packed$.MODULE$.BasicAttestationRsa().attestationObject())
                .getAuthenticatorData()
                .getAttestedCredentialData()
                .get()
                .getCredentialPublicKey()
        );
        assertEquals(key.getAlgorithm(), "RSA");
    }

    @Test
    public void generateEcdsa() {
        TestAuthenticator.generateEcKeypair("secp256r1");
    }

    @Test
    public void importEcdsa() throws IOException, CoseException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey key = WebAuthnCodecs.importCosePublicKey(
            new AttestationObject(RegistrationTestData.Packed$.MODULE$.BasicAttestation().attestationObject())
                .getAuthenticatorData()
                .getAttestedCredentialData()
                .get()
                .getCredentialPublicKey()
        );
        assertEquals(key.getAlgorithm(), "EC");
    }

    @Test
    public void generateEddsa() {
        TestAuthenticator.generateEddsaKeypair();
    }

    @Test
    public void importEddsa() throws IOException, CoseException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey key = WebAuthnCodecs.importCosePublicKey(
            new AttestationObject(RegistrationTestData.Packed$.MODULE$.BasicAttestationEdDsa().attestationObject())
                .getAuthenticatorData()
                .getAttestedCredentialData()
                .get()
                .getCredentialPublicKey()
        );
        assertTrue("EdDSA".equals(key.getAlgorithm()) || "Ed25519".equals(key.getAlgorithm()));
    }

}
