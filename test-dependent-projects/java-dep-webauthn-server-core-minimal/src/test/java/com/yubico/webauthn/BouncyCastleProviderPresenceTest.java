package com.yubico.webauthn;

import COSE.CoseException;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.Security;
import java.util.Arrays;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test that the BouncyCastle provider is not loaded by default
 * when depending on the <code>webauthn-server-core-minimal</code> package.
 *
 * Motivation: https://github.com/Yubico/java-webauthn-server/issues/97
 */
public class BouncyCastleProviderPresenceTest {

    @Test(expected = ClassNotFoundException.class)
    public void bouncyCastleProviderIsNotInClasspath() throws ClassNotFoundException {
        Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
    }

    @Test
    public void bouncyCastleProviderIsNotLoadedByDefault() {
        assertTrue(
            Arrays.stream(Security.getProviders())
                .noneMatch(prov -> prov.getName().toLowerCase().contains("bouncy"))
        );
    }

    @Test
    public void bouncyCastleProviderIsNotLoadedAfterInstantiatingRelyingParty() {
        // The RelyingParty constructor has the possible side-effect of loading the BouncyCastle provider
        RelyingParty.builder()
            .identity(RelyingPartyIdentity.builder().id("foo").name("foo").build())
            .credentialRepository(Mockito.mock(CredentialRepository.class))
            .build();

        assertTrue(
            Arrays.stream(Security.getProviders())
                .noneMatch(prov ->
                    prov.getName().equals("BC")
                        || prov.getClass().getCanonicalName().contains("bouncy")
        ));
    }

    @Test
    public void bouncyCastleProviderIsNotLoadedAfterAttemptingToLoadEddsaKey() throws IOException, CoseException, NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            WebAuthnCodecs.importCosePublicKey(
                new AttestationObject(RegistrationTestData.Packed$.MODULE$.BasicAttestationEdDsa().attestationObject())
                    .getAuthenticatorData()
                    .getAttestedCredentialData()
                    .get()
                    .getCredentialPublicKey()
            );
        } catch (NoSuchAlgorithmException e) {
            // OK
        }

        assertTrue(
            Arrays.stream(Security.getProviders())
                .noneMatch(prov ->
                    prov.getName().equals("BC")
                        || prov.getClass().getCanonicalName().contains("bouncy")
        ));
    }

}
