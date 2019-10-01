package com.yubico.test.compilability;

import com.yubico.webauthn.attestation.AttestationResolver;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

public class ThisShouldCompile {

    public AttestationResolver getResolver() {
        return new AttestationResolver() {
            @Override
            public Optional<com.yubico.webauthn.attestation.Attestation> resolve(X509Certificate attestationCertificate, List<X509Certificate> certificateChain) {
                return Optional.empty();
            }

            @Override
            public com.yubico.webauthn.attestation.Attestation untrustedFromCertificate(X509Certificate attestationCertificate) {
                return null;
            }
        };
    }

}
