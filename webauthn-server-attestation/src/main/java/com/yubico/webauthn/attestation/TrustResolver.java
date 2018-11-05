package com.yubico.webauthn.attestation;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public interface TrustResolver {

    /**
     * Alias of <code>resolveTrustAnchor(attestationCertificate, Collections.emptyList())</code>.
     *
     * @see #resolveTrustAnchor(X509Certificate, List)
     */
    default Optional<X509Certificate> resolveTrustAnchor(X509Certificate attestationCertificate) {
        return resolveTrustAnchor(attestationCertificate, Collections.emptyList());
    }

    /**
     * Resolve a trusted root anchor for the given attestation certificate and certificate chain
     *
     * @param attestationCertificate The attestation certificate
     * @param caCertificateChain Zero or more certificates, of which the first
     *          has signed <code>attestationCertificate</code> and each of the
     *          rest has signed the previous in order
     * @return A trusted root certificate from which there exists a signature
     *          path to <code>attestationCertificate</code>, if one exists.
     */
    Optional<X509Certificate> resolveTrustAnchor(X509Certificate attestationCertificate, List<X509Certificate> caCertificateChain);

}
