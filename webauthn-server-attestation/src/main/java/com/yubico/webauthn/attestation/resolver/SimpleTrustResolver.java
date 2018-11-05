package com.yubico.webauthn.attestation.resolver;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.attestation.MetadataObject;
import com.yubico.webauthn.attestation.TrustResolver;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Assesses whether an argument certificate can be trusted, and if so, by what
 * trusted root certificate.
 */
public class SimpleTrustResolver implements TrustResolver {

    private static final Logger logger = LoggerFactory.getLogger(SimpleTrustResolver.class);

    private final Multimap<String, X509Certificate> trustedCerts = ArrayListMultimap.create();

    public SimpleTrustResolver(Iterable<X509Certificate> trustedCertificates) {
        for (X509Certificate cert : trustedCertificates) {
            trustedCerts.put(cert.getSubjectDN().getName(), cert);
        }
    }

    public static SimpleTrustResolver fromMetadata(Iterable<MetadataObject> metadataObjects) throws CertificateException {
        Set<X509Certificate> certs = new HashSet<>();
        for (MetadataObject metadata : metadataObjects) {
            for (String encodedCert : metadata.getTrustedCertificates()) {
                certs.add(CertificateParser.parsePem(encodedCert));
            }
        }
        return new SimpleTrustResolver(certs);
    }

    public static SimpleTrustResolver fromMetadataJson(String metadataObjectJson) throws IOException, CertificateException {
        return fromMetadata(Collections.singleton(WebAuthnCodecs.json().readValue(metadataObjectJson, MetadataObject.class)));
    }

    @Override
    public Optional<X509Certificate> resolveTrustAnchor(X509Certificate attestationCertificate, List<X509Certificate> caCertificateChain) {
        final List<X509Certificate> certChain = new ArrayList<>();
        certChain.add(attestationCertificate);
        certChain.addAll(caCertificateChain);

        X509Certificate lastTriedCert = null;

        for (X509Certificate untrustedCert : certChain) {
            if (lastTriedCert != null) {
                logger.trace("No trusted certificate has signed certificate [{}] - trying next element in certificate chain.", lastTriedCert);

                try {
                    lastTriedCert.verify(untrustedCert.getPublicKey());
                } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
                    logger.error("Failed to verify that certificate [{}] was signed by [{}]", lastTriedCert, untrustedCert, e);
                    throw new RuntimeException("Resolve failed", e);
                } catch (SignatureException e) {
                    logger.debug("Certificate chain broken - certificate [{}] was not signed by certificate [{}]", lastTriedCert, untrustedCert);
                    return Optional.empty();
                }
            }

            final String issuer = untrustedCert.getIssuerDN().getName();
            for (X509Certificate trustedCert : trustedCerts.get(issuer)) {
                try {
                    untrustedCert.verify(trustedCert.getPublicKey());
                    logger.debug("Found signature from trusted certificate [{}]", trustedCert);
                    return Optional.of(trustedCert);
                } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException e) {
                    logger.error("Resolve failed", e);
                    throw new RuntimeException("Resolve failed", e);
                } catch (SignatureException e) {
                    // Not signed by the trusted cert
                }
            }

            lastTriedCert = untrustedCert;
        }

        logger.debug("No trusted certificate has signed certificate chain {}", certChain);
        return Optional.empty();
    }

}
