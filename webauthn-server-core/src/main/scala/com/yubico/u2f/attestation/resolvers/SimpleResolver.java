/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation.resolvers;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.yubico.u2f.attestation.MetadataObject;
import com.yubico.u2f.attestation.MetadataResolver;
import com.yubico.u2f.data.messages.key.util.CertificateParser;
import com.yubico.u2f.exceptions.U2fBadConfigurationException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleResolver implements MetadataResolver {
    private static final Logger logger = LoggerFactory.getLogger(SimpleResolver.class);

    private final Multimap<String, X509Certificate> certs = ArrayListMultimap.create();
    private final Map<X509Certificate, MetadataObject> metadata = new HashMap<X509Certificate, MetadataObject>();

    public void addMetadata(String jsonData) throws CertificateException, U2fBadConfigurationException {
        for (MetadataObject object : MetadataObject.parseFromJson(jsonData)) {
            addMetadata(object);
        }
    }

    public void addMetadata(MetadataObject object) throws CertificateException {
        for (String caPem : object.getTrustedCertificates()) {
            X509Certificate caCert = CertificateParser.parsePem(caPem);
            certs.put(caCert.getSubjectDN().getName(), caCert);
            metadata.put(caCert, object);
        }
    }

    @Override
    public MetadataObject resolve(X509Certificate attestationCertificate) {
        String issuer = attestationCertificate.getIssuerDN().getName();
        for (X509Certificate cert : certs.get(issuer)) {
            try {
                attestationCertificate.verify(cert.getPublicKey());
                return metadata.get(cert);
            } catch (CertificateException e) {
                logger.error("resolve failed", e);
            } catch (NoSuchAlgorithmException e) {
                logger.error("resolve failed", e);
            } catch (InvalidKeyException e) {
                logger.error("resolve failed", e);
            } catch (NoSuchProviderException e) {
                logger.error("resolve failed", e);
            } catch (SignatureException e) {
                logger.error("resolve failed", e);
            }
        }
        return null;
    }
}
