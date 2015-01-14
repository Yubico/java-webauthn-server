/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation.resolvers;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.io.BaseEncoding;
import com.google.common.io.Closeables;
import com.yubico.u2f.attestation.MetadataObject;
import com.yubico.u2f.attestation.MetadataResolver;

import java.io.InputStream;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class SimpleResolver implements MetadataResolver {
    private final Multimap<String, X509Certificate> certs = ArrayListMultimap.create();
    private final Map<X509Certificate, MetadataObject> metadata = new HashMap<X509Certificate, MetadataObject>();

    public void addMetadata(String jsonData) throws CertificateException {
        for (MetadataObject object : MetadataObject.parseFromJson(jsonData)) {
            addMetadata(object);
        }
    }

    public void addMetadata(MetadataObject object) throws CertificateException {
        for (String caPem : object.getTrustedCertificates()) {
            X509Certificate caCert = parsePem(caPem);
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
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    public static X509Certificate parsePem(String pem) throws CertificateException {
        pem = pem.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "").replaceAll("\n", "");
        InputStream inputStream = null;
        try {
            inputStream = BaseEncoding.base64().decodingStream(new StringReader(pem));
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
        } finally {
            Closeables.closeQuietly(inputStream);
        }
    }
}
