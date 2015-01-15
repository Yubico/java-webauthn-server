package com.yubico.u2f.data.messages.key.util;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateParser {
    private static final Provider BC_PROVIDER = new BouncyCastleProvider();

    public static X509Certificate parsePem(String pemEncodedCert) throws CertificateException {
        return parseDer(pemEncodedCert.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "").replaceAll("\n", ""));
    }

    public static X509Certificate parseDer(String base64DerEncodedCert) throws CertificateException {
        return parseDer(BaseEncoding.base64().decodingStream(new StringReader(base64DerEncodedCert)));
    }

    public static X509Certificate parseDer(byte[] derEncodedCert) throws CertificateException {
        return parseDer(new ByteArrayInputStream(derEncodedCert));
    }

    public static X509Certificate parseDer(InputStream is) throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509", BC_PROVIDER).generateCertificate(is);
    }
}
