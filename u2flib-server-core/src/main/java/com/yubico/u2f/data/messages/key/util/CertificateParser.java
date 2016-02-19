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
import java.util.Arrays;
import java.util.List;

public class CertificateParser {
    private static final Provider BC_PROVIDER = new BouncyCastleProvider();

    private final static List<String> FIXSIG = Arrays.asList(
            "CN=Yubico U2F EE Serial 776137165",
            "CN=Yubico U2F EE Serial 1086591525",
            "CN=Yubico U2F EE Serial 1973679733",
            "CN=Yubico U2F EE Serial 13503277888",
            "CN=Yubico U2F EE Serial 13831167861",
            "CN=Yubico U2F EE Serial 14803321578"
    );


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
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509", BC_PROVIDER).generateCertificate(is);
        //Some known certs have an incorrect "unused bits" value, which causes problems on newer versions of BouncyCastle.
        if(FIXSIG.contains(cert.getSubjectDN().getName())) {
            byte[] encoded = cert.getEncoded();
            encoded[encoded.length-257] = 0;  // Fix the "unused bits" field (should always be 0).
            cert = (X509Certificate) CertificateFactory.getInstance("X.509", BC_PROVIDER).generateCertificate(new ByteArrayInputStream(encoded));
        }
        return cert;
    }
}
