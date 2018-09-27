package com.yubico.u2f.testdata;

import com.yubico.internal.util.CertificateParser;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static com.yubico.webauthn.TestUtils.parsePrivateKey;

public class GnubbyKey {

    public static final X509Certificate ATTESTATION_CERTIFICATE = getAttestationCertificate();

    private static X509Certificate getAttestationCertificate() {
        try {
            return CertificateParser.parseDer(GnubbyKey.class.getResourceAsStream("gnubby/attestation-certificate.der"));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static final PrivateKey ATTESTATION_CERTIFICATE_PRIVATE_KEY =
            parsePrivateKey(GnubbyKey.class.getResourceAsStream("gnubby/attestation-certificate-private-key.hex"));
}
