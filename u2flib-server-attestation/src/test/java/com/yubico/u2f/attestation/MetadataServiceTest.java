package com.yubico.u2f.attestation;

import com.yubico.u2f.data.messages.key.util.CertificateParser;
import org.junit.Test;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.EnumSet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class MetadataServiceTest {
    private static final String ATTESTATION_CERT = "MIICGzCCAQWgAwIBAgIEdaP2dTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NzM2Nzk3MzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZo35Damtpl81YdmcbhEuXKAr7xDcQzAy5n3ftAAhtBbu8EeGU4ynfSgLonckqX6J2uXLBppTNE3v2bt+Yf8MLoxIwEDAOBgorBgEEAYLECgECBAAwCwYJKoZIhvcNAQELA4IBAQG9LbiNPgs0sQYOHAJcg+lMk+HCsiWRlYVnbT4I/5lnqU907vY17XYAORd432bU3Nnhsbkvjz76kQJGXeNAF4DPANGGlz8JU+LNEVE2PWPGgEM0GXgB7mZN5Sinfy1AoOdO+3c3bfdJQuXlUxHbo+nDpxxKpzq9gr++RbokF1+0JBkMbaA/qLYL4WdhY5NvaOyMvYpO3sBxlzn6FcP67hlotGH1wU7qhCeh+uur7zDeAWVh7c4QtJOXHkLJQfV3Z7ZMvhkIA6jZJAX99hisABU/SSa5DtgX7AfsHwa04h69AAAWDUzSk3HgOXbUd1FaSOPdlVFkG2N2JllFHykyO3zO";
    private static final String ATTESTATION_CERT2 = "MIICLzCCARmgAwIBAgIEQvUaTTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDExMjMzNTkzMDkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQphQ+PJYiZjZEVHtrx5QGE3/LE1+OytZPTwzrpWBKywji/3qmg22mwmVFl32PO269TxY+yVN4jbfVf5uX0EWJWoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNDALBgkqhkiG9w0BAQsDggEBALSc3YwTRbLwXhePj/imdBOhWiqh6ssS2ONgp5tphJCHR5Agjg2VstLBRsJzyJnLgy7bGZ0QbPOyh/J0hsvgBfvjByXOu1AwCW+tcoJ+pfxESojDLDn8hrFph6eWZoCtBsWMDh6vMqPENeP6grEAECWx4fTpBL9Bm7F+0Rp/d1/l66g4IhF/ZvuRFhY+BUK94BfivuBHpEkMwxKENTas7VkxvlVstUvPqhPHGYOq7RdF1D/THsbNY8+tgCTgvTziEG+bfDeY6zIz5h7bxb1rpajNVTpUDWtVYL7/w44e1KCoErqdS+kEbmmkmm7KvDE8kuyg42Fmb5DTMsbY2jxMlMU=";
    private static final String ATTESTATION_CERT_WITH_TRANSPORTS = "MIICIjCCAQygAwIBAgIEIHHwozALBgkqhkiG9w0BAQswDzENMAsGA1UEAxMEdGVzdDAeFw0xNTA4MTEwOTAwMzNaFw0xNjA4MTAwOTAwMzNaMCkxJzAlBgNVBAMTHll1YmljbyBVMkYgRUUgU2VyaWFsIDU0NDMzODA4MzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPdFG1pBjBBQVhLrD39Qg1vKjuR2kRdBZnwLI/zgzztQpf4ffpkrkB/3E0TXj5zg8gN9sgMkX48geBe+tBEpvMmjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4yMBMGCysGAQQBguUcAgEBBAQDAgQwMAsGCSqGSIb3DQEBCwOCAQEAb3YpnmHHduNuWEXlLqlnww9034ZeZaojhPAYSLR8d5NPk9gc0hkjQKmIaaBM7DsaHbcHMKpXoMGTQSC++NCZTcKvZ0Lt12mp5HRnM1NNBPol8Hte5fLmvW4tQ9EzLl4gkz7LSlORxTuwTbae1eQqNdxdeB+0ilMFCEUc+3NGCNM0RWd+sP5+gzMXBDQAI1Sc9XaPIg8t3du5JChAl1ifpu/uERZ2WQgtxeBDO6z1Xoa5qz4svf5oURjPZjxS0WUKht48Z2rIjk5lZzERSaY3RrX3UtrnZEIzCmInXOrcRPeAD4ZutpiwuHe62ABsjuMRnKbATbOUiLdknNyPYYQz2g==";

    @Test
    public void testGetAttestation_x509extension_key() throws Exception {
        MetadataService service = new MetadataService();

        X509Certificate attestationCert = CertificateParser.parsePem(ATTESTATION_CERT);
        Attestation attestation = service.getAttestation(attestationCert);

        assertTrue(attestation.isTrusted());
        assertEquals("Yubico", attestation.getVendorProperties().get("name"));
        assertEquals("1.3.6.1.4.1.41482.1.2", attestation.getDeviceProperties().get("deviceId"));
    }

    @Test
    public void testGetAttestation_x509extension_key_value() throws Exception {
        MetadataService service = new MetadataService();

        X509Certificate attestationCert = CertificateParser.parsePem(ATTESTATION_CERT2);
        Attestation attestation = service.getAttestation(attestationCert);

        assertTrue(attestation.isTrusted());
        assertEquals("Yubico", attestation.getVendorProperties().get("name"));
        assertEquals("1.3.6.1.4.1.41482.1.4", attestation.getDeviceProperties().get("deviceId"));
    }

    @Test
    public void testGetTransportsFromCertificate() throws CertificateException {
        MetadataService service = new MetadataService(mock(MetadataResolver.class));

        X509Certificate attestationCert = CertificateParser.parsePem(ATTESTATION_CERT_WITH_TRANSPORTS);
        Attestation attestation = service.getAttestation(attestationCert);

        assertEquals(EnumSet.of(Transport.USB, Transport.NFC), attestation.getTransports());
    }

    @Test
    public void testGetTransportsFromMetadata() throws CertificateException {
        MetadataService service = new MetadataService();

        X509Certificate attestationCert = CertificateParser.parsePem(ATTESTATION_CERT2);
        Attestation attestation = service.getAttestation(attestationCert);

        assertEquals(EnumSet.of(Transport.USB), attestation.getTransports());
    }
}