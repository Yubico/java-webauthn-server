package com.yubico.webauthn.attestation;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

public interface MetadataService {

    Attestation getAttestation(List<X509Certificate> attestationCertificateChain) throws CertificateEncodingException;

}
