package com.yubico.webauthn;

import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.data.AttestationObject;
import java.security.cert.CertificateEncodingException;


interface AttestationTrustResolver {

  Attestation resolveTrustAnchor(AttestationObject attestationObject) throws CertificateEncodingException;

}
