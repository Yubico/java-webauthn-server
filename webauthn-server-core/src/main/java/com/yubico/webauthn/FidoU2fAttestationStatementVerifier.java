package com.yubico.webauthn;

import COSE.CoseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.data.AttestationData;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.ByteArray;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Objects;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;


@Slf4j
class FidoU2fAttestationStatementVerifier implements AttestationStatementVerifier, X5cAttestationStatementVerifier {

    private static boolean isP256(ECParameterSpec params) {
        ECNamedCurveParameterSpec p256 = ECNamedCurveTable.getParameterSpec("P-256");

        return (Objects.equals(p256.getN(), params.getOrder())
            && Objects.equals(p256.getG().getAffineXCoord().toBigInteger(), params.getGenerator().getAffineX())
            && Objects.equals(p256.getG().getAffineYCoord().toBigInteger(), params.getGenerator().getAffineY())
            && Objects.equals(p256.getH(), BigInteger.valueOf(params.getCofactor()))
        );
    }

    private X509Certificate getAttestationCertificate(AttestationObject attestationObject) throws CertificateException {
        return getX5cAttestationCertificate(attestationObject).map(attestationCertificate -> {
            if ("EC".equals(attestationCertificate.getPublicKey().getAlgorithm())
                && isP256(((ECPublicKey) attestationCertificate.getPublicKey()).getParams())
            ) {
                return attestationCertificate;
            } else {
                throw new IllegalArgumentException("Attestation certificate for fido-u2f must have an ECDSA P-256 public key.");
            }
        }).orElseThrow(() -> new IllegalArgumentException(
            "fido-u2f attestation statement must have an \"x5c\" property set to an array of at least one DER encoded X.509 certificate."
        ));
    }

    private static boolean validSelfSignature(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public AttestationType getAttestationType(AttestationObject attestationObject) throws CoseException, IOException, CertificateException {
        X509Certificate attestationCertificate = getAttestationCertificate(attestationObject);

        if (attestationCertificate.getPublicKey() instanceof ECPublicKey
            && validSelfSignature(attestationCertificate)
            && WebAuthnCodecs.ecPublicKeyToRaw(
                WebAuthnCodecs.importCoseP256PublicKey(
                    attestationObject.getAuthenticatorData().getAttestationData().get().getCredentialPublicKey()
                )
               )
                .equals(
                    WebAuthnCodecs.ecPublicKeyToRaw((ECPublicKey) attestationCertificate.getPublicKey())
                )
        ) {
            return AttestationType.SELF_ATTESTATION;
        } else {
            return AttestationType.BASIC;
        }
    }

    @Override
    public boolean verifyAttestationSignature(AttestationObject attestationObject, ByteArray clientDataJsonHash) {
        final X509Certificate attestationCertificate;
        try {
            attestationCertificate = getAttestationCertificate(attestationObject);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(String.format(
                "Failed to parse X.509 certificate from attestation object: %s", attestationObject));
        }

        if (!(
            "EC".equals(attestationCertificate.getPublicKey().getAlgorithm())
                && isP256(((ECPublicKey) attestationCertificate.getPublicKey()).getParams())
        )) {
            throw new IllegalArgumentException("Attestation certificate for fido-u2f must have an ECDSA P-256 public key.");
        }

        final Optional<AttestationData> attData = attestationObject.getAuthenticatorData().getAttestationData();

        return attData.map(attestationData -> {
            JsonNode signature = attestationObject.getAttestationStatement().get("sig");

            if (signature == null) {
                throw new IllegalArgumentException("fido-u2f attestation statement must have a \"sig\" property set to a DER encoded signature.");
            }

            if (signature.isBinary()) {
                ByteArray userPublicKey;

                try {
                    userPublicKey = WebAuthnCodecs.ecPublicKeyToRaw(
                        WebAuthnCodecs.importCoseP256PublicKey(
                            attestationData.getCredentialPublicKey()
                        )
                    );
                } catch (IOException | CoseException e) {
                    RuntimeException err = new RuntimeException(String.format("Failed to parse public key from attestation data %s", attestationData));
                    log.error(err.getMessage(), err);
                    throw err;
                }

                ByteArray keyHandle = attestationData.getCredentialId();

                U2fRawRegisterResponse u2fRegisterResponse;
                try {
                    u2fRegisterResponse = new U2fRawRegisterResponse(
                        userPublicKey,
                        keyHandle,
                        attestationCertificate,
                        new ByteArray(signature.binaryValue())
                    );
                } catch (IOException e) {
                    RuntimeException err = new RuntimeException("signature.isBinary() was true but signature.binaryValue() failed", e);
                    log.error(err.getMessage(), err);
                    throw err;
                }

                return u2fRegisterResponse.verifySignature(
                    attestationObject.getAuthenticatorData().getRpIdHash(),
                    clientDataJsonHash
                );
            } else {
                throw new IllegalArgumentException("\"sig\" property of fido-u2f attestation statement must be a CBOR byte array value.");
            }

        }).orElseThrow(() -> new IllegalArgumentException("Attestation object for credential creation must have attestation data."));
    }

}
