package com.yubico.webauthn.impl;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import COSE.CoseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.util.ExceptionUtil;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import com.upokecenter.cbor.CBORObject;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.webauthn.AttestationStatementVerifier;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;


@Slf4j
public class PackedAttestationStatementVerifier implements AttestationStatementVerifier, X5cAttestationStatementVerifier {

    @Override
    public AttestationType getAttestationType(AttestationObject attestation) {
        if (attestation.getAttestationStatement().hasNonNull("x5c")) {
            return AttestationType.BASIC; // TODO or Privacy CA
        } else if (attestation.getAttestationStatement().hasNonNull("ecdaaKeyId")) {
            return AttestationType.ECDAA;
        } else {
            return AttestationType.SELF_ATTESTATION;
        }
    }

    @Override
    public boolean verifyAttestationSignature(AttestationObject attestationObject, byte[] clientDataJsonHash) {
        val signatureNode = attestationObject.getAttestationStatement().get("sig");

        if (signatureNode == null || !signatureNode.isBinary()) {
            throw new IllegalArgumentException("attStmt.sig must be set to a binary value.");
        }

        if (attestationObject.getAttestationStatement().has("x5c")) {
            return verifyX5cSignature(attestationObject, clientDataJsonHash);
        } else if (attestationObject.getAttestationStatement().has("ecdaaKeyId")) {
            return verifyEcdaaSignature(attestationObject, clientDataJsonHash);
        } else {
            return verifySelfAttestationSignature(attestationObject, clientDataJsonHash);
        }
    }

    private boolean verifyEcdaaSignature(AttestationObject attestationObject, byte[] clientDataJsonHash) {
        throw new UnsupportedOperationException("ECDAA signature verification is not (yet) implemented.");
    }

    private boolean verifySelfAttestationSignature(AttestationObject attestationObject, byte[] clientDataJsonHash) {
        final PublicKey pubkey;
        try {
            pubkey = attestationObject.getAuthenticatorData().getAttestationData().get().getParsedCredentialPublicKey();
        } catch (IOException | CoseException e) {
            throw ExceptionUtil.wrapAndLog(
                log,
                String.format("Failed to parse public key from attestation data %s", attestationObject.getAuthenticatorData().getAttestationData()),
                e
            );
        }

        final COSEAlgorithmIdentifier keyAlg = new COSEAlgorithmIdentifier(
            CBORObject.DecodeFromBytes(attestationObject.getAuthenticatorData().getAttestationData().get().getCredentialPublicKeyBytes())
                .get(CBORObject.FromObject(3))
                .AsInt64());
        final COSEAlgorithmIdentifier sigAlg = new COSEAlgorithmIdentifier(attestationObject.getAttestationStatement().get("alg").asLong());

        if (!Objects.equals(keyAlg, sigAlg)) {
            throw new IllegalArgumentException(String.format(
                "Key algorithm and signature algorithm must be equal, was: Key: %s, Sig: %s", keyAlg, sigAlg));
        }

        byte[] signedData = Arrays.concatenate(attestationObject.getAuthenticatorData().getBytes(), clientDataJsonHash);
        byte[] signature;
        try {
            signature = attestationObject.getAttestationStatement().get("sig").binaryValue();
        } catch (IOException e) {
            throw ExceptionUtil.wrapAndLog(log, ".binaryValue() of \"sig\" failed", e);
        }

        try {
            new BouncyCastleCrypto().checkSignature(pubkey, signedData, signature);
            return true;
        } catch (U2fBadInputException e) {
            return false;
        }
    }

    private boolean verifyX5cSignature(AttestationObject attestationObject, byte[] clientDataHash) {
        final Optional<X509Certificate> attestationCert;
        try {
            attestationCert = getX5cAttestationCertificate(attestationObject);
        } catch (CertificateException e) {
            throw ExceptionUtil.wrapAndLog(
                log,
                String.format("Failed to parse X.509 certificate from attestation object: %s", attestationObject),
                e
            );
        }
        return attestationCert.map(attestationCertificate -> {
            JsonNode signatureNode = attestationObject.getAttestationStatement().get("sig");

            if (signatureNode == null) {
                throw new IllegalArgumentException("Packed attestation statement must have field \"sig\".");
            }

            if (signatureNode.isBinary()) {
                byte[] signature;
                try {
                    signature = signatureNode.binaryValue();
                } catch (IOException e) {
                    throw ExceptionUtil.wrapAndLog(log, "signatureNode.isBinary() was true but signatureNode.binaryValue() failed", e);
                }

                byte[] signedData = Arrays.concatenate(attestationObject.getAuthenticatorData().getBytes(), clientDataHash);

                // TODO support other signature algorithms
                Signature ecdsaSignature;
                try {
                    ecdsaSignature = Signature.getInstance("SHA256withECDSA");
                } catch (NoSuchAlgorithmException e) {
                    throw ExceptionUtil.wrapAndLog(log, "Failed to get a Signature instance for SHA256withECDSA", e);
                }
                try {
                    ecdsaSignature.initVerify(attestationCertificate.getPublicKey());
                } catch (InvalidKeyException e) {
                    throw ExceptionUtil.wrapAndLog(log, "Attestation key is invalid: " + attestationCertificate, e);
                }
                try {
                    ecdsaSignature.update(signedData);
                } catch (SignatureException e) {
                    throw ExceptionUtil.wrapAndLog(log, "Signature object in invalid state: " + ecdsaSignature, e);
                }

                try {
                    return (ecdsaSignature.verify(signature)
                        && verifyX5cRequirements(attestationCertificate, attestationObject.getAuthenticatorData().getAttestationData().get().getAaguid())
                    );
                } catch (SignatureException e) {
                    throw ExceptionUtil.wrapAndLog(log, "Failed to verify signature: " + attestationObject, e);
                }
            } else {
                throw new IllegalArgumentException("Field \"sig\" in packed attestation statement must be a binary value.");
            }
        }).orElseThrow(() -> new IllegalArgumentException(
            "If \"x5c\" property is present in \"packed\" attestation format it must be an array containing at least one DER encoded X.509 cerficicate."));
    }

    private Optional<Object> getDnField(String field, X509Certificate cert) {
        final LdapName ldap;
        try {
            ldap = new LdapName(cert.getSubjectX500Principal().getName());
        } catch (InvalidNameException e) {
            throw ExceptionUtil.wrapAndLog(log, "X500Principal name was not accepted as an LdapName: " + cert.getSubjectX500Principal().getName(), e);
        }
        return ldap.getRdns().stream()
            .filter(rdn -> Objects.equals(rdn.getType(), field))
            .findAny()
            .map(i -> i.getValue());
    }

    boolean verifyX5cRequirements(X509Certificate cert, byte[] aaguid) {
        if (cert.getVersion() != 3) {
            throw new IllegalArgumentException(String.format("Wrong attestation certificate X509 version: %s, expected: 3", cert.getVersion()));
        }

        final String ouValue = "Authenticator Attestation";
        final String idFidoGenCeAaguid = "1.3.6.1.4.1.45724.1.1.4";
        final Set<String> countries = Collections.unmodifiableSet(new HashSet<>(java.util.Arrays.asList(Locale.getISOCountries())));

        if (false == getDnField("C", cert).filter(c -> countries.contains(c)).isPresent()) {
            throw new IllegalArgumentException(String.format(
                "Invalid attestation certificate country code: %s", getDnField("C", cert)));
        }

        if (false == getDnField("O", cert).filter(o -> !((String) o).isEmpty()).isPresent()) {
            throw new IllegalArgumentException("Organization (O) field of attestation certificate DN must be present.");
        }

        if (false == getDnField("OU", cert).filter(ou -> ouValue.equals(ou)).isPresent()) {
            throw new IllegalArgumentException(String.format(
                "Organization Unit (OU) field of attestation certificate DN must be exactly \"%s\", was: %s",
                ouValue, getDnField("OU", cert)));
        }

        Optional.ofNullable(cert.getExtensionValue(idFidoGenCeAaguid))
            .map(ext -> {
                try {
                    return ((DEROctetString) ASN1Primitive.fromByteArray(
                        ((DEROctetString) ASN1Primitive.fromByteArray(ext)).getOctets()
                    )).getOctets();
                } catch (IOException e) {
                    throw new IllegalArgumentException("Failed to read id-fido-gen-ce-aaguid certificate extension value.");
                }
            })
            .ifPresent((byte[] value) -> {
                if (false == java.util.Arrays.equals(value, aaguid)) {
                    throw new IllegalArgumentException("X.509 extension " + idFidoGenCeAaguid + " (id-fido-gen-ce-aaguid) is present but does not match the authenticator AAGUID.");
                }
            });

        if (cert.getBasicConstraints() != -1) {
            throw new IllegalArgumentException("Attestation certificate must not be a CA certificate.");
        }

        return true;
    }

}
