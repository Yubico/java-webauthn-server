/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.webauthn;

import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;
import com.yubico.internal.util.ByteInputStream;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.U2fB64Encoding;
import com.yubico.webauthn.data.ByteArray;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * The register response produced by the token/key
 */
@EqualsAndHashCode
@ToString
class RawRegisterResponse {
    static final byte REGISTRATION_RESERVED_BYTE_VALUE = (byte) 0x05;
    private static final byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = (byte) 0x00;

    @EqualsAndHashCode.Exclude
    private transient final Crypto crypto;

    /**
     * The (uncompressed) x,y-representation of a curve point on the P-256
     * NIST elliptic curve.
     */
    final ByteArray userPublicKey;

    /**
     * A handle that allows the U2F token to identify the generated key pair.
     */
    final ByteArray keyHandle;
    final X509Certificate attestationCertificate;

    /**
     * A ECDSA signature (on P-256)
     */
    final ByteArray signature;

    public RawRegisterResponse(ByteArray userPublicKey,
                               ByteArray keyHandle,
                               X509Certificate attestationCertificate,
                               ByteArray signature) {
        this(userPublicKey, keyHandle, attestationCertificate, signature, new BouncyCastleCrypto());
    }

    public RawRegisterResponse(ByteArray userPublicKey,
                               ByteArray keyHandle,
                               X509Certificate attestationCertificate,
                               ByteArray signature,
                               Crypto crypto) {
        this.userPublicKey = userPublicKey;
        this.keyHandle = keyHandle;
        this.attestationCertificate = attestationCertificate;
        this.signature = signature;
        this.crypto = crypto;
    }

    static RawRegisterResponse fromBase64(String rawDataBase64, Crypto crypto) throws U2fBadInputException {
        ByteInputStream bytes = new ByteInputStream(U2fB64Encoding.decode(rawDataBase64));
        try {
            byte reservedByte = bytes.readSigned();
            if (reservedByte != REGISTRATION_RESERVED_BYTE_VALUE) {
                throw new U2fBadInputException(
                        "Incorrect value of reserved byte. Expected: " + REGISTRATION_RESERVED_BYTE_VALUE +
                                ". Was: " + reservedByte
                );
            }

            return new RawRegisterResponse(
                    new ByteArray(bytes.read(65)),
                    new ByteArray(bytes.read(bytes.readUnsigned())),
                    CertificateParser.parseDer(bytes),
                    new ByteArray(bytes.readAll()),
                    crypto
            );
        } catch (CertificateException e) {
            throw new U2fBadInputException("Malformed attestation certificate", e);
        } catch (IOException e) {
            throw new U2fBadInputException("Truncated registration data", e);
        }
    }

    public boolean verifySignature(ByteArray appIdHash, ByteArray clientDataHash) {
        ByteArray signedBytes = packBytesToSign(appIdHash, clientDataHash, keyHandle, userPublicKey);
        return crypto.verifySignature(attestationCertificate, signedBytes, signature);
    }

    static ByteArray packBytesToSign(ByteArray appIdHash, ByteArray clientDataHash, ByteArray keyHandle, ByteArray userPublicKey) {
        ByteArrayDataOutput encoded = ByteStreams.newDataOutput();
        encoded.write(REGISTRATION_SIGNED_RESERVED_BYTE_VALUE);
        encoded.write(appIdHash.getBytes());
        encoded.write(clientDataHash.getBytes());
        encoded.write(keyHandle.getBytes());
        encoded.write(userPublicKey.getBytes());
        return new ByteArray(encoded.toByteArray());
    }

}
