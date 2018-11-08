/*
 * Copyright 2014-2018 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the COPYING file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.webauthn;

import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;
import com.yubico.webauthn.data.ByteArray;
import java.security.cert.X509Certificate;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * The register response produced by the token/key
 */
@EqualsAndHashCode
@ToString
class U2fRawRegisterResponse {
    private static final byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = (byte) 0x00;

    @EqualsAndHashCode.Exclude
    private transient final Crypto crypto;

    /**
     * The (uncompressed) x,y-representation of a curve point on the P-256
     * NIST elliptic curve.
     */
    private final ByteArray userPublicKey;

    /**
     * A handle that allows the U2F token to identify the generated key pair.
     */
    private final ByteArray keyHandle;
    private final X509Certificate attestationCertificate;

    /**
     * A ECDSA signature (on P-256)
     */
    private final ByteArray signature;

    U2fRawRegisterResponse(ByteArray userPublicKey,
                           ByteArray keyHandle,
                           X509Certificate attestationCertificate,
                           ByteArray signature) {
        this(userPublicKey, keyHandle, attestationCertificate, signature, new BouncyCastleCrypto());
    }

    private U2fRawRegisterResponse(ByteArray userPublicKey,
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

    boolean verifySignature(ByteArray appIdHash, ByteArray clientDataHash) {
        ByteArray signedBytes = packBytesToSign(appIdHash, clientDataHash, keyHandle, userPublicKey);
        return crypto.verifySignature(attestationCertificate, signedBytes, signature);
    }

    private static ByteArray packBytesToSign(ByteArray appIdHash, ByteArray clientDataHash, ByteArray keyHandle, ByteArray userPublicKey) {
        ByteArrayDataOutput encoded = ByteStreams.newDataOutput();
        encoded.write(REGISTRATION_SIGNED_RESERVED_BYTE_VALUE);
        encoded.write(appIdHash.getBytes());
        encoded.write(clientDataHash.getBytes());
        encoded.write(keyHandle.getBytes());
        encoded.write(userPublicKey.getBytes());
        return new ByteArray(encoded.toByteArray());
    }

}
