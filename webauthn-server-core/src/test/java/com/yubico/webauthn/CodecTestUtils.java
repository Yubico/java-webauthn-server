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
import com.yubico.webauthn.data.ByteArray;
import java.security.cert.CertificateEncodingException;

public class CodecTestUtils {
    public static ByteArray encodeRegisterResponse(RawRegisterResponse rawRegisterResponse) throws U2fBadInputException {
        ByteArray keyHandle = rawRegisterResponse.keyHandle;
        if (keyHandle.getBytes().length > 255) {
            throw new U2fBadInputException("keyHandle length cannot be longer than 255 bytes!");
        }

        try {
            ByteArrayDataOutput encoded = ByteStreams.newDataOutput();
            encoded.write(RawRegisterResponse.REGISTRATION_RESERVED_BYTE_VALUE);
            encoded.write(rawRegisterResponse.userPublicKey.getBytes());
            encoded.write((byte) keyHandle.getBytes().length);
            encoded.write(keyHandle.getBytes());
            encoded.write(rawRegisterResponse.attestationCertificate.getEncoded());
            encoded.write(rawRegisterResponse.signature.getBytes());
            return new ByteArray(encoded.toByteArray());
        } catch (CertificateEncodingException e) {
            throw new U2fBadInputException("Error when encoding attestation certificate.", e);
        }
    }
}
