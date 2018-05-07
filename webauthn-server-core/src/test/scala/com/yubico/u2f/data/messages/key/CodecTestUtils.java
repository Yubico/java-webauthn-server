/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data.messages.key;

import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;
import com.yubico.u2f.exceptions.U2fBadInputException;
import java.security.cert.CertificateEncodingException;

public class CodecTestUtils {
    public static byte[] encodeRegisterResponse(RawRegisterResponse rawRegisterResponse) throws U2fBadInputException {
        byte[] keyHandle = rawRegisterResponse.keyHandle;
        if (keyHandle.length > 255) {
            throw new U2fBadInputException("keyHandle length cannot be longer than 255 bytes!");
        }

        try {
            ByteArrayDataOutput encoded = ByteStreams.newDataOutput();
            encoded.write(RawRegisterResponse.REGISTRATION_RESERVED_BYTE_VALUE);
            encoded.write(rawRegisterResponse.userPublicKey);
            encoded.write((byte) keyHandle.length);
            encoded.write(keyHandle);
            encoded.write(rawRegisterResponse.attestationCertificate.getEncoded());
            encoded.write(rawRegisterResponse.signature);
            return encoded.toByteArray();
        } catch (CertificateEncodingException e) {
            throw new U2fBadInputException("Error when encoding attestation certificate.", e);
        }
    }
}
