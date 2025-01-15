// Copyright (c) 2024, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn.attestation;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.experimental.UtilityClass;

@UtilityClass
public class CertificateUtil {
  public static final String ID_FIDO_GEN_CE_SERNUM = "1.3.6.1.4.1.45724.1.1.2";

  private static byte[] parseSerNum(byte[] bytes) {
    if (bytes != null) {
      ByteBuffer buffer = ByteBuffer.wrap(bytes);

      if (buffer.get() == (byte) 0x04 && buffer.get() > 0 && buffer.get() == (byte) 0x04) {

        byte length = buffer.get();
        byte[] serNumBytes = new byte[length];
        buffer.get(serNumBytes);

        return serNumBytes;
      }
    }

    throw new IllegalArgumentException(
        "X.509 extension 1.3.6.1.4.1.45724.1.1.2 (id-fido-gen-ce-sernum) is not valid.");
  }

  public static Optional<byte[]> parseFidoSerNumExtension(X509Certificate cert) {
    return Optional.ofNullable(cert.getExtensionValue(ID_FIDO_GEN_CE_SERNUM))
        .map(CertificateUtil::parseSerNum);
  }
}
