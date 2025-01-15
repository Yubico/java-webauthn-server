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
