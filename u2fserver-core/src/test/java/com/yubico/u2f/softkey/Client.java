package com.yubico.u2f.softkey;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.key.messages.RegisterResponse;
import com.yubico.u2f.server.messages.TokenRegistrationResponse;
import org.apache.commons.codec.binary.Base64;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Client {
  public static final byte REGISTRATION_RESERVED_BYTE_VALUE = (byte) 0x05;

  public static byte[] encodeRegisterResponse(RegisterResponse registerResponse)
          throws U2fException {
    byte[] userPublicKey = registerResponse.getUserPublicKey();
    byte[] keyHandle = registerResponse.getKeyHandle();
    X509Certificate attestationCertificate = registerResponse.getAttestationCertificate();
    byte[] signature = registerResponse.getSignature();

    byte[] attestationCertificateBytes;
    try {
      attestationCertificateBytes = attestationCertificate.getEncoded();
    } catch (CertificateEncodingException e) {
      throw new U2fException("Error when encoding attestation certificate.", e);
    }

    if (keyHandle.length > 255) {
      throw new U2fException("keyHandle length cannot be longer than 255 bytes!");
    }

    byte[] result = new byte[1 + userPublicKey.length + 1 + keyHandle.length
            + attestationCertificateBytes.length + signature.length];
    ByteBuffer.wrap(result)
            .put(REGISTRATION_RESERVED_BYTE_VALUE)
            .put(userPublicKey)
            .put((byte) keyHandle.length)
            .put(keyHandle)
            .put(attestationCertificateBytes)
            .put(signature);
    return result;
  }

  public static TokenRegistrationResponse encodeTokenRegistrationResponse(String clientDataJson, RegisterResponse registerResponse) throws U2fException {
    byte[] rawRegisterResponse = Client.encodeRegisterResponse(registerResponse);
    String rawRegisterResponseBase64 = Base64.encodeBase64URLSafeString(rawRegisterResponse);
    String clientDataBase64 = Base64.encodeBase64URLSafeString(clientDataJson.getBytes());
    return new TokenRegistrationResponse(rawRegisterResponseBase64, clientDataBase64);
  }
}
