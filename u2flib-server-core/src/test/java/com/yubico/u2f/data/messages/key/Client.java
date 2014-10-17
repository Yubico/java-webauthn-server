package com.yubico.u2f.data.messages.key;

import com.google.common.collect.ImmutableSet;
import com.google.gson.Gson;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.data.messages.key.util.ByteSink;
import com.yubico.u2f.U2F;
import com.yubico.u2f.data.Device;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.data.messages.StartedAuthentication;
import com.yubico.u2f.data.messages.StartedRegistration;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.softkey.SoftKey;
import com.yubico.u2f.softkey.messages.AuthenticateRequest;
import com.yubico.u2f.softkey.messages.RegisterRequest;
import org.apache.commons.codec.binary.Base64;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class Client {
  public static final byte REGISTRATION_RESERVED_BYTE_VALUE = (byte) 0x05;
  public static final ImmutableSet<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
  public static final String APP_ID = "my-app";

  private final BouncyCastleCrypto crypto = new BouncyCastleCrypto();
  private final Gson gson = new Gson();
  private final SoftKey key;

  public Client(SoftKey key) {
    this.key = key;
  }

  public static byte[] encodeRegisterResponse(RawRegisterResponse rawRegisterResponse)
          throws U2fException {
    byte[] userPublicKey = rawRegisterResponse.userPublicKey;
    byte[] keyHandle = rawRegisterResponse.keyHandle;
    X509Certificate attestationCertificate = rawRegisterResponse.attestationCertificate;
    byte[] signature = rawRegisterResponse.signature;

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

  public static RegisterResponse encodeTokenRegistrationResponse(String clientDataJson, RawRegisterResponse registerResponse) throws U2fException {
    byte[] rawRegisterResponse = Client.encodeRegisterResponse(registerResponse);
    String rawRegisterResponseBase64 = Base64.encodeBase64URLSafeString(rawRegisterResponse);
    String clientDataBase64 = Base64.encodeBase64URLSafeString(clientDataJson.getBytes());
    return new RegisterResponse(rawRegisterResponseBase64, clientDataBase64);
  }

  public Device register() throws U2fException, InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
    StartedRegistration startedRegistration = U2F.startRegistration(APP_ID);

    Map<String, String> clientData = new HashMap<String, String>();
    clientData.put("typ", "navigator.id.finishEnrollment");
    clientData.put("challenge", startedRegistration.getChallenge());
    clientData.put("origin", "http://example.com");
    String clientDataJson = gson.toJson(clientData);

    byte[] clientParam = crypto.hash(clientDataJson);
    byte[] appParam = crypto.hash(startedRegistration.getAppId());

    RawRegisterResponse rawRegisterResponse = key.register(new RegisterRequest(appParam, clientParam));

    // client encodes data
    RegisterResponse tokenResponse = Client.encodeTokenRegistrationResponse(clientDataJson, rawRegisterResponse);

    return U2F.finishRegistration(startedRegistration, tokenResponse, TRUSTED_DOMAINS);
  }

  public AuthenticateResponse authenticate(Device registeredDevice, StartedAuthentication startedAuthentication) throws U2fException {
    Map<String, String> clientData = new HashMap<String, String>();
    clientData.put("typ", "navigator.id.getAssertion");
    clientData.put("challenge", startedAuthentication.getChallenge());
    clientData.put("origin", "http://example.com");
    String clientDataJson = gson.toJson(clientData);


    byte[] clientParam = crypto.hash(clientDataJson);
    byte[] appParam = crypto.hash(startedAuthentication.getAppId());
    AuthenticateRequest authenticateRequest = new AuthenticateRequest((byte) 0x01, clientParam, appParam, registeredDevice.getKeyHandle());

    RawAuthenticateResponse rawAuthenticateResponse = key.authenticate(authenticateRequest);

    String clientDataBase64 = Base64.encodeBase64URLSafeString(clientDataJson.getBytes());
    byte[] authData = ByteSink.create()
            .put(rawAuthenticateResponse.getUserPresence())
            .putInt(rawAuthenticateResponse.getCounter())
            .put(rawAuthenticateResponse.getSignature())
            .toByteArray();

    return new AuthenticateResponse(
            clientDataBase64,
            Base64.encodeBase64URLSafeString(authData),
            startedAuthentication.getKeyHandle()
    );
  }
}
