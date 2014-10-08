package com.yubico.u2f.softkey;

import com.google.common.collect.ImmutableSet;
import com.google.gson.Gson;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.codec.ByteSink;
import com.yubico.u2f.key.messages.AuthenticateResponse;
import com.yubico.u2f.key.messages.RegisterResponse;
import com.yubico.u2f.server.U2F;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.impl.BouncyCastleCrypto;
import com.yubico.u2f.server.messages.StartedAuthentication;
import com.yubico.u2f.server.messages.StartedRegistration;
import com.yubico.u2f.server.messages.TokenAuthenticationResponse;
import com.yubico.u2f.server.messages.TokenRegistrationResponse;
import com.yubico.u2f.softkey.messages.AuthenticateRequest;
import com.yubico.u2f.softkey.messages.RegisterRequest;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

public class SoftKeyTest {

  public static final ImmutableSet<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
  public static final String APP_ID = "my-app";

  private final BouncyCastleCrypto crypto = new BouncyCastleCrypto();
  private final Gson gson = new Gson();

  @Test
  public void shouldRegister() throws Exception {
    SoftKey key = new SoftKey();
    register(key);
  }

  @Test
  public void shouldAuthenticate() throws Exception {
    SoftKey key = new SoftKey();

    Device registeredDevice = register(key);

    StartedAuthentication startedAuthentication = U2F.startAuthentication(APP_ID, TRUSTED_DOMAINS, registeredDevice);

    // client
    Map<String, String> clientData = new HashMap<String, String>();
    clientData.put("typ", "navigator.id.getAssertion");
    clientData.put("challenge", startedAuthentication.getChallenge());
    clientData.put("origin", "http://example.com");
    String clientDataJson = gson.toJson(clientData);


    byte[] clientParam = crypto.hash(new String(clientDataJson));
    byte[] appParam = crypto.hash(startedAuthentication.getAppId());
    AuthenticateRequest authenticateRequest = new AuthenticateRequest((byte) 0x01, clientParam, appParam, registeredDevice.getKeyHandle());

    AuthenticateResponse authenticateResponse = key.authenticate(authenticateRequest);

    // client encodes data
    String clientDataBase64 = Base64.encodeBase64URLSafeString(clientDataJson.getBytes());
    byte[] authData = ByteSink.create()
            .put(authenticateResponse.getUserPresence())
            .putInt(authenticateResponse.getCounter())
            .put(authenticateResponse.getSignature())
            .toByteArray();

    TokenAuthenticationResponse tokenAuthenticationResponse = new TokenAuthenticationResponse(
            clientDataBase64,
            Base64.encodeBase64URLSafeString(authData),
            startedAuthentication.getChallenge()
    );

    startedAuthentication.finish(tokenAuthenticationResponse, registeredDevice);
  }

  private Device register(SoftKey key) throws U2fException, InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
    StartedRegistration startedRegistration = U2F.startRegistration(APP_ID, TRUSTED_DOMAINS);

    // client
    Map<String, String> clientData = new HashMap<String, String>();
    clientData.put("typ", "navigator.id.finishEnrollment");
    clientData.put("challenge", startedRegistration.getChallenge());
    clientData.put("origin", "http://example.com");
    String clientDataJson = gson.toJson(clientData);

    byte[] clientParam = crypto.hash(new String(clientDataJson));
    byte[] appParam = crypto.hash(startedRegistration.getAppId());

    RegisterResponse registerResponse = key.register(new RegisterRequest(appParam, clientParam));

    // client encodes data
    TokenRegistrationResponse tokenResponse = Client.encodeTokenRegistrationResponse(clientDataJson, registerResponse);

    return startedRegistration.finish(tokenResponse);
  }
}
