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

  @Test
  public void shouldRegister() throws Exception {
    SoftKey key = new SoftKey();
    Client client = new Client(key);
    client.register();
  }

  @Test
  public void shouldAuthenticate() throws Exception {
    SoftKey key = new SoftKey();
    Client client = new Client(key);

    Device registeredDevice = client.register();

    StartedAuthentication startedAuthentication = StartedAuthentication.fromJson(U2F.startAuthentication(APP_ID, registeredDevice));
    TokenAuthenticationResponse tokenAuthenticationResponse = client.authenticate(registeredDevice, startedAuthentication);

    U2F.finishAuthentication(startedAuthentication, tokenAuthenticationResponse, registeredDevice, TRUSTED_DOMAINS);
  }


}
