package com.yubico.u2f.softkey;

import com.google.common.collect.ImmutableSet;
import com.google.gson.Gson;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.key.messages.RegisterResponse;
import com.yubico.u2f.server.U2F;
import com.yubico.u2f.server.impl.BouncyCastleCrypto;
import com.yubico.u2f.server.messages.StartedRegistration;
import com.yubico.u2f.softkey.messages.RegisterRequest;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class SoftKeyTest {

  public static final ImmutableSet<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
  public static final String APP_ID = "my-app";

  private final BouncyCastleCrypto crypto = new BouncyCastleCrypto();
  private final Gson gson = new Gson();

  @Test
  public void shouldRegister() throws Exception {
    StartedRegistration startedRegistration = U2F.startRegistration(APP_ID, TRUSTED_DOMAINS);

    SoftKey key = new SoftKey();

    Map<String, String> clientData = new HashMap<String, String>();
    clientData.put("typ", "navigator.id.finishEnrollment");
    clientData.put("challenge", startedRegistration.getChallenge());
    clientData.put("origin", "http://example.com");
    String clientDataJson = gson.toJson(clientData);

    byte[] clientParam = crypto.hash(new String(clientDataJson));
    byte[] appParam = crypto.hash(startedRegistration.getAppId());

    RegisterRequest registerRequest = new RegisterRequest(appParam, clientParam);
    RegisterResponse registerResponse = key.register(registerRequest);

    // convert registerResponse to TokenAuthenticationResponse

    //startedRegistration.finish(tokenAuthenticationResponse);
  }
}
