package com.yubico.u2f.softkey;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.U2F;
import com.yubico.u2f.data.Device;
import com.yubico.u2f.data.messages.StartedAuthentication;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.key.Client;
import org.junit.Test;

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

    StartedAuthentication startedAuthentication = U2F.startAuthentication(APP_ID, registeredDevice);
    AuthenticateResponse authenticateResponse = client.authenticate(registeredDevice, startedAuthentication);

    U2F.finishAuthentication(startedAuthentication, authenticateResponse, registeredDevice, TRUSTED_DOMAINS);
  }
}
