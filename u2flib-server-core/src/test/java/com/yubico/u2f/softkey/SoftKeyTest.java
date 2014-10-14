package com.yubico.u2f.softkey;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.server.U2F;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.messages.StartedAuthentication;
import com.yubico.u2f.server.messages.AuthenticationResponse;
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
    AuthenticationResponse authenticationResponse = client.authenticate(registeredDevice, startedAuthentication);

    U2F.finishAuthentication(startedAuthentication, authenticationResponse, registeredDevice, TRUSTED_DOMAINS);
  }


}
