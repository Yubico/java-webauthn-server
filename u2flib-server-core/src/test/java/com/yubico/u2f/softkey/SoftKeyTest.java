package com.yubico.u2f.softkey;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.U2F;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.data.Device;
import com.yubico.u2f.data.messages.ClientData;
import com.yubico.u2f.data.messages.StartedAuthentication;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.key.Client;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;

public class SoftKeyTest {

  private static final Logger Log = Logger.getLogger(SoftKeyTest.class.getName());

  public static final ImmutableSet<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
  public static final String APP_ID = "my-app";

  @Test
  public void shouldRegister() throws Exception {
    Client client = createClient();
    client.register();
  }

  @Test
  public void shouldAuthenticate() throws Exception {
    Client client = createClient();
    Device registeredDevice = client.register();
    authenticateUsing(client, registeredDevice);
  }

  @Test
  public void shouldProvideAttestationCert() throws Exception {
    Client client = createClient();
    Device device = client.register();
    assertEquals("CN=Gnubby Pilot", device.getAttestationCertificate().getIssuerDN().getName());
  }

  @Test(expected = U2fException.class)
  public void shouldProtectAgainstClonedDevices() throws Exception {
    SoftKey key = new SoftKey();
    Client client = new Client(key);

    SoftKey clonedKey = key.clone();
    Client clientUsingClone = new Client(clonedKey);

    Device registeredDevice = client.register();

    authenticateUsing(client, registeredDevice);
    authenticateUsing(clientUsingClone, registeredDevice);
  }

  @Test(expected = U2fException.class)
  public void shouldVerifyKeySignatures() throws Exception {
    Client client = createClient();

    Device registeredDevice = client.register();

    StartedAuthentication startedAuthentication = U2F.startAuthentication(APP_ID, registeredDevice);
    AuthenticateResponse originalResponse = client.authenticate(registeredDevice, startedAuthentication);
    AuthenticateResponse tamperedResponse = new AuthenticateResponse(
            tamperChallenge(originalResponse.getClientData()),
            originalResponse.getSignatureData(),
            originalResponse.getKeyHandle()
    );
    U2F.finishAuthentication(startedAuthentication, tamperedResponse, registeredDevice);
  }

  private String tamperChallenge(ClientData clientData) throws U2fException {

    byte[] rawClientData = clientData.getRawClientData();
    rawClientData[50] = 85;
    return Base64.encodeBase64URLSafeString(rawClientData);
  }

  private Client createClient() {
    SoftKey key = new SoftKey();
    return new Client(key);
  }

  private void authenticateUsing(Client client, Device registeredDevice) throws U2fException {
    StartedAuthentication startedAuthentication = U2F.startAuthentication(APP_ID, registeredDevice);
    AuthenticateResponse authenticateResponse = client.authenticate(registeredDevice, startedAuthentication);
    U2F.finishAuthentication(startedAuthentication, authenticateResponse, registeredDevice);
  }
}
