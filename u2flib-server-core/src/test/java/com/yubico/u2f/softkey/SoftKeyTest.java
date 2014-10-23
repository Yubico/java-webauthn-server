package com.yubico.u2f.softkey;

import com.yubico.u2f.U2F;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.ClientData;
import com.yubico.u2f.data.messages.StartedAuthentication;
import com.yubico.u2f.data.messages.key.Client;
import com.yubico.u2f.exceptions.U2fException;
import com.yubico.u2f.testdata.AcmeKey;
import com.yubico.u2f.testdata.GnubbyKey;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;

public class SoftKeyTest {

  private static final Logger Log = Logger.getLogger(SoftKeyTest.class.getName());

  public static final String APP_ID = "my-app";

  @Test
  public void shouldRegister() throws Exception {
    Client client = createClient();
    client.register();
  }

  @Test
  public void shouldAuthenticate() throws Exception {
    Client client = createClient();
    DeviceRegistration registeredDevice = client.register();
    authenticateUsing(client, registeredDevice);
  }

  // Tests FIDO Security Measure [SM-3]
  @Test
  public void shouldProvideAttestationCert() throws Exception {
    Client client = createClient();
    DeviceRegistration deviceRegistration = client.register();
    assertEquals("CN=Gnubby Pilot", deviceRegistration.getAttestationCertificate().getIssuerDN().getName());
  }

  @Test(expected = U2fException.class)
  public void shouldVerifyAttestationCert() throws Exception {
    SoftKey key = new SoftKey(
            new HashMap<String, KeyPair>(),
            0,
            AcmeKey.ATTESTATION_CERTIFICATE,
            GnubbyKey.ATTESTATION_CERTIFICATE_PRIVATE_KEY
    );
    new Client(key).register();
  }

  // Tests FIDO Security Measure [SM-15]
  @Test(expected = U2fException.class)
  public void shouldProtectAgainstClonedDevices() throws Exception {
    SoftKey key = new SoftKey();
    Client client = new Client(key);

    SoftKey clonedKey = key.clone();
    Client clientUsingClone = new Client(clonedKey);

    DeviceRegistration registeredDevice = client.register();

    authenticateUsing(client, registeredDevice);
    authenticateUsing(clientUsingClone, registeredDevice);
  }

  @Test(expected = U2fException.class)
  public void shouldVerifyKeySignatures() throws Exception {
    Client client = createClient();

    DeviceRegistration registeredDevice = client.register();

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

  private void authenticateUsing(Client client, DeviceRegistration registeredDevice) throws Exception {
    StartedAuthentication startedAuthentication = U2F.startAuthentication(APP_ID, registeredDevice);
    AuthenticateResponse authenticateResponse = client.authenticate(registeredDevice, startedAuthentication);
    U2F.finishAuthentication(startedAuthentication, authenticateResponse, registeredDevice);
  }
}
