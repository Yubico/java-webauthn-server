package com.yubico.u2f.softkey;

import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequest;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.ClientData;
import com.yubico.u2f.data.messages.key.Client;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.InvalidDeviceCounterException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.u2f.testdata.AcmeKey;
import com.yubico.u2f.testdata.GnubbyKey;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;

public class SoftKeyTest {

    public static final String APP_ID = "my-app";

    private U2fPrimitives u2f;

    @Before
    public void setup() {
        u2f = new U2fPrimitives();
    }

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

    @Test(expected = U2fBadInputException.class)
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
    @Test(expected = InvalidDeviceCounterException.class)
    public void shouldProtectAgainstClonedDevices() throws Exception {
        SoftKey key = new SoftKey();
        Client client = new Client(key);

        SoftKey clonedKey = key.clone();
        Client clientUsingClone = new Client(clonedKey);

        DeviceRegistration registeredDevice = client.register();

        authenticateUsing(client, registeredDevice);
        authenticateUsing(clientUsingClone, registeredDevice);
    }

    @Test(expected = U2fBadInputException.class)
     public void shouldVerifyChallenge() throws Exception {

        Client client = createClient();

        DeviceRegistration registeredDevice = client.register();

        AuthenticateRequest authenticateRequest = u2f.startAuthentication(APP_ID, registeredDevice);
        AuthenticateResponse originalResponse = client.authenticate(registeredDevice, authenticateRequest);
        AuthenticateResponse tamperedResponse = new AuthenticateResponse(
                tamperChallenge(originalResponse.getClientData()),
                originalResponse.getSignatureData(),
                originalResponse.getKeyHandle()
        );
        u2f.finishAuthentication(authenticateRequest, tamperedResponse, registeredDevice);
    }

    private String tamperChallenge(ClientData clientData) {
        byte[] rawClientData = clientData.asJson().getBytes();
        rawClientData[50] += 1;
        return U2fB64Encoding.encode(rawClientData);
    }

    @Test(expected = U2fBadInputException.class)
    public void shouldVerifySignature() throws Exception {

        Client client = createClient();

        DeviceRegistration registeredDevice = client.register();

        AuthenticateRequest authenticateRequest = u2f.startAuthentication(APP_ID, registeredDevice);
        AuthenticateResponse originalResponse = client.authenticate(registeredDevice, authenticateRequest);
        AuthenticateResponse tamperedResponse = new AuthenticateResponse(
                U2fB64Encoding.encode(originalResponse.getClientData().asJson().getBytes()),
                tamperSignature(originalResponse.getSignatureData()),
                originalResponse.getKeyHandle()
        );
        u2f.finishAuthentication(authenticateRequest, tamperedResponse, registeredDevice);
    }


    private String tamperSignature(String signature) {
        return signature.substring(0, 5) + "47" + signature.substring(7);
    }

    private Client createClient() {
        return new Client(new SoftKey());
    }

    private void authenticateUsing(Client client, DeviceRegistration registeredDevice) throws Exception {
        AuthenticateRequest authenticateRequest = u2f.startAuthentication(APP_ID, registeredDevice);
        AuthenticateResponse authenticateResponse = client.authenticate(registeredDevice, authenticateRequest);
        u2f.finishAuthentication(authenticateRequest, authenticateResponse, registeredDevice);
    }
}
