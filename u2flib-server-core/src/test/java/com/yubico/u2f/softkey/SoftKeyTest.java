package com.yubico.u2f.softkey;

import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.ClientData;
import com.yubico.u2f.data.messages.SignRequest;
import com.yubico.u2f.data.messages.SignResponse;
import com.yubico.u2f.data.messages.key.Client;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.InvalidDeviceCounterException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.u2f.exceptions.U2fRegistrationException;
import com.yubico.u2f.testdata.AcmeKey;
import com.yubico.u2f.testdata.GnubbyKey;
import java.security.KeyPair;
import java.util.HashMap;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.assertEquals;

public class SoftKeyTest {

    public static final String APP_ID = "my-app";

    private U2fPrimitives u2f;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

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
    public void shouldSign() throws Exception {
        Client client = createClient();
        DeviceRegistration registeredDevice = client.register();
        signUsing(client, registeredDevice);
    }

    // Tests FIDO Security Measure [SM-3]
    @Test
    public void shouldProvideAttestationCert() throws Exception {
        Client client = createClient();
        DeviceRegistration deviceRegistration = client.register();
        assertEquals("CN=Gnubby Pilot", deviceRegistration.getAttestationCertificate().getIssuerDN().getName());
    }

    @Test
    public void shouldVerifyAttestationCert() throws Throwable {
        expectedException.expectCause(isA(U2fBadInputException.class));

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

        signUsing(client, registeredDevice);
        signUsing(clientUsingClone, registeredDevice);
    }

    @Test
     public void shouldVerifyChallenge() throws Throwable {
        expectedException.expectCause(isA(U2fBadInputException.class));

        Client client = createClient();

        DeviceRegistration registeredDevice = client.register();

        SignRequest signRequest = u2f.startSignature(APP_ID, registeredDevice);
        SignResponse originalResponse = client.sign(registeredDevice, signRequest);
        SignResponse tamperedResponse = new SignResponse(
                tamperChallenge(originalResponse.getClientData()),
                originalResponse.getSignatureData(),
                originalResponse.getKeyHandle()
        );
        u2f.finishSignature(signRequest, tamperedResponse, registeredDevice);
    }

    private String tamperChallenge(ClientData clientData) {
        byte[] rawClientData = clientData.asJson().getBytes();
        rawClientData[50] += 1;
        return U2fB64Encoding.encode(rawClientData);
    }

    @Test
    public void shouldVerifySignature() throws Throwable {
        expectedException.expectCause(isA(U2fBadInputException.class));

        Client client = createClient();

        DeviceRegistration registeredDevice = client.register();

        SignRequest signRequest = u2f.startSignature(APP_ID, registeredDevice);
        SignResponse originalResponse = client.sign(registeredDevice, signRequest);
        SignResponse tamperedResponse = new SignResponse(
                U2fB64Encoding.encode(originalResponse.getClientData().asJson().getBytes()),
                tamperSignature(originalResponse.getSignatureData()),
                originalResponse.getKeyHandle()
        );
        u2f.finishSignature(signRequest, tamperedResponse, registeredDevice);
    }


    @Test(expected = RuntimeException.class)
    public void shouldThrowSeparateExceptionForMalformedSignature() throws Exception {

        Client client = createClient();

        DeviceRegistration registeredDevice = client.register();

        SignRequest signRequest = u2f.startSignature(APP_ID, registeredDevice);
        SignResponse originalResponse = client.sign(registeredDevice, signRequest);
        SignResponse tamperedResponse = new SignResponse(
            U2fB64Encoding.encode(originalResponse.getClientData().asJson().getBytes()),
            makeSignatureMalformed(originalResponse.getSignatureData()),
            originalResponse.getKeyHandle()
        );
        u2f.finishSignature(signRequest, tamperedResponse, registeredDevice);
    }

    private String makeSignatureMalformed(String signature) {
        return signature.substring(0, 5) + "47" + signature.substring(7);
    }

    private String tamperSignature(String signature) {
        return signature.substring(0, 24) + "47" + signature.substring(26);
    }

    private Client createClient() {
        return new Client(new SoftKey());
    }

    private void signUsing(Client client, DeviceRegistration registeredDevice) throws Exception {
        SignRequest signRequest = u2f.startSignature(APP_ID, registeredDevice);
        SignResponse signResponse = client.sign(registeredDevice, signRequest);
        u2f.finishSignature(signRequest, signResponse, registeredDevice);
    }
}
