package com.yubico.u2f.data;

import com.yubico.u2f.data.messages.key.Client;
import com.yubico.u2f.exceptions.InvalidDeviceCounterException;
import com.yubico.u2f.softkey.SoftKey;
import org.junit.Test;

import static com.yubico.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static com.yubico.u2f.testdata.TestVectors.KEY_HANDLE_BASE64;
import static com.yubico.u2f.testdata.TestVectors.USER_PUBLIC_KEY_AUTHENTICATE_HEX;
import static junit.framework.Assert.fail;
import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DeviceRegistrationTest {

    @Test
    public void shouldSerialize() throws Exception {
        DeviceRegistration deviceRegistration = getDeviceRegistration();

        String json = deviceRegistration.toJson();

        DeviceRegistration deserializedDeviceRegistration = DeviceRegistration.fromJson(json);
        assertEquals(deviceRegistration.getKeyHandle(), deserializedDeviceRegistration.getKeyHandle());
        assertEquals(deviceRegistration.getPublicKey(), deserializedDeviceRegistration.getPublicKey());
        assertEquals(deviceRegistration.getCounter(), deserializedDeviceRegistration.getCounter());
    }

    @Test
    public void shouldAcceptValidCounters() throws Exception {
        DeviceRegistration deviceRegistration = getDeviceRegistration();

        deviceRegistration.checkAndUpdateCounter(3);
        deviceRegistration.checkAndUpdateCounter(10);
        deviceRegistration.checkAndUpdateCounter(97);

        assertFalse(deviceRegistration.isCompromised());
    }

    @Test
    public void shouldDetectInvalidCounters() throws Exception {
        DeviceRegistration deviceRegistration = getDeviceRegistration();

        deviceRegistration.checkAndUpdateCounter(9);

        try {
            deviceRegistration.checkAndUpdateCounter(5);
            fail();
        } catch (InvalidDeviceCounterException e) {
            assertTrue(deviceRegistration.isCompromised());
        }
    }

    private DeviceRegistration getDeviceRegistration() throws Exception {
        Client client = new Client(new SoftKey());
        return client.register();
    }
}