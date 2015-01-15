package com.yubico.u2f.data;

import com.yubico.u2f.data.messages.key.Client;
import com.yubico.u2f.softkey.SoftKey;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DeviceRegistrationJsonTest {

    @Test
    public void shouldSerialize() throws Exception {
        SoftKey key = new SoftKey();
        Client client = new Client(key);
        DeviceRegistration deviceRegistration = client.register();

        String json = deviceRegistration.toJson();

        DeviceRegistration deserializedDeviceRegistration = DeviceRegistration.fromJson(json);
        assertEquals(deviceRegistration.getKeyHandle(), deserializedDeviceRegistration.getKeyHandle());
        assertEquals(deviceRegistration.getPublicKey(), deserializedDeviceRegistration.getPublicKey());
        assertEquals(deviceRegistration.getCounter(), deserializedDeviceRegistration.getCounter());
    }

}