package com.yubico.u2f.data;

import com.yubico.u2f.data.messages.key.Client;
import com.yubico.u2f.softkey.SoftKey;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class DeviceJsonTest {

  @Test
  public void shouldSerialize() throws Exception {
    SoftKey key = new SoftKey();
    Client client = new Client(key);
    Device device = client.register();

    String json = device.toJson();

    Device deserializedDevice = Device.fromJson(json);
    assertArrayEquals(device.getKeyHandle(), deserializedDevice.getKeyHandle());
    assertArrayEquals(device.getPublicKey(), deserializedDevice.getPublicKey());
    assertEquals(device.getCounter(), deserializedDevice.getCounter());
  }

}