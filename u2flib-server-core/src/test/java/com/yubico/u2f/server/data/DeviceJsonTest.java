package com.yubico.u2f.server.data;

import com.yubico.u2f.softkey.Client;
import com.yubico.u2f.softkey.SoftKey;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DeviceJsonTest {

  @Test
  public void shouldSerialize() throws Exception {
    SoftKey key = new SoftKey();
    Client client = new Client(key);
    Device device = client.register();

    String json= device.toJson();

    assertEquals(device, Device.fromJson(json));
  }

}