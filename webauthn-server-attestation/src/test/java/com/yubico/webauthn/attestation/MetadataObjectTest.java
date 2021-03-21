// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn.attestation;

import static org.junit.Assert.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.internal.util.JacksonCodecs;
import org.junit.Test;

public class MetadataObjectTest {
  public static final String JSON =
      "{"
          + "\"identifier\":\"foobar\","
          + "\"version\":1,"
          + "\"vendorInfo\":{\"name\":\"Yubico\",\"url\":\"https://yubico.com\",\"imageUrl\":\"https://developers.yubico.com/U2F/Images/yubico.png\"},"
          + "\"trustedCertificates\":[\"-----BEGIN CERTIFICATE-----\\nMIIDHjCCAgagAwIBAgIEG1BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ\\ndWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw\\nMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290\\nIENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\\nAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk\\n5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep\\n8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw\\nnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT\\n9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw\\nLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ\\nhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN\\nBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4\\nMYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt\\nhX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k\\nLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U\\nsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc\\nU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==\\n-----END CERTIFICATE-----\"],"
          + "\"devices\":[{"
          + "\"deviceId\":\"1.3.6.1.4.1.41482.1.2\","
          + "\"deviceUrl\":\"https://www.yubico.com/products/yubikey-hardware/yubikey-neo/\","
          + "\"displayName\":\"YubiKey NEO/NEO-n\","
          + "\"imageUrl\":\"https://developers.yubico.com/U2F/Images/NEO.png\","
          + "\"selectors\":[{"
          + "\"type\":\"x509Extension\","
          + "\"parameters\":{"
          + "\"key\":\"1.3.6.1.4.1.41482.1.2\""
          + "}"
          + "}]"
          + "}]"
          + "}";

  private final ObjectMapper objectMapper = JacksonCodecs.json();

  @Test
  public void testToAndFromJson() throws Exception {
    MetadataObject metadata = objectMapper.readValue(JSON, MetadataObject.class);
    ObjectMapper objectMapper = new ObjectMapper();
    MetadataObject metadata2 =
        objectMapper.readValue(objectMapper.writeValueAsString(metadata), MetadataObject.class);

    assertEquals("foobar", metadata.getIdentifier());
    assertEquals(1, metadata.getVersion());
    assertEquals(1, metadata.getTrustedCertificates().size());

    assertEquals("Yubico", metadata.getVendorInfo().get("name"));
    assertEquals("1.3.6.1.4.1.41482.1.2", metadata.getDevices().get(0).get("deviceId").asText());

    assertEquals(metadata, metadata2);
    assertEquals(JSON, objectMapper.writeValueAsString(metadata));
  }
}
