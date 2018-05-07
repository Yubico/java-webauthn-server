package com.yubico.u2f.attestation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Iterables;
import com.yubico.u2f.exceptions.U2fBadConfigurationException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MetadataObjectTest {
    public static final String JSON = "{\"identifier\":\"foobar\",\"version\":1,\"trustedCertificates\":[\"-----BEGIN CERTIFICATE-----\\nMIIDHjCCAgagAwIBAgIEG1BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ\\ndWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw\\nMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290\\nIENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\\nAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk\\n5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep\\n8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw\\nnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT\\n9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw\\nLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ\\nhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN\\nBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4\\nMYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt\\nhX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k\\nLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U\\nsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc\\nU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==\\n-----END CERTIFICATE-----\"],\"vendorInfo\":{\"name\":\"Yubico\",\"url\":\"https://yubico.com\",\"imageUrl\":\"https://developers.yubico.com/U2F/Images/yubico.png\"},\"devices\":[{\"displayName\":\"YubiKey NEO/NEO-n\",\"deviceId\":\"1.3.6.1.4.1.41482.1.2\",\"deviceUrl\":\"https://www.yubico.com/products/yubikey-hardware/yubikey-neo/\",\"imageUrl\":\"https://developers.yubico.com/U2F/Images/NEO.png\",\"selectors\":[{\"type\":\"x509Extension\",\"parameters\":{\"key\":\"1.3.6.1.4.1.41482.1.2\"}}]}]}";

    @Test
    public void testToAndFromJson() throws Exception {
        MetadataObject metadata = MetadataObject.fromJson(JSON);
        ObjectMapper objectMapper = new ObjectMapper();
        MetadataObject metadata2 = objectMapper.readValue(objectMapper.writeValueAsString(metadata), MetadataObject.class);

        assertEquals("foobar", metadata.getIdentifier());
        assertEquals(1, metadata.getVersion());
        assertEquals(1, metadata.getTrustedCertificates().size());

        assertEquals("Yubico", metadata.getVendorInfo().get("name"));
        assertEquals("1.3.6.1.4.1.41482.1.2", metadata.getDevices().get(0).get("deviceId").asText());

        assertEquals(metadata, metadata2);
        assertEquals(JSON, metadata.toJson());
    }

    @Test
    public void testParseFromJson() throws U2fBadConfigurationException {
        MetadataObject parsed1 = Iterables.getOnlyElement(MetadataObject.parseFromJson(JSON));
        MetadataObject parsed2 = Iterables.getOnlyElement(MetadataObject.parseFromJson("[" + JSON + "]"));
        MetadataObject expected = MetadataObject.fromJson(JSON);

        assertEquals(expected.toJson(), parsed1.toJson());
        assertEquals(expected.toJson(), parsed2.toJson());
    }
}
