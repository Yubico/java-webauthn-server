package com.yubico.u2f.testdata;

import java.security.cert.X509Certificate;

import static com.yubico.u2f.testdata.TestDataUtils.fetchCertificate;

public class YubiKey {

  public static final X509Certificate ATTESTATION_CERTIFICATE =
          fetchCertificate(YubiKey.class.getResourceAsStream("yubikey/attestation-certificate.der"));
}
