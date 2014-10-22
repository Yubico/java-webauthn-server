package com.yubico.u2f.testdata;

import com.yubico.u2f.TestUtils;
import org.apache.commons.codec.binary.Base64;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class TestDataUtils {

  static X509Certificate fetchCertificate(InputStream resourceAsStream) {
    Scanner in = new Scanner(resourceAsStream);
    return TestUtils.parseCertificate(Base64.decodeBase64(in.nextLine()));
  }
}
