package com.yubico.fido.metadata;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.databind.util.Converter;
import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.data.ByteArray;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class CertFromBase64Converter implements Converter<String, X509Certificate> {
  @Override
  public X509Certificate convert(String value) {
    try {
      return CertificateParser.parseDer(ByteArray.fromBase64(value).getBytes());
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public JavaType getInputType(TypeFactory typeFactory) {
    return typeFactory.constructType(String.class);
  }

  @Override
  public JavaType getOutputType(TypeFactory typeFactory) {
    return typeFactory.constructType(X509Certificate.class);
  }
}
