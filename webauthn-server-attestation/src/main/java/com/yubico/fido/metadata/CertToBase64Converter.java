package com.yubico.fido.metadata;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.databind.util.Converter;
import com.yubico.webauthn.data.ByteArray;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

class CertToBase64Converter implements Converter<X509Certificate, String> {
  @Override
  public String convert(X509Certificate value) {
    try {
      return new ByteArray(value.getEncoded()).getBase64();
    } catch (CertificateEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public JavaType getInputType(TypeFactory typeFactory) {
    return typeFactory.constructType(X509Certificate.class);
  }

  @Override
  public JavaType getOutputType(TypeFactory typeFactory) {
    return typeFactory.constructType(String.class);
  }
}
