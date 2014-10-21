package com.yubico.u2f.softkey;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import com.yubico.u2f.exceptions.U2fException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Crypto {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public byte[] sign(byte[] signedData, PrivateKey privateKey) throws U2fException {
    try {
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(privateKey);
      signature.update(signedData);
      return signature.sign();
    } catch (NoSuchAlgorithmException e) {
      throw new U2fException("Error when signing", e);
    } catch (SignatureException e) {
      throw new U2fException("Error when signing", e);
    } catch (InvalidKeyException e) {
      throw new U2fException("Error when signing", e);
    }
  }
}