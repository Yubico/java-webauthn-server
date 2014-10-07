// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package com.yubico.u2f.softkey;

import com.yubico.u2f.TestVectors;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.codec.RawMessageCodec;
import com.yubico.u2f.key.messages.AuthenticateResponse;
import com.yubico.u2f.key.messages.RegisterResponse;
import com.yubico.u2f.softkey.messages.AuthenticateRequest;
import com.yubico.u2f.softkey.messages.RegisterRequest;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class SoftKey {
  private static final Logger Log = Logger.getLogger(SoftKey.class.getName());

  private final X509Certificate vendorCertificate;
  private final PrivateKey certificatePrivateKey;
  private final Map<byte[], KeyPair> dataStore = new HashMap<byte[], KeyPair>();
  private final Crypto crypto;
  private int deviceCounter = 0;

  public SoftKey() {
    this.vendorCertificate = TestVectors.VENDOR_CERTIFICATE;
    this.certificatePrivateKey = TestVectors.VENDOR_CERTIFICATE_PRIVATE_KEY;
    this.crypto = new Crypto();
  }

  public RegisterResponse register(RegisterRequest registerRequest) throws U2fException, InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
    Log.info(">> register");

    byte[] applicationSha256 = registerRequest.getApplicationSha256();
    byte[] challengeSha256 = registerRequest.getChallengeSha256();

    Log.info(" -- Inputs --");
    Log.info("  applicationSha256: " + Hex.encodeHexString(applicationSha256));
    Log.info("  challengeSha256: " + Hex.encodeHexString(challengeSha256));


    // generate ECC key
    SecureRandom random = new SecureRandom();
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA");
    g.initialize(ecSpec, random);
    KeyPair keyPair = g.generateKeyPair();

    byte[] keyHandle = new byte[64];
    random.nextBytes(keyHandle);
    dataStore.put(keyHandle, keyPair);

    byte[] userPublicKey = keyPair.getPublic().getEncoded();

    byte[] signedData = RawMessageCodec.encodeRegistrationSignedBytes(applicationSha256, challengeSha256,
            keyHandle, userPublicKey);
    Log.info("Signing bytes " + Hex.encodeHexString(signedData));

    byte[] signature = crypto.sign(signedData, certificatePrivateKey);

    Log.info(" -- Outputs --");
    Log.info("  userPublicKey: " + Hex.encodeHexString(userPublicKey));
    Log.info("  keyHandle: " + Hex.encodeHexString(keyHandle));
    Log.info("  vendorCertificate: " + vendorCertificate);
    Log.info("  signature: " + Hex.encodeHexString(signature));

    Log.info("<< register");

    return new RegisterResponse(userPublicKey, keyHandle, vendorCertificate, signature);
  }

  public AuthenticateResponse authenticate(AuthenticateRequest authenticateRequest)
          throws U2fException {
    Log.info(">> authenticate");

    byte control = authenticateRequest.getControl();
    byte[] applicationSha256 = authenticateRequest.getApplicationSha256();
    byte[] challengeSha256 = authenticateRequest.getChallengeSha256();
    byte[] keyHandle = authenticateRequest.getKeyHandle();

    Log.info(" -- Inputs --");
    Log.info("  control: " + control);
    Log.info("  applicationSha256: " + Hex.encodeHexString(applicationSha256));
    Log.info("  challengeSha256: " + Hex.encodeHexString(challengeSha256));
    Log.info("  keyHandle: " + Hex.encodeHexString(keyHandle));

    KeyPair keyPair = dataStore.get(keyHandle);
    int counter = ++deviceCounter;
    byte userPresence = 0x1;
    byte[] signedData = RawMessageCodec.encodeAuthenticateSignedBytes(applicationSha256, userPresence,
            counter, challengeSha256);

    Log.info("Signing bytes " + Hex.encodeHexString(signedData));

    byte[] signature = crypto.sign(signedData, keyPair.getPrivate());

    Log.info(" -- Outputs --");
    Log.info("  userPresence: " + userPresence);
    Log.info("  deviceCounter: " + counter);
    Log.info("  signature: " + Hex.encodeHexString(signature));

    Log.info("<< authenticate");

    return new AuthenticateResponse(userPresence, counter, signature);
  }
}