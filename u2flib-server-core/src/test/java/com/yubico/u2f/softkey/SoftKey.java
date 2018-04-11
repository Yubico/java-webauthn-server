// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package com.yubico.u2f.softkey;

import com.yubico.u2f.data.messages.key.RawSignResponse;
import com.yubico.u2f.data.messages.key.RawRegisterResponse;
import com.yubico.u2f.data.messages.key.util.ByteInputStream;
import com.yubico.u2f.softkey.messages.SignRequest;
import com.yubico.u2f.softkey.messages.RegisterRequest;
import com.yubico.u2f.testdata.GnubbyKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Preconditions.checkNotNull;

public final class SoftKey implements Cloneable {

    private final X509Certificate attestationCertificate;
    private final PrivateKey certificatePrivateKey;
    private final Map<String, KeyPair> dataStore;
    private long deviceCounter = 0;

    public SoftKey() {
        this(
                new HashMap<String, KeyPair>(),
                0,
                GnubbyKey.ATTESTATION_CERTIFICATE,
                GnubbyKey.ATTESTATION_CERTIFICATE_PRIVATE_KEY
        );
    }

    public SoftKey(
            Map<String, KeyPair> dataStore,
            long deviceCounter,
            X509Certificate attestationCertificate,
            PrivateKey certificatePrivateKey
    ) {
        this.dataStore = dataStore;
        this.deviceCounter = deviceCounter;
        this.attestationCertificate = attestationCertificate;
        this.certificatePrivateKey = certificatePrivateKey;
    }

    @Override
    public SoftKey clone() {
        return new SoftKey(
                this.dataStore,
                this.deviceCounter,
                this.attestationCertificate,
                this.certificatePrivateKey
        );
    }

    public RawRegisterResponse register(RegisterRequest registerRequest) throws Exception {

        byte[] applicationSha256 = registerRequest.getApplicationSha256();
        byte[] challengeSha256 = registerRequest.getChallengeSha256();

        // generate ECC key
        SecureRandom random = new SecureRandom();
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA");
        g.initialize(ecSpec, random);
        KeyPair keyPair = g.generateKeyPair();

        byte[] keyHandle = new byte[64];
        random.nextBytes(keyHandle);
        dataStore.put(new String(keyHandle), keyPair);

        byte[] userPublicKey = stripMetaData(keyPair.getPublic().getEncoded());

        byte[] signedData = RawRegisterResponse.packBytesToSign(applicationSha256, challengeSha256,
                keyHandle, userPublicKey);

        byte[] signature = sign(signedData, certificatePrivateKey);

        return new RawRegisterResponse(userPublicKey, keyHandle, attestationCertificate, signature);
    }

    private byte[] stripMetaData(byte[] a) {
        ByteInputStream bis = new ByteInputStream(a);
        try {
            bis.read(3);
            bis.read(bis.readUnsigned() + 1);
            int keyLength = bis.readUnsigned();
            bis.read(1);
            return bis.read(keyLength - 1);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public RawSignResponse sign(SignRequest signRequest) throws Exception {

        byte[] applicationSha256 = signRequest.getApplicationSha256();
        byte[] challengeSha256 = signRequest.getChallengeSha256();
        byte[] keyHandle = signRequest.getKeyHandle();

        KeyPair keyPair = checkNotNull(dataStore.get(new String(keyHandle)));
        long counter = ++deviceCounter;
        byte[] signedData = RawSignResponse.packBytesToSign(applicationSha256, RawSignResponse.USER_PRESENT_FLAG,
                counter, challengeSha256);

        byte[] signature = sign(signedData, keyPair.getPrivate());

        return new RawSignResponse(RawSignResponse.USER_PRESENT_FLAG, counter, signature);
    }

    private byte[] sign(byte[] signedData, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(signedData);
        return signature.sign();
    }
}
