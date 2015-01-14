/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data;

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.key.util.ByteInputStream;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.InvalidDeviceCounterException;
import com.yubico.u2f.exceptions.U2fException;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class DeviceRegistration extends JsonSerializable implements Serializable {
    private static final long serialVersionUID = -142942195464329902L;
    public static final long INITIAL_COUNTER_VALUE = -1;

    private final String keyHandle;
    private final String publicKey;
    private final String attestationCert;
    private long counter;

    private DeviceRegistration() {
        keyHandle = null;
        publicKey = null;
        attestationCert = null; // Gson requires a no-args constructor.
    }

    public DeviceRegistration(String keyHandle, String publicKey, X509Certificate attestationCert, long counter)
            throws U2fException {
        this.keyHandle = keyHandle;
        this.publicKey = publicKey;
        try {
            this.attestationCert = U2fB64Encoding.encode(attestationCert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new U2fException("Invalid attestation certificate", e);
        }
        this.counter = counter;
    }

    public String getKeyHandle() {
        return keyHandle;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public X509Certificate getAttestationCertificate() throws CertificateException, NoSuchFieldException {
        if (attestationCert == null) {
            throw new NoSuchFieldException();
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteInputStream(U2fB64Encoding.decode(attestationCert)));
    }

    public long getCounter() {
        return counter;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(keyHandle, publicKey, attestationCert);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof DeviceRegistration)) {
            return false;
        }
        DeviceRegistration that = (DeviceRegistration) obj;
        return Objects.equal(this.keyHandle, that.keyHandle)
                && Objects.equal(this.publicKey, that.publicKey)
                && Objects.equal(this.attestationCert, that.attestationCert);
    }

    @Override
    public String toString() {
        X509Certificate certificate = null;
        try {
            certificate = getAttestationCertificate();
        } catch (CertificateException e) {
            // do nothing
        } catch (NoSuchFieldException e) {
            // do nothing
        }
        return MoreObjects.toStringHelper(this)
                .omitNullValues()
                .add("Key handle", keyHandle)
                .add("Public key", publicKey)
                .add("Counter", counter)
                .add("Attestation certificate", certificate)
                .toString();
    }

    public static DeviceRegistration fromJson(String json) {
        return fromJson(json, DeviceRegistration.class);
    }

    @Override
    public String toJson() {
        return GSON.toJson(new DeviceWithoutCertificate(keyHandle, publicKey, counter));
    }

    public String toJsonWithAttestationCert() {
        return super.toJson();
    }

    public void checkAndUpdateCounter(long clientCounter) throws U2fException {
        if (clientCounter <= counter) {
            throw new InvalidDeviceCounterException();
        }
        counter = clientCounter;
    }

    private static class DeviceWithoutCertificate {
        private final String keyHandle;
        private final String publicKey;
        private final long counter;

        private DeviceWithoutCertificate(String keyHandle, String publicKey, long counter) {
            this.keyHandle = keyHandle;
            this.publicKey = publicKey;
            this.counter = counter;
        }
    }
}
