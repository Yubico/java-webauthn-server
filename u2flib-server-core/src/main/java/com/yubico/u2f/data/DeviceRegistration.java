/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.MoreObjects;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.key.util.CertificateParser;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.InvalidDeviceCounterException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(of = { "keyHandle", "publicKey", "attestationCert" })
public class DeviceRegistration extends JsonSerializable implements Serializable {
    private static final long serialVersionUID = -142942195464329902L;
    public static final long INITIAL_COUNTER_VALUE = -1;

    @JsonProperty
    private final String keyHandle;
    @JsonProperty
    private final String publicKey;
    @JsonProperty
    private final String attestationCert;
    @JsonProperty
    private long counter;
    @JsonProperty
    private boolean compromised;

    @JsonCreator
    public DeviceRegistration(@JsonProperty("keyHandle") String keyHandle, @JsonProperty("publicKey") String publicKey, @JsonProperty("attestationCert") String attestationCert, @JsonProperty("counter") long counter, @JsonProperty("compromised") boolean compromised) {
        this.keyHandle = keyHandle;
        this.publicKey = publicKey;
        this.attestationCert = attestationCert;
        this.counter = counter;
        this.compromised = compromised;
    }

    public DeviceRegistration(String keyHandle, String publicKey, X509Certificate attestationCert, long counter)
            throws U2fBadInputException {
        this.keyHandle = keyHandle;
        this.publicKey = publicKey;
        try {
            this.attestationCert = U2fB64Encoding.encode(attestationCert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new U2fBadInputException("Malformed attestation certificate", e);
        }
        this.counter = counter;
    }

    public String getKeyHandle() {
        return keyHandle;
    }

    public String getPublicKey() {
        return publicKey;
    }

    @JsonIgnore
    public X509Certificate getAttestationCertificate() throws U2fBadInputException, CertificateException {
        if (attestationCert == null) {
            return null;
        } else {
            return CertificateParser.parseDer(U2fB64Encoding.decode(attestationCert));
        }
    }

    public long getCounter() {
        return counter;
    }

    public boolean isCompromised() {
        return compromised;
    }

    public void markCompromised() {
        compromised = true;
    }

    @Override
    public String toString() {
        X509Certificate certificate = null;
        try {
            certificate = getAttestationCertificate();
        } catch (CertificateException e) {
            // do nothing
        } catch (U2fBadInputException e) {
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

    public static DeviceRegistration fromJson(String json) throws U2fBadInputException {
        return fromJson(json, DeviceRegistration.class);
    }

    @Override
    public String toJson() {
        try {
            return OBJECT_MAPPER.writeValueAsString(new DeviceWithoutCertificate(keyHandle, publicKey, counter, compromised));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    public String toJsonWithAttestationCert() {
        return super.toJson();
    }

    public void checkAndUpdateCounter(long clientCounter) throws InvalidDeviceCounterException {
        if (clientCounter <= getCounter()) {
            markCompromised();
            throw new InvalidDeviceCounterException(this);
        }
        counter = clientCounter;
    }

    private static class DeviceWithoutCertificate {
        @JsonProperty
        private final String keyHandle;
        @JsonProperty
        private final String publicKey;
        @JsonProperty
        private final long counter;
        @JsonProperty
        private final boolean compromised;

        private DeviceWithoutCertificate(String keyHandle, String publicKey, long counter, boolean compromised) {
            this.keyHandle = keyHandle;
            this.publicKey = publicKey;
            this.counter = counter;
            this.compromised = compromised;
        }
    }
}
