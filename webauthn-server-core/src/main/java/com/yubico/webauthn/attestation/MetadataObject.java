/* Copyright 2015 Yubico */

package com.yubico.webauthn.attestation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableList;
import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.WebAuthnCodecs;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.EqualsAndHashCode;

@JsonIgnoreProperties(ignoreUnknown = true)
@EqualsAndHashCode(of = { "data" }, callSuper = false)
public class MetadataObject {
    private static final ObjectMapper OBJECT_MAPPER = WebAuthnCodecs.json();

    private static final TypeReference<Map<String, String>> MAP_STRING_STRING_TYPE = new TypeReference<Map<String, String>>() {
    };
    private static final TypeReference LIST_STRING_TYPE = new TypeReference<List<String>>() {
    };
    private static final TypeReference LIST_JSONNODE_TYPE = new TypeReference<List<JsonNode>>() {
    };

    private final transient JsonNode data;

    private final String identifier;
    private final long version;
    private final Map<String, String> vendorInfo;
    private final List<String> trustedCertificates;
    private final List<JsonNode> devices;

    @JsonCreator
    public MetadataObject(JsonNode data) {
        this.data = data;
        try {
            vendorInfo = OBJECT_MAPPER.readValue(data.get("vendorInfo").traverse(), MAP_STRING_STRING_TYPE);
            trustedCertificates = OBJECT_MAPPER.readValue(data.get("trustedCertificates").traverse(), LIST_STRING_TYPE);
            devices = OBJECT_MAPPER.readValue(data.get("devices").traverse(), LIST_JSONNODE_TYPE);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid JSON data", e);
        }

        identifier = data.get("identifier").asText();
        version = data.get("version").asLong();
    }

    public String getIdentifier() {
        return identifier;
    }

    public long getVersion() {
        return version;
    }

    public Map<String, String> getVendorInfo() {
        return vendorInfo;
    }

    public List<String> getTrustedCertificates() {
        return trustedCertificates;
    }

    @JsonIgnore
    public List<X509Certificate> getParsedTrustedCertificates() throws CertificateException {
        List<X509Certificate> list = new ArrayList<>();
        for (String trustedCertificate : trustedCertificates) {
            X509Certificate x509Certificate = CertificateParser.parsePem(trustedCertificate);
            list.add(x509Certificate);
        }
        return list;
    }

    public List<JsonNode> getDevices() {
        return MoreObjects.firstNonNull(devices, ImmutableList.of());
    }

}
