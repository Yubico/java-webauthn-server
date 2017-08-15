/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableList;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.exceptions.U2fBadInputException;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import lombok.EqualsAndHashCode;

@JsonIgnoreProperties(ignoreUnknown = true)
@EqualsAndHashCode(of = { "data" })
public class MetadataObject extends JsonSerializable {
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
    public MetadataObject(JsonNode data) throws U2fBadInputException {
        this.data = data;
        try {
            vendorInfo = OBJECT_MAPPER.readValue(data.get("vendorInfo").traverse(), MAP_STRING_STRING_TYPE);
            trustedCertificates = OBJECT_MAPPER.readValue(data.get("trustedCertificates").traverse(), LIST_STRING_TYPE);
            devices = OBJECT_MAPPER.readValue(data.get("devices").traverse(), LIST_JSONNODE_TYPE);
        } catch (JsonMappingException e) {
            throw new U2fBadInputException("Invalid JSON data", e);
        } catch (JsonParseException e) {
            throw new U2fBadInputException("Invalid JSON data", e);
        } catch (IOException e) {
            throw new U2fBadInputException("Invalid JSON data", e);
        }

        identifier = data.get("identifier").asText();
        version = data.get("version").asLong();
    }

    @Override
    public String toJson() {
        return data.toString();
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

    public List<JsonNode> getDevices() {
        return MoreObjects.firstNonNull(devices, ImmutableList.<JsonNode>of());
    }

    public static List<MetadataObject> parseFromJson(String jsonData) throws U2fBadInputException {
        JsonNode items;
        try {
            items = OBJECT_MAPPER.readValue(jsonData, JsonNode.class);
            if (!items.isArray()) {
                items = OBJECT_MAPPER.createArrayNode().add(items);
            }
        } catch (IOException e) {
            throw new U2fBadInputException("Malformed data", e);
        }

        ImmutableList.Builder<MetadataObject> objects = ImmutableList.builder();
        for (JsonNode item : items) {
            objects.add(MetadataObject.fromJson(item.toString()));
        }
        return objects.build();
    }

    public static MetadataObject fromJson(String json) throws U2fBadInputException {
        try {
            return new MetadataObject(OBJECT_MAPPER.readTree(json));
        } catch (IOException e) {
            throw new U2fBadInputException("Malformed data", e);
        }
    }
}
