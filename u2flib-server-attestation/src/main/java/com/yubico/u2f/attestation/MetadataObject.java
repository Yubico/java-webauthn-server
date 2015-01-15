/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableList;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.yubico.u2f.data.messages.json.JsonSerializable;

import java.lang.reflect.Type;
import java.util.List;
import java.util.Map;

public class MetadataObject extends JsonSerializable {
    private static final Type MAP_STRING_STRING_TYPE = new TypeToken<Map<String, String>>() {
    }.getType();
    private static final Type LIST_STRING_TYPE = new TypeToken<List<String>>() {
    }.getType();
    private static final Type LIST_JSONOBJECT_TYPE = new TypeToken<List<JsonObject>>() {
    }.getType();

    private final transient String json;

    private final String identifier;
    private final long version;
    private final Map<String, String> vendorInfo;
    private final List<String> trustedCertificates;
    private final List<JsonObject> devices;

    private MetadataObject(String json) {
        this.json = json;
        JsonObject data = new JsonParser().parse(json).getAsJsonObject();

        identifier = data.get("identifier").getAsString();
        version = data.get("version").getAsLong();
        vendorInfo = GSON.fromJson(data.get("vendorInfo"), MAP_STRING_STRING_TYPE);
        trustedCertificates = GSON.fromJson(data.get("trustedCertificates"), LIST_STRING_TYPE);
        devices = GSON.fromJson(data.get("devices"), LIST_JSONOBJECT_TYPE);
    }

    @Override
    public String toJson() {
        return json;
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

    public List<JsonObject> getDevices() {
        return MoreObjects.firstNonNull(devices, ImmutableList.<JsonObject>of());
    }

    public static List<MetadataObject> parseFromJson(String jsonData) {
        JsonParser parser = new JsonParser();
        JsonElement parsed = parser.parse(jsonData);
        JsonArray items;
        if (!parsed.isJsonArray()) {
            items = new JsonArray();
            items.add(parsed);
        } else {
            items = parsed.getAsJsonArray();
        }
        ImmutableList.Builder<MetadataObject> objects = ImmutableList.builder();
        for (JsonElement item : items) {
            objects.add(MetadataObject.fromJson(item.toString()));
        }
        return objects.build();
    }

    public static MetadataObject fromJson(String json) {
        return new MetadataObject(json);
    }
}
