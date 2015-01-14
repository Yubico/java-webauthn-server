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
    public static final Type STRING_TO_STRING_MAP = new TypeToken<Map<String, String>>() {
    }.getType();
    public static final Type STRING_LIST = new TypeToken<List<String>>() {
    }.getType();

    private final JsonObject data;

    private final String identifier;
    private final long version;
    private final Map<String, String> vendorInfo;
    private final List<String> trustedCertificates;
    private final List<JsonObject> devices;

    private MetadataObject() {
        data = null;
        identifier = null;
        version = -1;
        vendorInfo = null;
        trustedCertificates = null;
        devices = null; // Gson requires a no-args constructor.
    }

    public MetadataObject(JsonObject jsonData) {
        data = jsonData;
        identifier = data.get("identifier").getAsString();
        version = data.get("version").getAsLong();
        vendorInfo = GSON.fromJson(data.get("vendorInfo"), STRING_TO_STRING_MAP);
        trustedCertificates = GSON.fromJson(data.get("trustedCertificates"), STRING_LIST);
        ImmutableList.Builder<JsonObject> devicesBuilder = ImmutableList.builder();
        for (JsonElement deviceElement : data.get("devices").getAsJsonArray()) {
            devicesBuilder.add(deviceElement.getAsJsonObject());
        }
        devices = devicesBuilder.build();
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
            objects.add(new MetadataObject(item.getAsJsonObject()));
        }
        return objects.build();
    }

    public static MetadataObject fromJson(String json) {
        return fromJson(json, MetadataObject.class);
    }
}
