package com.yubico.u2f.data.messages;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableSet;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.InvalidFacetException;
import com.yubico.u2f.exceptions.U2fBadInputException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

public class ClientData {

    private static final String TYPE_PARAM = "typ";
    private static final String CHALLENGE_PARAM = "challenge";
    private static final String ORIGIN_PARAM = "origin";

    private final String type;
    private final String challenge;
    private final String origin;
    private final String rawClientData;
    private final JsonObject jsonObject;

    public String asJson() {
        return rawClientData;
    }

    public ClientData(String clientData) {
        this.rawClientData = new String(U2fB64Encoding.decode(clientData));
        JsonElement clientDataAsElement = new JsonParser().parse(rawClientData);
        jsonObject = clientDataAsElement.getAsJsonObject();
        this.type = getString(TYPE_PARAM);
        this.challenge = getString(CHALLENGE_PARAM);
        this.origin = getString(ORIGIN_PARAM);
    }

    @Override
    public String toString() {
        return rawClientData;
    }

    public String getChallenge() {
        return challenge;
    }

    public String getString(String key) {
        return jsonObject.get(key).getAsString();
    }

    public void checkContent(String type, String challenge, Optional<Set<String>> facets) throws U2fBadInputException {
        if (!type.equals(this.type)) {
            throw new U2fBadInputException("Bad clientData: wrong type " + this.type);
        }
        if (!challenge.equals(this.challenge)) {
            throw new U2fBadInputException("Bad clientData: wrong challenge");
        }
        if (facets.isPresent()) {
            Set<String> allowedFacets = canonicalizeOrigins(facets.get());
            String canonicalOrigin;
            try {
                canonicalOrigin = canonicalizeOrigin(origin);
            } catch (RuntimeException e) {
                throw new U2fBadInputException("Bad clientData: Malformed origin", e);
            }
            verifyOrigin(canonicalOrigin, allowedFacets);
        }
    }

    private static void verifyOrigin(String origin, Set<String> allowedOrigins) throws InvalidFacetException {
        if (!allowedOrigins.contains(origin)) {
            throw new InvalidFacetException(origin +
                    " is not a recognized home origin for this backend");
        }
    }

    public static Set<String> canonicalizeOrigins(Set<String> origins) {
        ImmutableSet.Builder<String> result = ImmutableSet.builder();
        for (String origin : origins) {
            result.add(canonicalizeOrigin(origin));
        }
        return result.build();
    }

    public static String canonicalizeOrigin(String url) {
        try {
            URI uri = new URI(url);
            if (uri.getAuthority() == null) {
                return url;
            }
            return uri.getScheme() + "://" + uri.getAuthority();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("specified bad origin", e);
        }
    }
}
