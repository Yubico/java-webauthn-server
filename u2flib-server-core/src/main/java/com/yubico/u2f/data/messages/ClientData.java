package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;

import java.io.IOException;
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

    public String asJson() {
        return rawClientData;
    }

    public ClientData(String clientData) throws U2fBadInputException {
        rawClientData = new String(U2fB64Encoding.decode(clientData));
        try {
            JsonNode data = new ObjectMapper().readTree(rawClientData);
            type = getString(data, TYPE_PARAM);
            challenge = getString(data, CHALLENGE_PARAM);
            origin = getString(data, ORIGIN_PARAM);
        } catch (IOException e) {
            throw new U2fBadInputException("Malformed ClientData", e);
        }
    }

    @Override
    public String toString() {
        return rawClientData;
    }

    public String getChallenge() {
        return challenge;
    }

    private static String getString(JsonNode data, String key) throws U2fBadInputException {
        JsonNode node = data.get(key);
        if (node == null) {
            throw new U2fBadInputException("Bad clientData: missing field " + key);
        }
        if (!node.isTextual()) {
            throw new U2fBadInputException("Bad clientData: field " + key + " not a string");
        }
        return node.asText();
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

    private static void verifyOrigin(String origin, Set<String> allowedOrigins) throws U2fBadInputException {
        if (!allowedOrigins.contains(origin)) {
            throw new U2fBadInputException(origin +
                    " is not a recognized facet for this application");
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
