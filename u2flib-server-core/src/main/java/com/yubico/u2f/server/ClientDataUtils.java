package com.yubico.u2f.server;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableSet;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.yubico.u2f.U2fException;
import org.apache.commons.codec.binary.Base64;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

public class ClientDataUtils {

  private static final String TYPE_PARAM = "typ";
  public static final String CHALLENGE_PARAM = "challenge";
  private static final String ORIGIN_PARAM = "origin";

    public static byte[] checkClientData(String clientDataBase64, String messageType, String challenge,
                                       Optional<Set<String>> facets)
          throws U2fException {

    byte[] clientDataBytes = Base64.decodeBase64(clientDataBase64);
    JsonObject clientData = toJsonObject(clientDataBytes);

    // check that the right "typ" parameter is present in the clientData JSON
    if (!clientData.has(TYPE_PARAM)) {
      throw new U2fException("Bad clientData: missing 'typ' param");
    }

    String type = clientData.get(TYPE_PARAM).getAsString();
    if (!messageType.equals(type)) {
      throw new U2fException("Bad clientData: bad type " + type);
    }

    // check that the right challenge is in the clientData
    if (!clientData.has(CHALLENGE_PARAM)) {
      throw new U2fException("Bad clientData: missing 'challenge' param");
    }

    if(facets.isPresent()) {
      if (clientData.has(ORIGIN_PARAM)) {
        verifyOrigin(
                clientData.get(ORIGIN_PARAM).getAsString(),
                ClientDataUtils.canonicalizeOrigins(facets.get())
        );
      }
    }

    String challengeFromClientData = clientData.get(CHALLENGE_PARAM).getAsString();
    if (!challengeFromClientData.equals(challenge)) {
      throw new U2fException("Wrong challenge signed in clientData");
    }

    // TODO: Deal with ChannelID

    return clientDataBytes;
  }

  public static JsonObject toJsonObject(byte[] clientDataBytes) throws U2fException {
    JsonElement clientDataAsElement = new JsonParser().parse(new String(clientDataBytes));
    if (!clientDataAsElement.isJsonObject()) {
      throw new U2fException("clientData has wrong format");
    }
    return clientDataAsElement.getAsJsonObject();
  }

  private static void verifyOrigin(String origin, Set<String> allowedOrigins) throws U2fException {
    if (!allowedOrigins.contains(canonicalizeOrigin(origin))) {
      throw new U2fException(origin +
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
      return uri.getScheme() + "://" + uri.getAuthority();
    } catch (URISyntaxException e) {
      throw new AssertionError("specified bad origin", e);
    }
  }
}
