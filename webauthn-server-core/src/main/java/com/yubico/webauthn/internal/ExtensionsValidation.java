package com.yubico.webauthn.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.upokecenter.cbor.CBORObject;
import com.yubico.internal.util.StreamUtil;
import com.yubico.webauthn.data.AuthenticatorResponse;
import com.yubico.webauthn.data.PublicKeyCredential;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.experimental.UtilityClass;


@UtilityClass
public class ExtensionsValidation {

    public static boolean validate(Optional<JsonNode> requested, PublicKeyCredential<? extends AuthenticatorResponse> response) {
        if (requested.isPresent() && !requested.get().isObject()) {
            throw new IllegalArgumentException(String.format(
                "Requested extensions must be a JSON object, was: %s",
                requested.get()
            ));
        }

        Set<String> requestedExtensionIds = requested.map(req -> StreamUtil.toSet(req.fieldNames())).orElseGet(HashSet::new);
        Set<String> clientExtensionIds = StreamUtil.toSet(response.getClientExtensionResults().fieldNames());

        if (!requestedExtensionIds.containsAll(clientExtensionIds)) {
            throw new IllegalArgumentException(String.format(
                "Client extensions {%s} are not a subset of requested extensions {%s}.",
                String.join(", ", clientExtensionIds),
                String.join(", ", requestedExtensionIds)
            ));
        }

        Set<String> authenticatorExtensionIds = response.getResponse().getParsedAuthenticatorData().getExtensions()
            .map(extensions -> extensions.getKeys().stream()
                .map(CBORObject::AsString)
                .collect(Collectors.toSet())
            )
            .orElseGet(HashSet::new);

        if (!requestedExtensionIds.containsAll(authenticatorExtensionIds)) {
            throw new IllegalArgumentException(String.format(
                "Authenticator extensions {%s} are not a subset of requested extensions {%s}.",
                String.join(", ", authenticatorExtensionIds),
                String.join(", ", requestedExtensionIds)
            ));
        }

        return true;
    }

}
