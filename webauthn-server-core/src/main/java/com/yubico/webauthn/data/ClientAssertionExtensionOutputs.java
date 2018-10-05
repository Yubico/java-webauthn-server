package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
public class ClientAssertionExtensionOutputs implements ClientExtensionOutputs {

    @Builder.Default
    private final Optional<Boolean> appid = Optional.empty();

    @JsonCreator
    private ClientAssertionExtensionOutputs(
        @NonNull @JsonProperty("appid") Optional<Boolean> appid
    ) {
        this.appid = appid;
    }

    @Override
    public Set<String> getExtensionIds() {
        Set<String> ids = new HashSet<>();

        appid.ifPresent((id) -> ids.add("appid"));

        return ids;
    }

}
