package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.extension.appid.AppId;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder(toBuilder = true)
public class AssertionExtensionInputs implements ExtensionInputs {

    @Builder.Default
    private final Optional<AppId> appid = Optional.empty();

    @JsonCreator
    private AssertionExtensionInputs(
        @NonNull @JsonProperty("appid") Optional<AppId> appid
    ) {
        this.appid = appid;
    }

    @Override
    @JsonIgnore
    public Set<String> getExtensionIds() {
        Set<String> ids = new HashSet<>();

        appid.ifPresent((id) -> ids.add("appid"));

        return ids;
    }

}
