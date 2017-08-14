package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.json.Persistable;
import com.yubico.u2f.exceptions.U2fBadInputException;
import java.util.List;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode
public class RegisterRequestData extends JsonSerializable implements Persistable {

    private static final long serialVersionUID = 60855174227617680L;

    @JsonProperty
    private final String appId;
    @JsonProperty
    private final List<RegisteredKey> registeredKeys;
    @JsonProperty
    private final List<RegisterRequest> registerRequests;

    public RegisterRequestData(@JsonProperty("appId") String appId, @JsonProperty("registeredKeys") List<RegisteredKey> registeredKeys, @JsonProperty("registerRequests") List<RegisterRequest> registerRequests) {
        this.appId = appId;
        this.registeredKeys = registeredKeys;
        this.registerRequests = registerRequests;
    }

    public RegisterRequestData(String appId, Iterable<? extends DeviceRegistration> devices, U2fPrimitives u2f, ChallengeGenerator challengeGenerator) {
        this.appId = appId;

        ImmutableList.Builder<RegisteredKey> registeredKeys = ImmutableList.builder();
        for (DeviceRegistration device : devices) {
            if(!device.isCompromised()) {
                registeredKeys.add(new RegisteredKey(device.getKeyHandle()));
            }
        }

        this.registeredKeys = registeredKeys.build();
        this.registerRequests = ImmutableList.of(u2f.startRegistration(appId, challengeGenerator.generateChallenge()));
    }

    public List<RegisteredKey> getRegisteredKeys() {
        return ImmutableList.copyOf(registeredKeys);
    }

    public List<RegisterRequest> getRegisterRequests() {
        return ImmutableList.copyOf(registerRequests);
    }

    public RegisterRequest getRegisterRequest(RegisterResponse response) {
        return Iterables.getOnlyElement(registerRequests);
    }

    public String getRequestId() {
        return Iterables.getOnlyElement(registerRequests).getChallenge();
    }

    public static RegisterRequestData fromJson(String json) throws U2fBadInputException {
        return fromJson(json, RegisterRequestData.class);
    }
}
