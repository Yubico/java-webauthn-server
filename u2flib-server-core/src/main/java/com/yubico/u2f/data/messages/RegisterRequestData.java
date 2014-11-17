package com.yubico.u2f.data.messages;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.yubico.u2f.U2F;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.json.JsonObject;
import com.yubico.u2f.data.messages.json.Persistable;
import com.yubico.u2f.exceptions.U2fException;

import java.util.List;

public class RegisterRequestData extends JsonObject implements Persistable {
    private final List<AuthenticateRequest> authenticateRequests;
    private final List<RegisterRequest> registerRequests;

    public RegisterRequestData(String appId, Iterable<? extends DeviceRegistration> devices, U2F u2f, ChallengeGenerator challengeGenerator) {
        ImmutableList.Builder<AuthenticateRequest> authenticateRequests = ImmutableList.builder();
        for(DeviceRegistration device : devices) {
            authenticateRequests.add(u2f.startAuthentication(appId, device));
        }

        this.authenticateRequests = authenticateRequests.build();
        this.registerRequests = ImmutableList.of(u2f.startRegistration(appId, challengeGenerator.generateChallenge()));
    }

    private RegisterRequestData() {
        authenticateRequests = null;
        registerRequests = null; // Gson requires a no-args constructor.
    }

    public List<AuthenticateRequest> getAuthenticateRequests() {
        return ImmutableList.copyOf(authenticateRequests);
    }

    public List<RegisterRequest> getRegisterRequests() {
        return ImmutableList.copyOf(registerRequests);
    }

    public RegisterRequest getRegisterRequest(RegisterResponse response) {
        return Iterables.getOnlyElement(registerRequests);
    }

    public String getKey()  {
        return Iterables.getOnlyElement(registerRequests).getChallenge();
    }

    public static RegisterRequestData fromJson(String json) {
        return GSON.fromJson(json, RegisterRequestData.class);
    }
}
