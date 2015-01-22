package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.json.Persistable;
import com.yubico.u2f.exceptions.U2fBadInputException;

import java.util.List;

public class RegisterRequestData extends JsonSerializable implements Persistable {

    private static final long serialVersionUID = 60855174227617680L;

    @JsonProperty
    private final List<AuthenticateRequest> authenticateRequests;
    @JsonProperty
    private final List<RegisterRequest> registerRequests;

    private RegisterRequestData(@JsonProperty("authenticateRequests") List<AuthenticateRequest> authenticateRequests, @JsonProperty("registerRequests") List<RegisterRequest> registerRequests) {
        this.authenticateRequests = authenticateRequests;
        this.registerRequests = registerRequests;
    }

    public RegisterRequestData(String appId, Iterable<? extends DeviceRegistration> devices, U2fPrimitives u2f, ChallengeGenerator challengeGenerator) {
        ImmutableList.Builder<AuthenticateRequest> authenticateRequests = ImmutableList.builder();
        for (DeviceRegistration device : devices) {
            if(!device.isCompromised()) {
                authenticateRequests.add(u2f.startAuthentication(appId, device));
            }
        }

        this.authenticateRequests = authenticateRequests.build();
        this.registerRequests = ImmutableList.of(u2f.startRegistration(appId, challengeGenerator.generateChallenge()));
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

    public String getRequestId() {
        return Iterables.getOnlyElement(registerRequests).getChallenge();
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(authenticateRequests, registerRequests);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof RegisterRequestData))
            return false;
        RegisterRequestData other = (RegisterRequestData) obj;
        return Objects.equal(authenticateRequests, other.authenticateRequests)
                && Objects.equal(registerRequests, other.registerRequests);
    }

    public static RegisterRequestData fromJson(String json) throws U2fBadInputException {
        return fromJson(json, RegisterRequestData.class);
    }
}
