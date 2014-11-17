package com.yubico.u2f.data.messages;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.yubico.u2f.U2F;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.json.JsonObject;
import com.yubico.u2f.data.messages.json.Persistable;
import com.yubico.u2f.exceptions.U2fException;

import java.util.List;

public class AuthenticateRequestData extends JsonObject implements Persistable {
    private final List<AuthenticateRequest> authenticateRequests;

    public AuthenticateRequestData(String appId, Iterable<? extends DeviceRegistration> devices, U2F u2f, ChallengeGenerator challengeGenerator) {
        ImmutableList.Builder<AuthenticateRequest> requestBuilder = ImmutableList.builder();
        byte[] challenge = challengeGenerator.generateChallenge();
        for(DeviceRegistration device : devices) {
            requestBuilder.add(u2f.startAuthentication(appId, device, challenge));
        }
        this.authenticateRequests = requestBuilder.build();
    }

    public List<AuthenticateRequest> getAuthenticateRequests() {
        return ImmutableList.copyOf(authenticateRequests);
    }

    public AuthenticateRequest getAuthenticateRequest(AuthenticateResponse response) throws U2fException {
        if(!Objects.equal(getKey(), response.getKey())) {
            throw new U2fException("Wrong request for response data");
        }
        for(AuthenticateRequest request : authenticateRequests) {
            if(Objects.equal(request.getKeyHandle(), response.getKeyHandle())) {
                return request;
            }
        }
        throw new U2fException("Unknown keyHandle");
    }

    public String getKey() {
        return Iterables.getFirst(authenticateRequests, null).getChallenge();
    }

    public static AuthenticateRequestData fromJson(String json) {
        return GSON.fromJson(json, AuthenticateRequestData.class);
    }
}
