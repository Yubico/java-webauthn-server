package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.json.JsonSerializable;
import com.yubico.u2f.data.messages.json.Persistable;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.NoEligibleDevicesException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import java.util.List;
import lombok.EqualsAndHashCode;

import static com.google.common.base.Preconditions.checkArgument;

@EqualsAndHashCode
public class SignRequestData extends JsonSerializable implements Persistable {

    private static final long serialVersionUID = 35378338769078256L;

    @JsonProperty
    private final String appId;

    /**
     * The websafe-base64-encoded challenge.
     */
    @JsonProperty
    private final String challenge;

    @JsonProperty
    private final List<SignRequest> signRequests;

    @JsonCreator
    public SignRequestData(@JsonProperty("appId") String appId, @JsonProperty("challenge") String challenge, @JsonProperty("signRequests") List<SignRequest> signRequests) {
        this.appId = appId;
        this.challenge = challenge;
        this.signRequests = signRequests;
    }

    public SignRequestData(String appId, Iterable<? extends DeviceRegistration> devices, U2fPrimitives u2f, ChallengeGenerator challengeGenerator) throws NoEligibleDevicesException {
        this.appId = appId;

        byte[] challenge = challengeGenerator.generateChallenge();
        this.challenge = U2fB64Encoding.encode(challenge);

        ImmutableList.Builder<SignRequest> requestBuilder = ImmutableList.builder();
        for (DeviceRegistration device : devices) {
            if(!device.isCompromised()) {
                requestBuilder.add(u2f.startSignature(appId, device, challenge));
            }
        }
        signRequests = requestBuilder.build();

        if (signRequests.isEmpty()) {
            if(Iterables.isEmpty(devices)) {
                throw new NoEligibleDevicesException(ImmutableList.<DeviceRegistration>of(), "No devices registrered");
            } else {
                throw new NoEligibleDevicesException(devices, "All devices compromised");
            }
        }
    }

    public List<SignRequest> getSignRequests() {
        return ImmutableList.copyOf(signRequests);
    }

    public SignRequest getSignRequest(SignResponse response) throws U2fBadInputException {
        checkArgument(Objects.equal(getRequestId(), response.getRequestId()), "Wrong request for response data");

        for (SignRequest request : signRequests) {
            if (Objects.equal(request.getKeyHandle(), response.getKeyHandle())) {
                return request;
            }
        }
        throw new U2fBadInputException("Responses keyHandle does not match any contained request");
    }

    public String getRequestId() {
        return signRequests.get(0).getChallenge();
    }

    public static SignRequestData fromJson(String json) throws U2fBadInputException {
        return fromJson(json, SignRequestData.class);
    }
}
