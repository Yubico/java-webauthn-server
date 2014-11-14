package com.yubico.u2f.softkey.messages;

public class RegisterRequest {
    private final byte[] challengeSha256;
    private final byte[] applicationSha256;

    public RegisterRequest(byte[] applicationSha256, byte[] challengeSha256) {
        this.challengeSha256 = challengeSha256;
        this.applicationSha256 = applicationSha256;
    }

    /**
     * The challenge parameter is the SHA-256 hash of the Client Data, a
     * stringified JSON datastructure that the FIDO Client prepares. Among other
     * things, the Client Data contains the challenge from the relying party
     * (hence the name of the parameter). See below for a detailed explanation of
     * Client Data.
     */
    public byte[] getChallengeSha256() {
        return challengeSha256;
    }

    /**
     * The application parameter is the SHA-256 hash of the application identity
     * of the application requesting the registration
     */
    public byte[] getApplicationSha256() {
        return applicationSha256;
    }
}