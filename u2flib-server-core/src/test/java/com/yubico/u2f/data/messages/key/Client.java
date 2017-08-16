package com.yubico.u2f.data.messages.key;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.SignRequest;
import com.yubico.u2f.data.messages.SignResponse;
import com.yubico.u2f.data.messages.RegisterRequest;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.u2f.softkey.SoftKey;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class Client {
    public static final byte REGISTRATION_RESERVED_BYTE_VALUE = (byte) 0x05;
    public static final ImmutableSet<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
    public static final String APP_ID = "my-app";

    private final BouncyCastleCrypto crypto = new BouncyCastleCrypto();
    private final SoftKey key;
    private final U2fPrimitives u2f = new U2fPrimitives();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public Client(SoftKey key) {
        this.key = key;
    }

    public static byte[] encodeRegisterResponse(RawRegisterResponse rawRegisterResponse)
            throws U2fBadInputException {
        byte[] userPublicKey = rawRegisterResponse.userPublicKey;
        byte[] keyHandle = rawRegisterResponse.keyHandle;
        X509Certificate attestationCertificate = rawRegisterResponse.attestationCertificate;
        byte[] signature = rawRegisterResponse.signature;

        byte[] attestationCertificateBytes;
        try {
            attestationCertificateBytes = attestationCertificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new U2fBadInputException("Error when encoding attestation certificate.", e);
        }

        if (keyHandle.length > 255) {
            throw new U2fBadInputException("keyHandle length cannot be longer than 255 bytes!");
        }

        byte[] result = new byte[1 + userPublicKey.length + 1 + keyHandle.length
                + attestationCertificateBytes.length + signature.length];
        ByteBuffer.wrap(result)
                .put(REGISTRATION_RESERVED_BYTE_VALUE)
                .put(userPublicKey)
                .put((byte) keyHandle.length)
                .put(keyHandle)
                .put(attestationCertificateBytes)
                .put(signature);
        return result;
    }

    public static RegisterResponse encodeTokenRegistrationResponse(String clientDataJson, RawRegisterResponse registerResponse) throws U2fBadInputException {
        byte[] rawRegisterResponse = Client.encodeRegisterResponse(registerResponse);
        String rawRegisterResponseBase64 = U2fB64Encoding.encode(rawRegisterResponse);
        String clientDataBase64 = U2fB64Encoding.encode(clientDataJson.getBytes());
        return new RegisterResponse(rawRegisterResponseBase64, clientDataBase64);
    }

    public DeviceRegistration register() throws Exception {
        RegisterRequest registerRequest = u2f.startRegistration(APP_ID);

        Map<String, String> clientData = new HashMap<String, String>();
        clientData.put("typ", "navigator.id.finishEnrollment");
        clientData.put("challenge", registerRequest.getChallenge());
        clientData.put("origin", "http://example.com");
        String clientDataJson = objectMapper.writeValueAsString(clientData);

        byte[] clientParam = crypto.hash(clientDataJson);
        byte[] appParam = crypto.hash(registerRequest.getAppId());

        RawRegisterResponse rawRegisterResponse = key.register(new com.yubico.u2f.softkey.messages.RegisterRequest(appParam, clientParam));

        // client encodes data
        RegisterResponse tokenResponse = Client.encodeTokenRegistrationResponse(clientDataJson, rawRegisterResponse);

        return u2f.finishRegistration(registerRequest, tokenResponse, TRUSTED_DOMAINS);
    }

    public SignResponse sign(DeviceRegistration registeredDevice, SignRequest startedSignature) throws Exception {
        Map<String, String> clientData = new HashMap<String, String>();
        clientData.put("typ", "navigator.id.getAssertion");
        clientData.put("challenge", startedSignature.getChallenge());
        clientData.put("origin", "http://example.com");
        String clientDataJson = objectMapper.writeValueAsString(clientData);


        byte[] clientParam = crypto.hash(clientDataJson);
        byte[] appParam = crypto.hash(startedSignature.getAppId());
        com.yubico.u2f.softkey.messages.SignRequest signRequest = new com.yubico.u2f.softkey.messages.SignRequest((byte) 0x01, clientParam, appParam, U2fB64Encoding.decode(registeredDevice.getKeyHandle()));

        RawSignResponse rawSignResponse = key.sign(signRequest);

        String clientDataBase64 = U2fB64Encoding.encode(clientDataJson.getBytes());
        ByteArrayDataOutput authData = ByteStreams.newDataOutput();
        authData.write(rawSignResponse.getUserPresence());
        authData.writeInt((int) rawSignResponse.getCounter());
        authData.write(rawSignResponse.getSignature());

        return new SignResponse(
                clientDataBase64,
                U2fB64Encoding.encode(authData.toByteArray()),
                startedSignature.getKeyHandle()
        );
    }
}
