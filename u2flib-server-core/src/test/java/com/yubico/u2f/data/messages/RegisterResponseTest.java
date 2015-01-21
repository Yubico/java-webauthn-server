package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.TestUtils;
import org.junit.Test;

import static com.yubico.u2f.testdata.TestVectors.*;
import static org.junit.Assert.assertEquals;

public class RegisterResponseTest {
    public static final String JSON = "{\"registrationData\":\"BQSxdLxJx8olS3DS5cIHzunPF0gg69d-o8ZVCMJtpRtlfBzGuVL4YhaXk2SC2gptPTgmpZCV2vbNfAPi5gOF0vbZQCpVLf23R37WX9hBM_hhlgELIhW1faddMVt7no_i45JaYBlVG6th0WWRZZy68AtJUPer_mZg4uAG92hot3LXDCUwggE8MIHkoAMCAQICCkeQEoAAEVWVc1IwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAxMMR251YmJ5IFBpbG90MB4XDTEyMDgxNDE4MjkzMloXDTEzMDgxNDE4MjkzMlowMTEvMC0GA1UEAxMmUGlsb3RHbnViYnktMC40LjEtNDc5MDEyODAwMDExNTU5NTczNTIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNYX5lyVCOZLzFZzrIKmeZ2jwURmgsJYxGP__fWN_S-j5sN4tT15XEpN_7QZnt14YvI6uvAgO0uJEboFaZlOEBMAoGCCqGSM49BAMCA0cAMEQCIGDNtgYenCImLRqsHZbYxwgpsjZlMd2iaIMsuDa80w36AiBjGxRZ8J5jMAVXIsjYm39IiDuQibiNYNHZeVkCswQQ3zBFAiAUcYmbzDmH5i6CAsmznDPBkDP3NANS26gPyrAX25Iw5AIhAIJnfWc9iRkzreb2F-Xb3i4kfnBCP9WteASm09OWHvhx\",\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoib3BzWHFVaWZEcmlBQW1XY2xpbmZiUzBlLVVTWTBDZ3lKSGVfT3RkN3o4byIsImNpZF9wdWJrZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJIelF3bGZYWDdRNFM1TXRDQ25aVU5CdzNSTXpQTzl0T3lXakJxUmw0dEo4IiwieSI6IlhWZ3VHRkxJWngxZlhnM3dOcWZkYm43NWhpNC1fNy1CeGhNbGp3NDJIdDQifSwib3JpZ2luIjoiaHR0cDovL2V4YW1wbGUuY29tIn0\"}";

    @Test
    public void testGetters() throws Exception {
        RegisterResponse registerResponse = new RegisterResponse(REGISTRATION_DATA_BASE64, CLIENT_DATA_AUTHENTICATE_BASE64);

        assertEquals(CLIENT_DATA_AUTHENTICATE, registerResponse.getClientData().toString());
        assertEquals(REGISTRATION_DATA_BASE64, registerResponse.getRegistrationData());
    }

    @Test
    public void testToAndFromJson() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        RegisterResponse registerResponse = RegisterResponse.fromJson(JSON);
        RegisterResponse registerResponse2 = objectMapper.readValue(registerResponse.toJson(), RegisterResponse.class);

        assertEquals(registerResponse, registerResponse2);
        assertEquals(registerResponse.getRequestId(), registerResponse2.getRequestId());
        assertEquals(registerResponse.toJson(), objectMapper.writeValueAsString(registerResponse));
    }

    @Test
    public void testJavaSerializer() throws Exception {
        RegisterResponse registerResponse = RegisterResponse.fromJson(JSON);
        RegisterResponse registerResponse2 = TestUtils.clone(registerResponse);

        assertEquals(registerResponse, registerResponse2);
        assertEquals(registerResponse.getRequestId(), registerResponse2.getRequestId());
    }

}