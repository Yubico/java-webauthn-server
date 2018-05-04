package com.yubico.u2f.json;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.data.messages.SignResponse;
import org.junit.Test;

import static com.google.common.base.Preconditions.checkNotNull;

public class SerializationTest {

    @Test
    public void tokenSignResponse() throws Exception {
        String response = "{ \"signatureData\": \"AQAAAAUwRAIgB1Q5iWRzC4zkZE2eIqoJZsXXCcg_6FVbZk-sMtLXcz4CIHxWaQsjLc-vD_kZLeg-p7IQ1HAmAFgiTk_dq6Q6iGcu\", \"clientData\": \"eyAiY2hhbGxlbmdlIjogIkQ1VG1CaEQzbTg0c3BRd3FfVm81VWZFSm8xV2JXTnBnRHdvZ0dWcmtBd00iLCAib3JpZ2luIjogImh0dHA6XC9cL2V4YW1wbGUuY29tIiwgInR5cCI6ICJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiB9\", \"keyHandle\": \"fSgg0l0JefF0GAFGAi9cOf5iL1nnzSswSmgpathyRRhsZ8QTzxPH1WAu8TqTbadfnNHOnINoF0UkMjKrxKVZLA\" }";
        SignResponse ar = new ObjectMapper().readValue(response, SignResponse.class);
        checkNotNull(ar.getKeyHandle());
        checkNotNull(ar.getClientData());
        checkNotNull(ar.getSignatureData());

    }
}
