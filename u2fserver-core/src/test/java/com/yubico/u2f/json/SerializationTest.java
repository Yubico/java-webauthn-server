package com.yubico.u2f.json;

import com.google.gson.Gson;
import com.yubico.u2f.server.messages.AuthenticationResponse;
import org.junit.Test;

import static com.google.common.base.Preconditions.checkNotNull;

public class SerializationTest {

  Gson gson = new Gson();

  @Test
  public void tokenAuthenticationResponse() throws Exception {
    String response = "{ \"signatureData\": \"AQAAAAUwRAIgB1Q5iWRzC4zkZE2eIqoJZsXXCcg_6FVbZk-sMtLXcz4CIHxWaQsjLc-vD_kZLeg-p7IQ1HAmAFgiTk_dq6Q6iGcu\", \"clientData\": \"eyAiY2hhbGxlbmdlIjogIkQ1VG1CaEQzbTg0c3BRd3FfVm81VWZFSm8xV2JXTnBnRHdvZ0dWcmtBd00iLCAib3JpZ2luIjogImh0dHA6XC9cL2V4YW1wbGUuY29tIiwgInR5cCI6ICJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiB9\", \"challenge\": \"fSgg0l0JefF0GAFGAi9cOf5iL1nnzSswSmgpathyRRhsZ8QTzxPH1WAu8TqTbadfnNHOnINoF0UkMjKrxKVZLA\" }";
    AuthenticationResponse tar = gson.fromJson(response, AuthenticationResponse.class);
    checkNotNull(tar.getChallenge());
    checkNotNull(tar.getClientData());
    checkNotNull(tar.getSignatureData());

  }
}
