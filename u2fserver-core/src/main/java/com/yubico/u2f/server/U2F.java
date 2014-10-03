package com.yubico.u2f.server;

import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.impl.ChallengeGeneratorImpl;
import com.yubico.u2f.server.messages.StartedAuthentication;
import com.yubico.u2f.server.messages.StartedRegistration;
import org.apache.commons.codec.binary.Base64;

import java.util.Set;

public class U2F {

  private static final String U2F_VERSION = "U2F_V2";
  private static final ChallengeGenerator challengeGenerator = new ChallengeGeneratorImpl();

  public static StartedRegistration startRegistration(String appId, Set<String> trustedDomains) {
    byte[] challenge = challengeGenerator.generateChallenge();
    String challengeBase64 = Base64.encodeBase64URLSafeString(challenge);
    return new StartedRegistration(U2F_VERSION, challengeBase64, appId, trustedDomains);
  }

  public static StartedAuthentication startAuthentication(String appId, Set<String> trustedDomains, Device device) {
    byte[] challenge = challengeGenerator.generateChallenge();

    return new StartedAuthentication(
            U2F_VERSION,
            Base64.encodeBase64URLSafeString(challenge),
            appId,
            Base64.encodeBase64URLSafeString(device.getKeyHandle()),
            trustedDomains
    );
  }
}
