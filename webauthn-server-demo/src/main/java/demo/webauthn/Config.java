// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package demo.webauthn;

import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Config {

  private static final Logger logger = LoggerFactory.getLogger(Config.class);

  private static final String DEFAULT_ORIGIN = "https://localhost:8443";
  private static final int DEFAULT_PORT = 8443;
  private static final RelyingPartyIdentity DEFAULT_RP_ID =
      RelyingPartyIdentity.builder().id("localhost").name("Yubico WebAuthn demo").build();

  private final Set<String> origins;
  private final int port;
  private final RelyingPartyIdentity rpIdentity;

  private Config(Set<String> origins, int port, RelyingPartyIdentity rpIdentity) {
    this.origins = CollectionUtil.immutableSet(origins);
    this.port = port;
    this.rpIdentity = rpIdentity;
  }

  private static Config instance;

  private static Config getInstance() {
    if (instance == null) {
      try {
        instance = new Config(computeOrigins(), computePort(), computeRpIdentity());
      } catch (MalformedURLException e) {
        throw new RuntimeException(e);
      }
    }
    return instance;
  }

  public static Set<String> getOrigins() {
    return getInstance().origins;
  }

  public static int getPort() {
    return getInstance().port;
  }

  public static RelyingPartyIdentity getRpIdentity() {
    return getInstance().rpIdentity;
  }

  public static boolean useFidoMds() {
    return "true".equalsIgnoreCase(System.getenv("YUBICO_WEBAUTHN_USE_FIDO_MDS"));
  }

  private static Set<String> computeOrigins() {
    final String origins = System.getenv("YUBICO_WEBAUTHN_ALLOWED_ORIGINS");

    logger.debug("YUBICO_WEBAUTHN_ALLOWED_ORIGINS: {}", origins);

    final Set<String> result;

    if (origins == null) {
      result = Collections.singleton(DEFAULT_ORIGIN);
    } else {
      result = new HashSet<>(Arrays.asList(origins.split(",")));
    }

    logger.info("Origins: {}", result);

    return result;
  }

  private static int computePort() {
    final String port = System.getenv("YUBICO_WEBAUTHN_PORT");

    if (port == null) {
      return DEFAULT_PORT;
    } else {
      return Integer.parseInt(port);
    }
  }

  private static RelyingPartyIdentity computeRpIdentity() throws MalformedURLException {
    final String name = System.getenv("YUBICO_WEBAUTHN_RP_NAME");
    final String id = System.getenv("YUBICO_WEBAUTHN_RP_ID");

    logger.debug("RP name: {}", name);
    logger.debug("RP ID: {}", id);

    RelyingPartyIdentity.RelyingPartyIdentityBuilder resultBuilder = DEFAULT_RP_ID.toBuilder();

    if (name == null) {
      logger.debug("RP name not given - using default.");
    } else {
      resultBuilder.name(name);
    }

    if (id == null) {
      logger.debug("RP ID not given - using default.");
    } else {
      resultBuilder.id(id);
    }

    final RelyingPartyIdentity result = resultBuilder.build();
    logger.info("RP identity: {}", result);
    return result;
  }
}
