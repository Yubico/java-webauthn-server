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

package com.yubico.webauthn.extension.appid;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.net.InetAddresses;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import lombok.NonNull;
import lombok.Value;

/**
 * A FIDO AppID verified to be syntactically valid.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html">FIDO
 *     AppID and Facet Specification</a>
 */
@Value
@JsonSerialize(using = AppId.JsonSerializer.class)
public class AppId {

  /** The underlying string representation of this AppID. */
  private final String id;

  /**
   * Verify that the <code>appId</code> is a valid FIDO AppID, and wrap it as an {@link AppId}.
   *
   * @throws InvalidAppIdException if <code>appId</code> is not a valid FIDO AppID.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html">FIDO
   *     AppID and Facet Specification</a>
   */
  @JsonCreator
  public AppId(@NonNull String appId) throws InvalidAppIdException {
    checkIsValid(appId);
    this.id = appId;
  }

  /**
   * Throws {@link InvalidAppIdException} if the given App ID is found to be incompatible with the
   * U2F specification or any major U2F Client implementation.
   *
   * @param appId the App ID to be validated
   */
  private static void checkIsValid(String appId) throws InvalidAppIdException {
    if (!appId.contains(":")) {
      throw new InvalidAppIdException(
          "App ID does not look like a valid facet or URL. Web facets must start with 'https://'.");
    }
    if (appId.startsWith("http:")) {
      throw new InvalidAppIdException(
          "HTTP is not supported for App IDs (by Chrome). Use HTTPS instead.");
    }
    if (appId.startsWith("https://")) {
      URI url = checkValidUrl(appId);
      checkPathIsNotSlash(url);
      checkNotIpAddress(url);
    }
  }

  private static void checkPathIsNotSlash(URI url) throws InvalidAppIdException {
    if ("/".equals(url.getPath())) {
      throw new InvalidAppIdException(
          "The path of the URL set as App ID is '/'. This is probably not what you want -- remove the trailing slash of the App ID URL.");
    }
  }

  private static URI checkValidUrl(String appId) throws InvalidAppIdException {
    try {
      return new URI(appId);
    } catch (URISyntaxException e) {
      throw new InvalidAppIdException("App ID looks like a HTTPS URL, but has syntax errors.", e);
    }
  }

  private static void checkNotIpAddress(URI url) throws InvalidAppIdException {
    if (InetAddresses.isInetAddress(url.getAuthority())
        || (url.getHost() != null && InetAddresses.isInetAddress(url.getHost()))) {
      throw new InvalidAppIdException(
          "App ID must not be an IP-address, since it is not supported (by Chrome). Use a host name instead.");
    }
  }

  static class JsonSerializer extends com.fasterxml.jackson.databind.JsonSerializer<AppId> {
    @Override
    public void serialize(AppId value, JsonGenerator gen, SerializerProvider serializers)
        throws IOException {
      gen.writeString(value.getId());
    }
  }
}
