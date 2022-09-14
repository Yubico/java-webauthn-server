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

package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

/**
 * Used to supply additional Relying Party attributes when creating a new credential.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-publickeycredentialrpentity">§5.4.2.
 *     Relying Party Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity)
 *     </a>
 */
@Value
@Builder(toBuilder = true)
public class RelyingPartyIdentity implements PublicKeyCredentialEntity {

  /**
   * The human-palatable name of the Relaying Party.
   *
   * <p>For example: "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
   */
  @NonNull
  @Getter(onMethod = @__({@Override}))
  private final String name;

  /**
   * A unique identifier for the Relying Party, which sets the <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#rp-id">RP ID</a>.
   *
   * <p>This defines the domains where users' credentials are valid. See <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#scope">RP ID: scope</a> for details
   * and examples.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#rp-id">RP ID</a>
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#scope">RP ID: scope</a>
   */
  @NonNull private final String id;

  @JsonCreator
  private RelyingPartyIdentity(
      @NonNull @JsonProperty("name") String name, @NonNull @JsonProperty("id") String id) {
    this.name = name;
    this.id = id;
  }

  public static RelyingPartyIdentityBuilder.MandatoryStages builder() {
    return new RelyingPartyIdentityBuilder.MandatoryStages();
  }

  public static class RelyingPartyIdentityBuilder {

    public static class MandatoryStages {
      private final RelyingPartyIdentityBuilder builder = new RelyingPartyIdentityBuilder();

      /**
       * A unique identifier for the Relying Party, which sets the <a
       * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#rp-id">RP ID</a>.
       *
       * <p>This defines the domains where users' credentials are valid. See <a
       * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#scope">RP ID: scope</a> for
       * details and examples.
       *
       * @see RelyingPartyIdentityBuilder#id(String)
       * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#rp-id">RP ID</a>
       * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#scope">RP ID: scope</a>
       */
      public Step2 id(String id) {
        builder.id(id);
        return new Step2();
      }

      public class Step2 {
        /**
         * The human-palatable name of the Relaying Party.
         *
         * <p>For example: "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
         *
         * @see RelyingPartyIdentityBuilder#name(String)
         */
        public RelyingPartyIdentityBuilder name(String name) {
          return builder.name(name);
        }
      }
    }
  }
}
