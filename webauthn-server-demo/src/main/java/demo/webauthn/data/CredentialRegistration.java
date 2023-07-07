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

package demo.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.CredentialRecord;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import java.time.Instant;
import java.util.Optional;
import java.util.SortedSet;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.With;

@Value
@Builder
@With
public class CredentialRegistration implements CredentialRecord {

  UserIdentity userIdentity;
  Optional<String> credentialNickname;
  SortedSet<AuthenticatorTransport> transports;

  @JsonIgnore Instant registrationTime;
  RegisteredCredential credential;

  Optional<Object> attestationMetadata;

  @JsonProperty("registrationTime")
  public String getRegistrationTimestamp() {
    return registrationTime.toString();
  }

  public String getUsername() {
    return userIdentity.getName();
  }

  @Override
  public @NonNull ByteArray getCredentialId() {
    return credential.getCredentialId();
  }

  @Override
  public @NonNull ByteArray getUserHandle() {
    return userIdentity.getId();
  }

  @Override
  public @NonNull ByteArray getPublicKeyCose() {
    return credential.getPublicKeyCose();
  }

  @Override
  public long getSignatureCount() {
    return credential.getSignatureCount();
  }

  @Override
  public Optional<Boolean> isBackupEligible() {
    return credential.isBackupEligible();
  }

  @Override
  public Optional<Boolean> isBackedUp() {
    return credential.isBackedUp();
  }
}
