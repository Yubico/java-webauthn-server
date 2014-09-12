// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package com.google.u2f.key.messages;

import java.util.Arrays;

public class RegisterRequest {
  private final byte[] challengeHash;
  private final byte[] applicationHash;

  public RegisterRequest(byte[] challengeHash, byte[] applicationHash) {
    this.challengeHash = challengeHash;
    this.applicationHash = applicationHash;
  }

  /**
   * The challenge parameter is the SHA-256 hash of the Client Data, a
   * stringified JSON datastructure that the FIDO Client prepares. Among other
   * things, the Client Data contains the challenge from the relying party
   * (hence the name of the parameter). See below for a detailed explanation of
   * Client Data.
   */
  public byte[] getChallengeHash() {
    return challengeHash;
  }

  /**
   * The application parameter is the SHA-256 hash of the application identity
   * of the application requesting the registration
   */
  public byte[] getApplicationHash() {
    return applicationHash;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(applicationHash);
    result = prime * result + Arrays.hashCode(challengeHash);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    RegisterRequest other = (RegisterRequest) obj;
    if (!Arrays.equals(applicationHash, other.applicationHash))
      return false;
    return Arrays.equals(challengeHash, other.challengeHash);
  }
}
