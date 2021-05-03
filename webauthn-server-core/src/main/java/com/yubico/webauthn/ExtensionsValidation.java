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

package com.yubico.webauthn;

import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AuthenticatorResponse;
import com.yubico.webauthn.data.ClientExtensionOutputs;
import com.yubico.webauthn.data.ExtensionInputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.experimental.UtilityClass;

@UtilityClass
class ExtensionsValidation {

  static boolean validate(
      ExtensionInputs requested,
      PublicKeyCredential<? extends AuthenticatorResponse, ? extends ClientExtensionOutputs>
          response) {
    Set<String> requestedExtensionIds = requested.getExtensionIds();
    Set<String> clientExtensionIds = response.getClientExtensionResults().getExtensionIds();

    if (!requestedExtensionIds.containsAll(clientExtensionIds)) {
      throw new IllegalArgumentException(
          String.format(
              "Client extensions {%s} are not a subset of requested extensions {%s}.",
              String.join(", ", clientExtensionIds), String.join(", ", requestedExtensionIds)));
    }

    Set<String> authenticatorExtensionIds =
        response
            .getResponse()
            .getParsedAuthenticatorData()
            .getExtensions()
            .map(
                extensions ->
                    extensions.getKeys().stream()
                        .map(CBORObject::AsString)
                        .collect(Collectors.toSet()))
            .orElseGet(HashSet::new);

    if (!requestedExtensionIds.containsAll(authenticatorExtensionIds)) {
      throw new IllegalArgumentException(
          String.format(
              "Authenticator extensions {%s} are not a subset of requested extensions {%s}.",
              String.join(", ", authenticatorExtensionIds),
              String.join(", ", requestedExtensionIds)));
    }

    return true;
  }
}
