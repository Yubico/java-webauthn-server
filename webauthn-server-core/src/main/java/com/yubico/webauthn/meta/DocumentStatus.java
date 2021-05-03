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

package com.yubico.webauthn.meta;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.internal.util.json.JsonStringSerializable;
import com.yubico.internal.util.json.JsonStringSerializer;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.NonNull;

/** A representation of Web Authentication specification document statuses. */
@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum DocumentStatus implements JsonStringSerializable {
  /** An editor's draft is a changing work in progress. */
  EDITORS_DRAFT("editors-draft"),

  /** A working draft is a named snapshot of a particular state of an editor's draft. */
  WORKING_DRAFT("working-draft"),

  /** A candidate recommendation is a specification release candidate. */
  CANDIDATE_RECOMMENDATION("candidate-recommendation"),

  /** A proposed recommendation is a finished draft intended for release. */
  PROPOSED_RECOMMENDATION("proposed-recommendation"),

  /** A recommendation is a finished and released specification. */
  RECOMMENDATION("recommendation");

  private final String id;

  static Optional<DocumentStatus> fromString(@NonNull String id) {
    return Stream.of(values()).filter(v -> v.id.equals(id)).findAny();
  }

  /** Used by JSON serializer. */
  @Override
  public String toJsonString() {
    return id;
  }
}
