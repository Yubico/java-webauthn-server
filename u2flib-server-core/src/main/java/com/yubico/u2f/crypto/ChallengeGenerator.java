/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.crypto;

public interface ChallengeGenerator {

    byte[] generateChallenge();
}
