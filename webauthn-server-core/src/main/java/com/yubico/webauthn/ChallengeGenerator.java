/*
 * Copyright 2014-2018 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the COPYING file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;

public interface ChallengeGenerator {

    ByteArray generateChallenge();

}
