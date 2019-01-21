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

import com.yubico.internal.util.ExceptionUtil;
import java.io.IOException;
import java.net.URL;
import java.time.LocalDate;
import java.util.Enumeration;
import java.util.Optional;
import java.util.jar.Manifest;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;


/**
 * Contains version information for the com.yubico.webauthn package.
 *
 * @see Specification
 */
@Slf4j
@Value
public class VersionInfo {

    private static VersionInfo instance;

    public static VersionInfo getInstance() {
        if (instance == null) {
            try {
                instance = new VersionInfo();
            } catch (IOException e) {
                throw ExceptionUtil.wrapAndLog(log, "Failed to create VersionInfo", e);
            }
        }

        return instance;
    }

    /**
     * Represents the specification this implementation is based on
     */
    private final Specification specification = Specification.builder()
        .url(new URL("https://www.w3.org/TR/2019/PR-webauthn-20190117/"))
        .latestVersionUrl(new URL("https://www.w3.org/TR/webauthn/"))
        .status(DocumentStatus.PROPOSED_RECOMMENDATION)
        .releaseDate(LocalDate.parse("2019-01-17"))
        .build();

    /**
     * Represents the specification this implementation is based on
     */
    private final Implementation implementation = new Implementation(
        findImplementationVersionInManifest(),
        new URL("https://github.com/Yubico/java-webauthn-server")
    );

    private VersionInfo() throws IOException {
    }

    private Optional<String> findImplementationVersionInManifest() throws IOException {
        final Enumeration<URL> resources = getClass().getClassLoader().getResources("META-INF/MANIFEST.MF");

        while (resources.hasMoreElements()) {
            final URL resource = resources.nextElement();
            final Manifest manifest = new Manifest(resource.openStream());
            if ("java-webauthn-server".equals(manifest.getMainAttributes().getValue("Implementation-Id"))) {
                return Optional.ofNullable(manifest.getMainAttributes().getValue("Implementation-Version"));
            }
        }

        return Optional.empty();
    }

}
