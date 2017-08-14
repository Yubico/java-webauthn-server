package com.yubico.gradle.plugins.signing.signatory.gpg;

import org.gradle.api.Project;
import org.gradle.plugins.signing.SigningExtension;
import org.gradle.plugins.signing.signatory.SignatoryProvider;

class GpgSignatoryProvider implements SignatoryProvider<GpgSignatory> {

    @Override
    void configure(SigningExtension settings, Closure closure) {
        println("configure(${settings}, ${closure}")
    }

    @Override
    GpgSignatory getDefaultSignatory(Project project) {
        return new GpgSignatory(project."signing.keyId")
    }

    @Override
    GpgSignatory getSignatory(String name) {
        return new GpgSignatory(name)
    }

}
