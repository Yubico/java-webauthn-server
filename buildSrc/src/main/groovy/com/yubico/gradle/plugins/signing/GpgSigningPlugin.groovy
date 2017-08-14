package com.yubico.gradle.plugins.signing;

import com.yubico.gradle.plugins.signing.signatory.gpg.GpgSignatoryProvider;
import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.plugins.signing.SigningPlugin;

class GpgSigningPlugin implements Plugin<Project> {

  @Override
  void apply(Project project) {
    project.getPluginManager().apply(SigningPlugin);

    project.signing.signatories = new GpgSignatoryProvider()
  }

}