plugins {
    id("com.diffplug.spotless")
    id("io.github.cosmicsilence.scalafix")
}

spotless {
    java {
        googleJavaFormat()
    }
    scala {
        scalafmt("2.6.3").configFile(project.rootProject.file("scalafmt.conf"))
    }
}

scalafix {
    configFile.set(project.rootProject.file("scalafix.conf"))

    // Work around dependency resolution issues in April 2022
    semanticdb.autoConfigure.set(true)
    semanticdb.version.set("4.5.5")
}

project.dependencies.scalafix("com.github.liancheng:organize-imports_2.13:0.6.0")

project.tasks.spotlessApply.configure { dependsOn(project.tasks["scalafix"]) }
project.tasks.spotlessCheck.configure { dependsOn(project.tasks["checkScalafix"]) }

// Scalafix adds tasks in afterEvaluate, so their configuration must be deferred
project.afterEvaluate {
    project.tasks["scalafix"].finalizedBy(project.tasks.spotlessApply)
    project.tasks["checkScalafix"].finalizedBy(project.tasks.spotlessCheck)
}
