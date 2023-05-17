// Spotless dropped Java 8 support in version 2.33.0
if (JavaVersion.current().isJava11Compatible) {
    apply(plugin = "project-convention-code-formatting-internal")
}
