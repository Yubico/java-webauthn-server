// Spotless dropped Java 8 support in version 2.33.0
// spotless-plugin-gradle dropped Java <17 support in version 8.0.0
if (JavaVersion.current().isCompatibleWith(JavaVersion.VERSION_17)) {
    apply(plugin = "project-convention-code-formatting-internal")
}
