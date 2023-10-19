plugins {
    java
    id("info.solidsoft.pitest")
}

pitest {
    pitestVersion.set("1.15.0")
    timestampedReports.set(false)

    outputFormats.set(listOf("XML", "HTML"))

    avoidCallsTo.set(listOf(
        "java.util.logging",
        "org.apache.log4j",
        "org.slf4j",
        "org.apache.commons.logging",
        "com.google.common.io.Closeables",
    ))
}
