package com.yubico.gradle

public class GitUtils {

    public static String getGitCommit(File projectDir) {
        def proc = "git rev-parse HEAD".execute(null, projectDir)
        proc.waitFor()
        if (proc.exitValue() != 0) {
            return null
        }
        return proc.text.trim()
    }

    public static String getGitCommitOrUnknown(projectDir) {
        return getGitCommit(projectDir) ?: 'UNKNOWN'
    }

}
