package com.yubico.internal.util;

import lombok.experimental.UtilityClass;
import org.slf4j.Logger;

@UtilityClass
public class ExceptionUtil {

    public static RuntimeException wrapAndLog(Logger log, String message, Throwable t) {
        RuntimeException err = new RuntimeException(message, t);
        log.error(err.getMessage(), err);
        return err;
    }

    public static void assure(boolean condition, String failureMessageTemplate, Object... failureMessageArgs) {
        if (!condition) {
            throw new IllegalArgumentException(String.format(failureMessageTemplate, failureMessageArgs));
        }
    }

}
