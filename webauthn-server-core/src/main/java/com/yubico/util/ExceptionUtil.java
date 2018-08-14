package com.yubico.util;

import lombok.experimental.UtilityClass;
import org.slf4j.Logger;

@UtilityClass
public class ExceptionUtil {

    public static RuntimeException wrapAndLog(Logger log, String message, Throwable t) {
        RuntimeException err = new RuntimeException(message, t);
        log.error(err.getMessage(), err);
        return err;
    }

}
