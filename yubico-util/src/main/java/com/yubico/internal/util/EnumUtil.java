package com.yubico.internal.util;

import java.util.Set;

public class EnumUtil {

    public static <T extends Enum<?>> int compareSets(Set<T> a, Set<T> b, Class<T> clazz) {
        for (T value : clazz.getEnumConstants()) {
            if (a.contains(value) && !b.contains(value)) {
                return 1;
            } else if (!a.contains(value) && b.contains(value)) {
                return -1;
            }
        }
        return 0;
    }

}
