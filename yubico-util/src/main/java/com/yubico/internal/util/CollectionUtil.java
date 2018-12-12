package com.yubico.internal.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CollectionUtil {

    public static <T> List<T> immutableList(List<T> l) {
        return Collections.unmodifiableList(new ArrayList<>(l));
    }

}
