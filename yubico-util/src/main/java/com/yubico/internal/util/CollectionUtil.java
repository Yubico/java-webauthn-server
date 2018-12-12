package com.yubico.internal.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CollectionUtil {

    /**
     * @return A shallow copy of <code>l</code> which cannot be modified
     */
    public static <T> List<T> immutableList(List<T> l) {
        return Collections.unmodifiableList(new ArrayList<>(l));
    }

    /**
     * @return A shallow copy of <code>s</code> which cannot be modified
     */
    public static <T> Set<T> immutableSet(Set<T> s) {
        return Collections.unmodifiableSet(new HashSet<>(s));
    }

}
