package com.yubico.internal.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

public class CollectionUtil {

  /**
   * Make an unmodifiable shallow copy of the argument.
   *
   * @return A shallow copy of <code>m</code> which cannot be modified
   */
  public static <K, V> Map<K, V> immutableMap(Map<K, V> m) {
    return Collections.unmodifiableMap(new HashMap<>(m));
  }

  /**
   * Make an unmodifiable shallow copy of the argument.
   *
   * @return A shallow copy of <code>l</code> which cannot be modified
   */
  public static <T> List<T> immutableList(List<T> l) {
    return Collections.unmodifiableList(new ArrayList<>(l));
  }

  /**
   * Make an unmodifiable shallow copy of the argument.
   *
   * @return A shallow copy of <code>s</code> which cannot be modified
   */
  public static <T> Set<T> immutableSet(Set<T> s) {
    return Collections.unmodifiableSet(new HashSet<>(s));
  }

  /**
   * Make an unmodifiable shallow copy of the argument.
   *
   * @return A shallow copy of <code>s</code> which cannot be modified
   */
  public static <T> SortedSet<T> immutableSortedSet(Set<T> s) {
    return Collections.unmodifiableSortedSet(new TreeSet<>(s));
  }
}
