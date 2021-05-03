package com.yubico.internal.util;

import java.util.Optional;
import java.util.function.BinaryOperator;
import lombok.experimental.UtilityClass;

/** Utilities for working with {@link Optional} values. */
@UtilityClass
public class OptionalUtil {

  /**
   * If both <code>a</code> and <code>b</code> are present, return <code>f(a, b)</code>.
   *
   * <p>If only <code>a</code> is present, return <code>a</code>.
   *
   * <p>Otherwise, return <code>b</code>.
   */
  public static <T> Optional<T> zipWith(Optional<T> a, Optional<T> b, BinaryOperator<T> f) {
    if (a.isPresent() && b.isPresent()) {
      return Optional.of(f.apply(a.get(), b.get()));
    } else if (a.isPresent()) {
      return a;
    } else {
      return b;
    }
  }
}
