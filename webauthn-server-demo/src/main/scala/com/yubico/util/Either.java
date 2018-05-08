package com.yubico.util;


import java.util.function.Function;
import scala.util.Left;
import scala.util.Right;

public final class Either<L, R> {

    private final boolean isRight;
    private final L leftValue;
    private final R rightValue;

    private Either(R rightValue) {
        this.isRight = true;
        this.leftValue = null;
        this.rightValue = rightValue;
    }

    private Either(boolean dummy, L leftValue) {
        this.isRight = false;
        this.leftValue = leftValue;
        this.rightValue = null;
    }

    public final boolean isLeft() {
        return !isRight();
    }

    public final boolean isRight() {
        return isRight;
    }

    public final L left() {
        if (isLeft()) {
            return leftValue;
        } else {
            throw new IllegalStateException("Cannot call left() on a right value.");
        }
    }

    public final R right() {
        if (isRight()) {
            return rightValue;
        } else {
            throw new IllegalStateException("Cannot call right() on a left value.");
        }
    }

    public final <RO> Either<L, RO> map(Function<R, RO> func) {
       return flatMap(r -> Either.right(func.apply(r)));
    }

    public final <RO> Either<L, RO> flatMap(Function<R, Either<L, RO>> func) {
        if (isRight()) {
            return func.apply(rightValue);
        } else {
            return Either.left(leftValue);
        }
    }

    public static <L, R> Either<L, R> left(L value) {
        return new Either<>(false, value);
    }

    public static <L, R> Either<L, R> right(R value) {
        return new Either<>(value);
    }

    public static <L, R> Either<L, R> fromScala(scala.util.Either<L, R> scala) {
        if (scala.isRight()) {
            return Either.right(scala.right().get());
        } else {
            return Either.left(scala.left().get());
        }
    }

    public final scala.util.Either<L, R> toScala() {
        if (isRight()) {
            return Right.apply(rightValue);
        } else {
            return Left.apply(leftValue);
        }
    }

}
