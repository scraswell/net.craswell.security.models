package net.craswell.security.annotations;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * This annotation is meant to be placed on a class field.  If a secure store processes a class
 * containing a field annotated by this, the field data will be encrypted prior to being stored
 * in the persistence layer.
 *
 */
@Retention(RetentionPolicy.RUNTIME)
public @interface EncryptIfPossible {

}
