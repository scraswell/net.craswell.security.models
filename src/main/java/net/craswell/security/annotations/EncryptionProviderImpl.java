package net.craswell.security.annotations;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import net.craswell.common.BinarySerializer;
import net.craswell.common.BinarySerializerException;
import net.craswell.common.encryption.AesToolImpl;
import net.craswell.common.encryption.AesTool;
import net.craswell.common.encryption.AesToolException;
import net.craswell.common.encryption.EncryptedObject;

/**
 * Provides encryption for the EncryptIfPossible annotation.
 * 
 * @author scraswell@gmail.com
 *
 */
public class EncryptionProviderImpl
  implements EncryptionProvider {
  /**
   * The passphrase used to secure encrypted values.
   */
  private final String passphrase;

  /**
   * The encryption provider.
   */
  private final AesTool aesTool;

  /**
   * Initializes a new instance of the EncryptionProviderImpl class.
   * 
   * @param passphrase The passphrase from which the encryption key is derived.
   * 
   * @throws EncryptionProviderException Thrown when the initialization fails.
   */
  public EncryptionProviderImpl(String passphrase)
      throws EncryptionProviderException {
    if (passphrase == null
        || passphrase.isEmpty()) {
      throw new IllegalArgumentException("passphrase");
    }

    this.passphrase = passphrase;

    try {
      this.aesTool = new AesToolImpl();
    } catch (AesToolException e) {
      throw new EncryptionProviderException(
          "An unhandled exception occurred while initializing the Encryption Provider.",
          e);
    }
  }
  
  /* (non-Javadoc)
   * @see net.craswell.security.annotations.EncryptionProvider#decryptObject(java.lang.Object)
   */
  @Override
  public void decryptObject(Object object)
      throws EncryptionProviderException {
    Field[] objectFields = object.getClass()
        .getDeclaredFields();

    for (Field field : objectFields) {
      try {
        this.decryptField(object, field);
      } catch (AesToolException e) {
        throw new EncryptionProviderException(
            "An unhandled exception occurred while decrypting the annotated object fields.",
            e);
      }
    }
  }

  /* (non-Javadoc)
   * @see net.craswell.security.annotations.EncryptionProvider#encryptObject(java.lang.Object)
   */
  @Override
  public void encryptObject(Object object)
      throws EncryptionProviderException {
    Field[] objectFields = object.getClass()
        .getDeclaredFields();

    for (Field field : objectFields) {
      try {
        this.encryptField(object, field);
      } catch (
          AesToolException
          | SecurityException e) {
        throw new EncryptionProviderException(
            "An unhandled exception occurred while encrypting the annotated object fields.",
            e);
      }
    }
  }

  /**
   * Decrypts a field, if annotated.
   * 
   * @param object The object.
   * @param field The field.
   *
   * @throws EncryptionProviderException 
   * @throws AesToolException Thrown when a failure is caught in the AesTool.
   */
  private void decryptField(
      Object object,
      Field field)
          throws EncryptionProviderException,
          AesToolException {

    if (field.isAnnotationPresent(EncryptIfPossible.class)) {
      if (field.getType() != String.class) {
        String exceptionMessage = String.format(
            "Fields requiring encryption must be of type %1$s.",
            String.class.getCanonicalName());
        
        throw new EncryptionProviderException(exceptionMessage);
      }

      Class<?> clazz = object.getClass();

      Method propertyGetter = this.getPropertyGetter(
          clazz,
          field);

      Method propertySetter = this.getPropertySetter(
          clazz,
          field);

      String secureString = this.invokeGetter(
          object,
          propertyGetter);

      EncryptedObject securedObject = this.aesTool
          .decodeObject(secureString);

      byte[] decryptedBytes = this.aesTool.decrypt(
          securedObject,
          this.passphrase);

      String decryptedString = this.deserializeString(decryptedBytes);

      Object[] methodArgs = new Object[1];
      methodArgs[0] = decryptedString;

      this.invokeSetter(
          object,
          propertySetter,
          methodArgs);
    }
  }

  /**
   * Encrypts a field, if annotated.
   * 
   * @param object The object.
   * @param field The field.
   * 
   * @throws AesToolException 
   * @throws EncryptionProviderException 
   * @throws BinarySerializerException 
   */
  private void encryptField(
      Object object,
      Field field)
          throws AesToolException,
          EncryptionProviderException {
    if (field.isAnnotationPresent(EncryptIfPossible.class)) {
      if (field.getType() != String.class) {
        throw new EncryptionProviderException(
            "Fields requiring encryption must be of type java.lang.String");
      }

      Class<?> clazz = object.getClass();

      Method propertyGetter = this.getPropertyGetter(
          clazz,
          field);

      Method propertySetter = this.getPropertySetter(
          clazz,
          field);

      String insecureString = this.invokeGetter(
          object,
          propertyGetter);

      byte[] insecureBytes = this.serializeString(insecureString);

      EncryptedObject securedObject = this.aesTool.encrypt(
          insecureBytes,
          this.passphrase);

      Object[] methodArgs = new Object[1];
      methodArgs[0] = this.aesTool
          .encodeObject(securedObject);

      this.invokeSetter(
          object,
          propertySetter,
          methodArgs);
    }
  }

  /**
   * De-serializes the string from the decrypted bytes.
   * 
   * @param decryptedBytes The decrypted bytes.
   * @return The decrypted string.
   * 
   * @throws EncryptionProviderException Thrown when the process to de-serialize the object fails.
   */
  private String deserializeString(byte[] decryptedBytes)
      throws EncryptionProviderException {
    String decryptedString;

    try {
      decryptedString = (String) BinarySerializer
          .deserializeObject(decryptedBytes);
    } catch (BinarySerializerException e) {
      throw new EncryptionProviderException(
          "An exception occurred while attempting to deserialize the encrypted string.",
          e);
    }

    return decryptedString;
  }

  /**
   * Serializes a string to binary.
   * 
   * @param insecureObject
   * @return
   * @throws EncryptionProviderException
   */
  private byte[] serializeString(Object insecureObject)
      throws EncryptionProviderException {
    byte[] insecureBytes;

    try {
      insecureBytes = BinarySerializer
          .serializeObject(insecureObject);
    } catch (BinarySerializerException e) {
      throw new EncryptionProviderException(
          "An exception occurred while attempting to serialize the string to binary.",
          e);
    }

    return insecureBytes;
  }

  /**
   * Invokes the property setter on an object with the given arguments.
   * 
   * @param object The object on which the setter should be invoked.
   * @param propertySetter The setter method.
   * @param methodArgs The setter method arguments.
   * 
   * @throws EncryptionProviderException Thrown when the invocation fails.
   */
  private void invokeSetter(
      Object object,
      Method propertySetter,
      Object[] methodArgs)
          throws EncryptionProviderException {
    try {
      propertySetter.invoke(object, methodArgs);
    } catch (
        Exception e) {
      throw new EncryptionProviderException(
          "An exception occurred during the setter invocation.");
    }
  }

  /**
   * Invokes the property getter.
   * 
   * @param object The object on which the getter should be invoked.
   * @param propertyGetter The property getter method.
   * 
   * @return The value returned from the property getter invocation.
   * 
   * @throws EncryptionProviderException When the getter invocation fails.
   */
  private String invokeGetter(
      Object object,
      Method propertyGetter)
          throws EncryptionProviderException {
    Object insecureObject;

    try {
      insecureObject = propertyGetter.invoke(
          object,
          (Object[]) null);
    } catch (
        Exception e) {
      throw new EncryptionProviderException(
          "An exception occurred while attempting to invoke the getter.",
          e);
    }
    return (String) insecureObject;
  }

  /**
   * Determines the name of the property getter method.
   * 
   * @param clazz The class.
   * @param field The field for which we will determine the getter.
   * 
   * @return The getter method associated with the field.
   * 
   * @throws EncryptionProviderException Thrown when the process to get the getter fails. 
   */
  private Method getPropertyGetter(
      Class<?> clazz,
      Field field)
          throws EncryptionProviderException {

    Class<?>[] classArgs = new Class[0];

    try {
      return clazz.getMethod(
          this.determineGetterName(field),
          classArgs);
    } catch (
        NoSuchMethodException
        | SecurityException e) {
      String exceptionMessage = String.format(
          "An exception occurred while getting the property getter for %1$s::%2$s.",
          clazz.getCanonicalName(),
          field.getName());

      throw new EncryptionProviderException(
          exceptionMessage,
          e);
    }
  }

  /**
   * Determines the setter method associated with a field.
   * 
   * @param clazz The class.
   * @param field The field.
   * @return The setter method associated with the field.
   * 
   * @throws EncryptionProviderException Thrown when the process to get the setter fails. 
   */
  private Method getPropertySetter(
      Class<?> clazz,
      Field field)
          throws EncryptionProviderException {

    Class<?>[] classArgs = new Class[1];
    classArgs[0] = field.getType();

    try {
      return clazz.getMethod(
          this.determineSetterName(field),
          classArgs);
    } catch (
        NoSuchMethodException
        | SecurityException e) {
      String exceptionMessage = String.format(
          "An exception occurred while getting the property setter for %1$s::%2$s.",
          clazz.getCanonicalName(),
          field.getName());

      throw new EncryptionProviderException(
          exceptionMessage,
          e);
    }
  }

  /**
   * Determines the name of the getter method based on known standards and principles.
   * 
   * @param field The field for which we will determine the name of the getter.
   * 
   * @return The name of the getter method.
   */
  private String determineGetterName(Field field) {
    return this.getPropertyMethod(
        field,
        false);
  }

  /**
   * Determines the name of the setter method based on known standards and principles.
   * 
   * @param field The field for which we will determine the name of the setter.
   * 
   * @return The name of the setter method.
   */
  private String determineSetterName(Field field) {
    return this.getPropertyMethod(
        field,
        true);
  }

  /**
   * Builds the name of the getter or setter method based on known standards and principles.
   * 
   * @param field The field for which we will determine the accessor or mutator.
   * @param isSetter A value indicating whether we want to determine the name of the mutator method.
   * 
   * @return The name of the accessor or mutator method associated with a given field.
   */
  private String getPropertyMethod(
      Field field,
      boolean isSetter) {
    StringBuilder methodNameBuilder = new StringBuilder();
    StringBuilder nameBuilder = new StringBuilder();

    String fieldName = field.getName();

    nameBuilder
        .append(fieldName.substring(0, 1).toUpperCase())
        .append(fieldName.substring(1, fieldName.length()));

    String propertyName = nameBuilder.toString();

    if (isSetter) {
      methodNameBuilder.append("set");
    } else {
      methodNameBuilder.append("get");
    }

    methodNameBuilder
        .append(propertyName);

    return methodNameBuilder.toString();
  }
}
