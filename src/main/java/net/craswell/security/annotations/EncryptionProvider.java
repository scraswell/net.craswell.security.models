package net.craswell.security.annotations;

public interface EncryptionProvider {

  /**
   * Decrypts the annotated fields contained within the object.
   * 
   * @param object The object containing annotated fields.
   * 
   * @throws EncryptionProviderException Thrown when the process to decrypt the object fields fails.
   */
  void decryptObject(Object object)
      throws EncryptionProviderException;

  /**
   * Encrypts annotated fields contained within the object.
   * 
   * @param object The object containing annotated fields.
   * 
   * @throws EncryptionProviderException Thrown when the process to encrypt the annotated fields
   *         fails.
   */
  void encryptObject(Object object)
      throws EncryptionProviderException;

}
