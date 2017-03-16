package net.craswell.security.annotations;

/**
 * A general exception thrown by an EncryptionProvider implementations.
 * 
 * @author scraswell@gmail.com
 *
 */
public class EncryptionProviderException 
    extends Exception {
  /**
   * The serial version UID. 
   */
  private static final long serialVersionUID = 1L;

  /**
   * Initializes a new instance of the EncryptionProviderException class.
   * 
   * @param message
   */
  public EncryptionProviderException(String message) {
    super(message);
  }

  /**
   * Initializes a new instance of the EncryptionProviderException class.
   * 
   * @param message
   * @param innerException
   */
  public EncryptionProviderException(String message, Exception innerException) {
    super(message, innerException);
  }
}
