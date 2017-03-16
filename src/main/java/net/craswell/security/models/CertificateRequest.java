package net.craswell.security.models;

import net.craswell.common.models.Model;

import javax.persistence.Entity;

/**
 * Models a certificate request.
 * 
 * @author 00005309
 *
 */
@Entity
public class CertificateRequest
    extends Model {
  /**
   * The x509 version supported by the certificate.
   */
  private static final int version = 3;

  /**
   * The certificate signature algorithm.
   */
  private HashAlgorithm signatureAlgorithm;

  /**
   * The certificate public key.
   */
  private byte[] publicKey;

  /**
   * The certificate subject.
   */
  private String subject;

  /**
   * Initializes a new instance of the CertificateRequest class.
   * 
   * @param subject
   * @param publicKey
   * @param signatureAlgorithm
   */
  public CertificateRequest(
      String subject,
      byte[] publicKey,
      HashAlgorithm signatureAlgorithm) {
    if (subject == null
        || subject.isEmpty()) {
      throw new IllegalArgumentException("subject");
    }

    if (publicKey == null
        || publicKey.length == 0) {
      throw new IllegalArgumentException("publicKey");
    }

    this.subject = subject;
    this.publicKey = publicKey;
    this.signatureAlgorithm = signatureAlgorithm;
  }
  
  /**
   * Initializes a new instance of the CertificateRequest class.
   */
  protected CertificateRequest() {
  }

  /**
   * @return the version
   */
  public static int getVersion() {
    return version;
  }

  /**
   * @return the signatureAlgorithm
   */
  public HashAlgorithm getSignatureAlgorithm() {
    return this.signatureAlgorithm;
  }

  /**
   * @return the publicKey
   */
  public byte[] getPublicKey() {
    return this.publicKey;
  }

  /**
   * @return the subject
   */
  public String getSubject() {
    return this.subject;
  }

  /**
   * @param signatureAlgorithm the signatureAlgorithm to set
   */
  protected void setSignatureAlgorithm(HashAlgorithm signatureAlgorithm) {
    this.signatureAlgorithm = signatureAlgorithm;
  }

  /**
   * @param publicKey the publicKey to set
   */
  protected void setPublicKey(byte[] publicKey) {
    this.publicKey = publicKey;
  }

  /**
   * @param subject the subject to set
   */
  protected void setSubject(String subject) {
    this.subject = subject;
  }
}
