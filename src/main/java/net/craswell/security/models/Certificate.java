package net.craswell.security.models;

import java.util.Date;

import javax.persistence.Entity;

/**
 * Models an X.509v3 Certificate.
 * 
 * @author 00005309
 *
 */
@Entity
public class Certificate
  extends CertificateRequest {
  /**
   * The certificate serial number.
   */
  private long serialNumber;

  /**
   * The certificate's issuing authority.
   */
  private Certificate issuer;

  /**
   * The date from which this certificate will be considered valid.
   */
  private Date validFrom;

  /**
   * The date until which this certificate will be considered valid.
   */
  private Date validUntil;

  /**
   * The certificate status.
   */
  private CertificateStatus certificateStatus;

  /**
   * Initializes a new instance of the certificate class.
   * 
   * @param serialNumber
   * @param subject
   * @param publicKey
   * @param signatureAlgorithm
   * @param issuer
   * @param validFrom
   * @param validUntil
   * @param certificateStatus
   */
  public Certificate(
      long serialNumber,
      String subject,
      byte[] publicKey,
      HashAlgorithm signatureAlgorithm,
      Certificate issuer,
      Date validFrom,
      Date validUntil,
      CertificateStatus certificateStatus) {
    super(subject, publicKey, signatureAlgorithm);

    if (serialNumber < 1) {
      throw new IllegalArgumentException("serialNumber");
    }

    if (issuer == null) {
      throw new IllegalArgumentException("issuer");
    }

    if (validFrom == null) {
      throw new IllegalArgumentException("validFrom");
    }

    if (validUntil == null) {
      throw new IllegalArgumentException("validUntil");
    }

    this.serialNumber = serialNumber;
    this.issuer = issuer;
    this.validFrom = validFrom;
    this.validUntil = validUntil;
  }
  
  /**
   * Initializes a new instance of the certificate class.
   */
  protected Certificate() {
  }

  /**
   * @return the serialNumber
   */
  public long getSerialNumber() {
    return this.serialNumber;
  }

  /**
   * @return the issuer
   */
  public Certificate getIssuer() {
    return this.issuer;
  }

  /**
   * @return the validFrom
   */
  public Date getValidFrom() {
    return this.validFrom;
  }

  /**
   * @return the validUntil
   */
  public Date getValidUntil() {
    return this.validUntil;
  }

  /**
   * @return the certificateStatus
   */
  public CertificateStatus getCertificateStatus() {
    return this.certificateStatus;
  }

  /**
   * @param serialNumber the serialNumber to set
   */
  protected void setSerialNumber(long serialNumber) {
    this.serialNumber = serialNumber;
  }

  /**
   * @param issuer the issuer to set
   */
  protected void setIssuer(Certificate issuer) {
    this.issuer = issuer;
  }

  /**
   * @param validFrom the validFrom to set
   */
  protected void setValidFrom(Date validFrom) {
    this.validFrom = validFrom;
  }

  /**
   * @param validUntil the validUntil to set
   */
  protected void setValidUntil(Date validUntil) {
    this.validUntil = validUntil;
  }

  /**
   * @param certificateStatus the certificateStatus to set
   */
  protected void setCertificateStatus(CertificateStatus certificateStatus) {
    this.certificateStatus = certificateStatus;
  }
}
