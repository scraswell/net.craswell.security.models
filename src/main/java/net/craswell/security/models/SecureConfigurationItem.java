package net.craswell.security.models;

import javax.persistence.Entity;

import net.craswell.common.models.Model;
import net.craswell.security.annotations.EncryptIfPossible;

/**
 * Model a secured name-value pair used for configurations.
 * 
 * @author scraswell@gmail.com
 *
 */
@Entity
public class SecureConfigurationItem
  extends Model {
  /**
   * The configuration item name. 
   */
  @EncryptIfPossible
  private String name;
  
  /**
   * The configuration item value.
   */
  @EncryptIfPossible
  private String value;

  /**
   * @return the name
   */
  public String getName() {
    return name;
  }

  /**
   * @param name the name to set
   */
  public void setName(String name) {
    this.name = name;
  }

  /**
   * @return the value
   */
  public String getValue() {
    return value;
  }

  /**
   * @param value the value to set
   */
  public void setValue(String value) {
    this.value = value;
  }
}
