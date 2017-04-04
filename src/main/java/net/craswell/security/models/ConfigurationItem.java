package net.craswell.security.models;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Table;

import net.craswell.common.models.Model;
import net.craswell.security.annotations.Confidential;
import net.craswell.security.annotations.RequiresConfidentiality;

/**
 * Model a secured name-value pair used for configurations.
 * 
 * @author scraswell@gmail.com
 *
 */
@Entity
@RequiresConfidentiality
@Table(name = "CONFIGURATION_ITEMS")
@Inheritance( strategy = InheritanceType.TABLE_PER_CLASS )
public class ConfigurationItem
  extends Model {
  /**
   * The configuration item name. 
   */
  @Confidential
  @Column( name = "NAME" )
  private String name;
  
  /**
   * The configuration item value.
   */
  @Confidential
  @Column( name = "VALUE" )
  private String value;

  @Confidential
  @Column( name = "NUMBER" )
  private int number;
}
