/**
 * Copyright (C) 2003, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package org.intalio.tempo.security.rbac;

/**
 * Constants used in the authentication system, most notably for the
 * passing of credential properties.
 *
 * @author <a href="http://www.intalio.com">&copy; Intalio Inc.</a>
 */
public class RBACConstants
{

    /**
     * Description property
     */
    public static final String PROPERTY_DESCRIPTION = "description";
    
    
    /**
     * Email address property
     */
    public static final String PROPERTY_EMAIL = "email";

    /**
     * User's full name property
     */
    public static final String PROPERTY_NAME = "name";

    /**
     * Assigned roles property
     */
    public static final String PROPERTY_ASSIGN_ROLES = "assignRole";

    /**
     * Descendant roles property
     */
    public static final String PROPERTY_DESCENDANT_ROLE = "descendantRole";

    /**
    * User password property
    */
   public static final String PROPERTY_PASSWORD = "password";

   /**
    * User first name property
    */
   public static final String PROPERTY_FIRST_NAME = "firstname";

   /**
    * User last name property
    */
   public static final String PROPERTY_LAST_NAME = "lastname";

   /**
    * User display name property
    */
   public static final String PROPERTY_DISPLAY_NAME = "displayName";

   /**
    * User database password property
    */
   public static final String PROPERTY_USER_PASSWORD = "userPassword";
}
