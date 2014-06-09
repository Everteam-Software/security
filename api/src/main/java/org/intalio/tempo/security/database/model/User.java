/**
 * Copyright (C) 2014, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */
package org.intalio.tempo.security.database.model;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * @author amit
 * 
 */
public class User implements Serializable {

    private static final long serialVersionUID = -8716663220156247920L;
    public static final String USER_NAME = "username";
    public static final String FIND_USER_OF_REALM = "findUserOfRealm";
    public static final String FIND_USERS_OF_REALM = "findUsersOfRealm";
    public static final String REALM_NAME = "realmname";
    public static final String FIND_USER = "findUser";
    public static final String WORKFLOW_ADMIN_USERS = "workflowAdminUsers";

    private int id;
    private Realm realm;
    private String identifier;
    private String displayName;
    private String firstName;
    private String lastName;
    private String password;
    private String email;
    private Set<Role> userRoles = new HashSet<Role>(0);

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<Role> getUserRoles() {
        return userRoles;
    }

    public void setUserRoles(Set<Role> userRoles) {
        this.userRoles = userRoles;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

}
