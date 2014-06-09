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
public class Role implements Serializable {

    private static final long serialVersionUID = 2085302387123740543L;
    public static final String ROLE_NAME = "role";
    public static final String REALM_NAME = "realmname";
    public static final String FIND_ROLES_OF_REALM = "findRolesOfRealm";
    public static final String FIND_ROLE_OF_REALM = "findRoleOfRealm";
    public static final String FIND_ROLE = "findRole";
    public static final String WORKFLOW_ADMIN_ROLES = "workflowAdminRoles";

    private int id;
    private Realm realm;
    private String identifier;
    private String description;
    private Set<User> userRoles = new HashSet<User>(0);
    private Set<RoleHierarchy> roleHierarchies = new HashSet<RoleHierarchy>(0);

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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public Set<User> getUserRoles() {
        return userRoles;
    }

    public void setUserRoles(Set<User> userRoles) {
        this.userRoles = userRoles;
    }

    public Set<RoleHierarchy> getRoleHierarchies() {
        return roleHierarchies;
    }

    public void setRoleHierarchies(Set<RoleHierarchy> roleHierarchies) {
        this.roleHierarchies = roleHierarchies;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + id;
        result = prime * result + ((realm == null) ? 0 : realm.hashCode());
        result = prime * result
                + ((identifier == null) ? 0 : identifier.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Role other = (Role) obj;
        if (id != other.id)
            return false;
        if (realm == null) {
            if (other.realm != null)
                return false;
        } else if (!realm.equals(other.realm))
            return false;
        if (identifier == null) {
            if (other.identifier != null)
                return false;
        } else if (!identifier.equals(other.identifier))
            return false;
        return true;
    }

}
