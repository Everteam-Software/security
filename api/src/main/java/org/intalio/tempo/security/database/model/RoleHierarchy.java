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

/**
 * @author amit
 * 
 */
public class RoleHierarchy implements Serializable {

    private static final long serialVersionUID = 448674951541065372L;
    public static final String FIND_ROLE_HIERARCHIES = "findRoleHierarchies";
    public static final String FIND_ROLE_HIERARCHY = "findRoleHierarchy";
    public static final String ROLE_NAME = "role";
    public static final String DESENDANT_ROLE_NAME = "descendantRole";
    public static final String FIND_ASC_DESC_ROLE_HIERARCHIES = "findAscDescRoleHierarchies";

    private Role role;
    private Role descendantRole;

    public RoleHierarchy() {
    }

    public RoleHierarchy(Role role, Role descendantRole) {
        this.role = role;
        this.descendantRole = descendantRole;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public Role getDescendantRole() {
        return descendantRole;
    }

    public void setDescendantRole(Role descendantRole) {
        this.descendantRole = descendantRole;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((descendantRole == null) ? 0 : descendantRole.hashCode());
        result = prime * result + ((role == null) ? 0 : role.hashCode());
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
        RoleHierarchy other = (RoleHierarchy) obj;
        if (descendantRole == null) {
            if (other.descendantRole != null)
                return false;
        } else if (!descendantRole.equals(other.descendantRole))
            return false;
        if (role == null) {
            if (other.role != null)
                return false;
        } else if (!role.equals(other.role))
            return false;
        return true;
    }

}
