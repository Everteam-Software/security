package org.intalio.tempo.security.database.model;

import java.util.HashSet;
import java.util.Set;

import org.intalio.tempo.security.database.model.Role;
import org.intalio.tempo.security.database.model.User;

/**
 * @author amit
 * 
 */
public class Realm implements java.io.Serializable {

    private static final long serialVersionUID = 5962144842145793217L;
    public static final String FIND_REALM = "findRealm";
    public static final String FIND_REALMS = "findRealms";
    public static final String REALM_NAME = "realmname";

    private int id;
    private String identifier;
    private Set<User> users = new HashSet<User>(0);
    private Set<Role> roles = new HashSet<Role>(0);

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    @Override
    public String toString() {
        return "Realm [id=" + id + ", name=" + identifier + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + id;
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
        Realm other = (Realm) obj;
        if (id != other.id)
            return false;
        if (identifier == null) {
            if (other.identifier != null)
                return false;
        } else if (!identifier.equals(other.identifier))
            return false;
        return true;
    }

}
