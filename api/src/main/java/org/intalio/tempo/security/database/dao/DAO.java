/**
 * Copyright (C) 2014, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */
package org.intalio.tempo.security.database.dao;

import java.util.ArrayList;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationConstants;
import org.intalio.tempo.security.database.model.Realm;
import org.intalio.tempo.security.database.model.Role;
import org.intalio.tempo.security.database.model.RoleHierarchy;
import org.intalio.tempo.security.database.model.User;
import org.intalio.tempo.security.database.util.DatabaseHelperUtil;
import org.intalio.tempo.security.rbac.RBACConstants;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.RoleNotFoundException;
import org.intalio.tempo.security.rbac.UserNotFoundException;
import org.intalio.tempo.security.util.IdentifierUtils;
import org.intalio.tempo.security.util.StringArrayUtils;

/**
 * @author amit
 * 
 */
public class DAO {

    private static Logger log = Logger.getLogger(DAO.class);

    private static final SessionFactory _sessionFactory;
    private Session _session;

    static {
        try {
            _sessionFactory = SessionFactoryHelper.getSessionFactory();
        } catch (Throwable ex) {
            log.error("Initial SessionFactory creation failed." + ex);
            throw new ExceptionInInitializerError(ex);
        }
    }

    /**
     * @param userName
     * @param realmName
     * @return
     * @throws Exception
     */
    public Property[] getUserCredentials(String userName, String realmName)
            throws Exception {
        User usr = null;
        try {
            Query query = _session.getNamedQuery(User.FIND_USER_OF_REALM)
                    .setString(User.USER_NAME, userName)
                    .setString(User.REALM_NAME, realmName);
            usr = (User) query.uniqueResult();
            if (usr == null) {
                throw new UserNotFoundException("User not found" + userName
                        + " in realm" + realmName);
            }
            Property name = new Property(RBACConstants.PROPERTY_DISPLAY_NAME,
                    usr.getDisplayName());
            Property password = new Property(
                    AuthenticationConstants.PROPERTY_PASSWORD, new String(
                            usr.getPassword()));

            return new Property[] { name, password };
        } catch (Exception re) {
            log.error("Error While fetching user credential of user " + userName, re);
            throw new Exception("Error While fetching user credential of user " + userName, re);
        }
    }

    /**
     * @param realm
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public List<User> getUsers(String realm) throws Exception {
        try {
            List<User> users = _session.getNamedQuery(User.FIND_USERS_OF_REALM)
                    .setString(User.REALM_NAME, realm).list();
            return users;
        } catch (Exception re) {
            log.error("Error while fetching users of realm " + realm, re);
            throw new Exception("Error while fetching users of realm " + realm,
                    re);
        }
    }

    /**
     * @param realm
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public List<Role> getRoles(String realm) throws Exception {
        try {
            List<Role> roles = _session.getNamedQuery(Role.FIND_ROLES_OF_REALM)
                    .setString(Role.REALM_NAME, realm).list();
            return roles;
        } catch (Exception re) {
            log.error("Error while fetching roles of realm " + realm, re);
            throw new Exception("Error while fetching roles of realm " + realm,
                    re);
        }
    }

    /**
     * @param roleName
     * @return
     * @throws Exception
     */
    public List<Property> roleProperties(String roleName) throws Exception {
        Role role = null;
        List<Property> properties = null;
        try {
            properties = new ArrayList<Property>();
            Query query = _session.getNamedQuery(Role.FIND_ROLE).setString(
                    Role.ROLE_NAME, roleName);
            role = (Role) query.uniqueResult();
            if (role != null) {
                String description = role.getDescription();
                if (description != null)
                    properties.add(new Property(
                            RBACConstants.PROPERTY_DESCRIPTION, role
                                    .getDescription()));
                Set<RoleHierarchy> roleHierarchies = role.getRoleHierarchies();
                List<String> descendantRoles = new ArrayList<String>();
                for (RoleHierarchy roleHierarchy : roleHierarchies) {
                    String descendantRoleName = DatabaseHelperUtil.normalize(
                            roleHierarchy.getDescendantRole().getIdentifier(),
                            roleHierarchy.getDescendantRole().getRealm()
                                    .getIdentifier());
                    descendantRoles.add(descendantRoleName);
                }
                if (descendantRoles.size() > 0)
                    properties
                            .add(new Property(
                                    RBACConstants.PROPERTY_DESCENDANT_ROLE,
                                    StringArrayUtils
                                            .toCommaDelimited((String[]) descendantRoles
                                                    .toArray(new String[descendantRoles
                                                            .size()]))));
            }
            return properties;
        } catch (Exception re) {
            log.error("Error while fetching role properties of Role "
                    + roleName, re);
            throw new Exception("Error while fetching role properties of Role "
                    + roleName, re);
        }
    }

    /**
     * @param userName
     * @param realmName
     * @return
     * @throws Exception
     */
    public List<Property> userProperties(String userName, String realmName)
            throws Exception {
        User usr = null;
        List<Property> properties = null;
        try {
            properties = new ArrayList<Property>();
            Query query = _session.getNamedQuery(User.FIND_USER_OF_REALM)
                    .setString(User.USER_NAME, userName)
                    .setString(User.REALM_NAME, realmName);
            usr = (User) query.uniqueResult();
            if (usr != null) {
                String name = usr.getDisplayName();
                if (name != null && !name.equals(""))
                    properties.add(new Property(
                            RBACConstants.PROPERTY_DISPLAY_NAME, name));
                String email = usr.getEmail();
                if (email != null && !email.equals(""))
                    properties.add(new Property(RBACConstants.PROPERTY_EMAIL,
                            email));
                String firstName = usr.getFirstName();
                if (firstName != null && !firstName.equals(""))
                    properties.add(new Property(
                            RBACConstants.PROPERTY_FIRST_NAME, firstName));
                String lastName = usr.getLastName();
                if (lastName != null && !lastName.equals(""))
                    properties.add(new Property(
                            RBACConstants.PROPERTY_LAST_NAME, lastName));
                Set<Role> userRoles = usr.getUserRoles();
                List<String> assignedRole = new ArrayList<String>();
                for (Role userRole : userRoles) {
                    String assignedRoleName = DatabaseHelperUtil.normalize(
                            userRole.getIdentifier(), userRole.getRealm()
                                    .getIdentifier());
                    assignedRole.add(assignedRoleName);
                }
                if (assignedRole.size() > 0)
                    properties.add(new Property(
                            RBACConstants.PROPERTY_ASSIGN_ROLES,
                            StringArrayUtils
                                    .toCommaDelimited((String[]) assignedRole
                                            .toArray(new String[assignedRole
                                                    .size()]))));
            }
            return properties;
        } catch (Exception re) {
            log.error("Error While fetching user properties of user "
                    + userName, re);
            throw new Exception("Error While fetching user properties of user "
                    + userName, re);
        }
    }

    /**
     * @param object
     * @throws Exception
     */
    public void saveOrUpdate(final Object object) throws Exception {
        try {
            _session.saveOrUpdate(object);
        } catch (Exception re) {
            log.error("Exception while saving or updating object", re);
            throw new Exception("Exception while saving or updating object", re);
        }
    }

    /**
     * @param object
     * @throws Exception
     */
    public void save(final Object object) throws Exception {
        try {
            _session.save(object);
        } catch (Exception re) {
            log.warn("Exception while saving object", re);
            throw new Exception("Exception while saving object", re);
        }
    }

    /**
     * @param object
     * @throws Exception
     */
    public void delete(final Object object) throws Exception {
        try {
            _session.delete(object);
        } catch (Exception re) {
            log.warn("Exception while deleting object", re);
            throw new Exception("Exception while deleting object", re);
        }
    }

    /**
     * @param realmName
     * @return
     * @throws Exception
     */
    public Realm getRealm(String realmName) throws Exception {
        Realm realm = null;
        try {
            Query query = _session.getNamedQuery(Realm.FIND_REALM).setString(
                    Realm.REALM_NAME, realmName);
            realm = (Realm) query.uniqueResult();
            if (realm == null) {
                throw new RBACException("Realm not found " + realmName);
            }
        } catch (Exception re) {
            log.error("Error while fetching realm " + realmName, re);
            throw new Exception("Error while fetching realm " + realmName, re);
        }
        return realm;
    }

    /**
     * @param roleName
     * @return
     * @throws Exception
     */
    public Role getRole(String roleName) throws Exception {
        Role role = null;
        try {
            Query query = _session.getNamedQuery(Role.FIND_ROLE).setString(
                    Role.ROLE_NAME, roleName);
            role = (Role) query.uniqueResult();
            if (role == null) {
                throw new RBACException("Role not found " + roleName);
            }
        } catch (Exception re) {
            log.error("Error while fetching role " + roleName, re);
            throw new Exception("Error while fetching role " + roleName, re);
        }
        return role;
    }

    /**
     * @param userName
     * @return
     * @throws Exception
     */
    public User getUser(String userName) throws Exception {
        User user = null;
        try {
            Query query = _session.getNamedQuery(User.FIND_USER).setString(
                    User.USER_NAME, userName);
            user = (User) query.uniqueResult();
            if (user == null) {
                throw new RBACException("User not found " + userName);
            }
        } catch (Exception re) {
            log.error("Error while fetching user " + userName, re);
            throw new Exception("Error while fetching user " + userName, re);
        }
        return user;
    }

    /**
     * @param userName
     * @param realmName
     * @return
     * @throws Exception
     */
    public Set<Role> authorizedRoles(String userName, String realmName)
            throws Exception {
        User user = null;
        Set<Role> userRoles = null;
        try {
            Query query = _session.getNamedQuery(User.FIND_USER_OF_REALM)
                    .setString(User.USER_NAME, userName)
                    .setString(User.REALM_NAME, realmName);
            user = (User) query.uniqueResult();
            if (user == null) {
                throw new RBACException("User not found " + userName);
            }
            userRoles = user.getUserRoles();
        } catch (Exception re) {
            log.error("Error while fetching authorized roles of user " + userName, re);
            throw new Exception("Error while fetching authorized roles of user " + userName, re);
        }
        return userRoles;
    }

    /**
     * @param workflowRoles
     * @return
     * @throws Exception
     */
    public Set<String> getWorkflowAdminRoles(Set<String> workflowRoles)
            throws Exception {
        Query query = null;
        Role role = null;
        Set<String> workflowAdminRoles = new HashSet<String>();
        try {
            for (String roleName : workflowRoles) {
                query = _session.getNamedQuery(Role.FIND_ROLE).setString(
                        Role.ROLE_NAME, IdentifierUtils.stripRealm(roleName));
                role = (Role) query.uniqueResult();
                if (role == null)
                    throw new RBACException("Role not found " + roleName);
                String workflowRole = DatabaseHelperUtil.normalize(
                        role.getIdentifier(), role.getRealm().getIdentifier());
                workflowAdminRoles.add(workflowRole);
            }
        } catch (Exception re) {
            log.error("Error while fetching WorkflowAdminRoles ", re);
            throw new Exception("Error while fetching WorkflowAdminRoles ", re);
        }
        return workflowAdminRoles;
    }

    /**
     * @param workflowUsers
     * @return
     * @throws Exception
     */
    public Set<String> getWorkflowAdminUsers(Set<String> workflowUsers)
            throws Exception {
        Query query = null;
        User user = null;
        Set<String> workflowAdminUsers = new HashSet<String>();
        try {
            for (String userName : workflowAdminUsers) {
                query = _session.getNamedQuery(User.FIND_USER).setString(
                        User.USER_NAME, userName);
                user = (User) query.uniqueResult();
                if (user == null)
                    throw new RBACException("User not found " + userName);
                String workflowUser = DatabaseHelperUtil.normalize(
                        user.getIdentifier(), user.getRealm().getIdentifier());
                workflowAdminUsers.add(workflowUser);
            }
        } catch (Exception re) {
            log.error("Error while fetching WorkflowAdminUsers ", re);
            throw new Exception("Error while fetching WorkflowAdminUsers ", re);
        }
        return workflowAdminUsers;
    }

    /**
     * @return
     * @throws Exception
     */
    public Session getSession() throws Exception {
        try {
            _session = _sessionFactory.openSession();
        } catch (Exception re) {
            log.warn("Exception while saving object", re);
            throw new Exception("Exception while opening session", re);
        }
        return _session;
    }

    /**
     * @throws Exception
     */
    public void closeSession() throws Exception {
        try {
            if (_session != null)
                _session.close();
        } catch (Exception re) {
            log.warn("Exception while saving object", re);
            throw new Exception("Exception while closing session", re);
        }
    }

    /**
     * @param roleName
     * @param realmName
     * @return
     * @throws Exception
     */
    public List<String> assignedUsers(String roleName, String realmName)
            throws Exception {
        Set<User> users = null;
        List<String> assignedUsers = null;
        Role role = null;
        Query query = null;
        try {
            assignedUsers = new ArrayList<String>();
            query = _session.getNamedQuery(Role.FIND_ROLE_OF_REALM)
                    .setString(Role.ROLE_NAME, roleName)
                    .setString(Role.REALM_NAME, realmName);
            role = (Role) query.uniqueResult();
            if (role == null) {
                throw new RoleNotFoundException("Role not found" + roleName
                        + " in realm" + realmName);
            }
            users = role.getUserRoles();
            for (User user : users) {
                String userName = DatabaseHelperUtil.normalize(
                        user.getIdentifier(), user.getRealm().getIdentifier());
                assignedUsers.add(userName);
            }
        } catch (Exception re) {
            log.error(
                    "Error while fetching assigned users of role " + roleName,
                    re);
            throw new Exception("Error while fetching assigned users of role "
                    + roleName, re);
        }
        return assignedUsers;
    }

    /**
     * @param userName
     * @param realmName
     * @return
     * @throws Exception
     */
    public List<String> assignedRoles(String userName, String realmName)
            throws Exception {
        Set<Role> roles = null;
        List<String> assignedRole = null;
        User user = null;
        Query query = null;
        try {
            assignedRole = new ArrayList<String>();
            query = _session.getNamedQuery(User.FIND_USER_OF_REALM)
                    .setString(User.USER_NAME, userName)
                    .setString(User.REALM_NAME, realmName);
            user = (User) query.uniqueResult();
            if (user == null) {
                throw new UserNotFoundException("User not found" + userName
                        + " in realm" + realmName);
            }
            roles = user.getUserRoles();
            for (Role role : roles) {
                String roleName = DatabaseHelperUtil.normalize(
                        role.getIdentifier(), role.getRealm().getIdentifier());
                assignedRole.add(roleName);
            }
        } catch (Exception re) {
            log.error(
                    "Error while fetching assigned roles of user " + userName,
                    re);
            throw new Exception("Error while fetching assigned roles of user "
                    + userName, re);
        }
        return assignedRole;
    }

    /**
     * @param roleName
     * @return
     * @throws Exception
     */
    public List<String> descendantRoles(String roleName) throws Exception {
        Set<RoleHierarchy> roleHierarchies = null;
        List<String> descendantRoles = null;
        Role role = null;
        Query query = null;
        try {
            descendantRoles = new ArrayList<String>();
            query = _session.getNamedQuery(Role.FIND_ROLE).setString(
                    Role.ROLE_NAME, roleName);
            role = (Role) query.uniqueResult();
            if (role == null) {
                throw new RoleNotFoundException("Role not found" + roleName);
            }
            roleHierarchies = role.getRoleHierarchies();
            descendantRoles = new ArrayList<String>();
            for (RoleHierarchy roleHierarchy : roleHierarchies) {
                String descendantRoleName = DatabaseHelperUtil.normalize(
                        roleHierarchy.getDescendantRole().getIdentifier(),
                        roleHierarchy.getDescendantRole().getRealm()
                                .getIdentifier());
                descendantRoles.add(descendantRoleName);
            }
        } catch (Exception re) {
            log.error("Error while fetching descendant roles of role "
                    + roleName, re);
            throw new Exception(
                    "Error while fetching descendant roles of role " + roleName,
                    re);
        }
        return descendantRoles;
    }

    /**
     * @param roleName
     * @param realmName
     * @return
     * @throws Exception
     */
    public Set<User> authorizedUsers(String roleName, String realmName)
            throws Exception {
        Role role = null;
        Set<User> users = null;
        try {
            Query query = _session.getNamedQuery(Role.FIND_ROLE_OF_REALM)
                    .setString(Role.ROLE_NAME, roleName)
                    .setString(Role.REALM_NAME, realmName);
            role = (Role) query.uniqueResult();
            if (role == null) {
                throw new RBACException("Role not found " + roleName);
            }
            users = role.getUserRoles();
        } catch (Exception re) {
            log.error("Error while fetching authorized users of role "
                    + roleName, re);
            throw new Exception(
                    "Error while fetching authorized users of role " + roleName,
                    re);
        }
        return users;
    }

    /**
     * @param roleName
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public List<RoleHierarchy> ascendantRoles(String roleName) throws Exception {
        List<RoleHierarchy> roleHierarchies = null;
        Query query = null;
        try {
            query = _session.getNamedQuery(RoleHierarchy.FIND_ROLE_HIERARCHIES)
                    .setString(RoleHierarchy.ROLE_NAME, roleName);
            roleHierarchies = query.list();
        } catch (Exception re) {
            log.error("Error while fetching ascendant roles of role "
                    + roleName, re);
            throw new Exception("Error while fetching ascendant roles of role "
                    + roleName, re);
        }
        return roleHierarchies;
    }

    /**
     * @param realmName
     * @return
     * @throws Exception
     */
    public List<String> topRoles(String realmName) throws Exception {
        Realm realm = null;
        List<String> topRoles = null;
        List<String> descendantRoles = null;
        Set<Role> roles = null;
        Query query = null;
        try {
            topRoles = new ArrayList<String>();
            query = _session.getNamedQuery(Realm.FIND_REALM).setString(
                    Realm.REALM_NAME, realmName);
            realm = (Realm) query.uniqueResult();
            topRoles = new ArrayList<String>();
            descendantRoles = new ArrayList<String>();
            roles = realm.getRoles();
            for (Role role : roles) {
                String topRoleName = DatabaseHelperUtil.normalize(
                        role.getIdentifier(), role.getRealm().getIdentifier());
                for (RoleHierarchy roleHierarchy : role.getRoleHierarchies()) {
                    String descendantRoleName = DatabaseHelperUtil.normalize(
                            roleHierarchy.getDescendantRole().getIdentifier(),
                            roleHierarchy.getDescendantRole().getRealm()
                                    .getIdentifier());
                    descendantRoles.add(descendantRoleName);
                }
                topRoles.add(topRoleName);
            }
            topRoles.removeAll(descendantRoles);
        } catch (Exception re) {
            log.error("Error while fetching top roles of realm " + realmName,
                    re);
            throw new Exception("Error while fetching top roles of realm "
                    + realmName, re);
        }
        return topRoles;
    }

    /**
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public List<Realm> getRealms() throws Exception {
        List<Realm> realms = null;
        Query query = null;
        try {
            query = _session.getNamedQuery(Realm.FIND_REALMS);
            realms = query.list();
        } catch (Exception re) {
            log.error("Error while fetching realms ", re);
            throw new Exception("Error while fetching realms ", re);
        }
        return realms;
    }

    /**
     * @param roleName
     * @param descendantRole
     * @return
     * @throws Exception
     */
    public RoleHierarchy getRoleHierarchy(String roleName, String descendantRole)
            throws Exception {
        RoleHierarchy roleHierarchy = null;
        try {
            Query query = _session
                    .getNamedQuery(RoleHierarchy.FIND_ROLE_HIERARCHY)
                    .setString(RoleHierarchy.ROLE_NAME, roleName)
                    .setString(RoleHierarchy.DESENDANT_ROLE_NAME,
                            descendantRole);
            roleHierarchy = (RoleHierarchy) query.uniqueResult();
        } catch (Exception re) {
            log.error("Error while fetching RoleHierarchy of role " + roleName,
                    re);
            throw new Exception("Error while fetching RoleHierarchy of role "
                    + roleName, re);
        }
        return roleHierarchy;
    }

    /**
     * @param roleName
     * @param descendantRole
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public List<RoleHierarchy> getAscDescRoleHierarchy(String roleName,
            String descendantRole) throws Exception {
        List<RoleHierarchy> roleHierarchies = null;
        try {
            Query query = _session
                    .getNamedQuery(RoleHierarchy.FIND_ASC_DESC_ROLE_HIERARCHIES)
                    .setString(RoleHierarchy.ROLE_NAME, roleName)
                    .setString(RoleHierarchy.DESENDANT_ROLE_NAME,
                            descendantRole);
            roleHierarchies = query.list();
        } catch (Exception re) {
            log.error(
                    "Error while fetching ascendant and descendant RoleHierarchy of role "
                            + roleName, re);
            throw new Exception(
                    "Error while fetching ascendant and descendant RoleHierarchy of role "
                            + roleName, re);
        }
        return roleHierarchies;
    }
}
