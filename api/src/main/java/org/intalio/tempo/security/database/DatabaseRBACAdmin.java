/**
 * Copyright (C) 2014, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */
package org.intalio.tempo.security.database;

import java.rmi.RemoteException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.database.dao.DAO;
import org.intalio.tempo.security.database.model.Realm;
import org.intalio.tempo.security.database.model.Role;
import org.intalio.tempo.security.database.model.RoleHierarchy;
import org.intalio.tempo.security.database.model.User;
import org.intalio.tempo.security.database.util.DatabaseHelperUtil;
import org.intalio.tempo.security.rbac.RBACAdmin;
import org.intalio.tempo.security.rbac.RBACConstants;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.RoleNotFoundException;
import org.intalio.tempo.security.rbac.UserNotFoundException;
import org.intalio.tempo.security.util.IdentifierUtils;
import org.jasypt.util.text.BasicTextEncryptor;

/**
 * @author amit
 * 
 */
public class DatabaseRBACAdmin implements RBACAdmin {

    private static Logger log = Logger.getLogger(DatabaseRBACAdmin.class);
    private String _realm;
    private DAO _dao;

    /**
     * @param realmName
     * @param dao
     */
    public DatabaseRBACAdmin(String realmName, DAO dao) {
        _realm = realmName;
        _dao = dao;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.rbac.RBACAdmin#addUser(java.lang.String,
     * org.intalio.tempo.security.Property[])
     */
    @Override
    public void addUser(String userName, Property[] properties)
            throws RBACException, RemoteException {
        Session session = null;
        Transaction transaction = null;
        Set<Role> userRoles = null;
        try {
            session = _dao.getSession();
            checkValidRoles(properties, session);
            if (isUserExists(userName, session)) {
                throw new RBACException("User already exists in database");
            } else {
                transaction = session.beginTransaction();
                User user = new User();
                userRoles = user.getUserRoles();
                user.setIdentifier(userName);
                Realm realm = _dao.getRealm(_realm, session);
                user.setRealm(realm);
                for (int i = 0; i < properties.length; i++) {
                    Property prop = properties[i];
                    if (prop.getName().equals(
                            RBACConstants.PROPERTY_DISPLAY_NAME))
                        user.setDisplayName((String) prop.getValue());
                    else if (prop.getName().equals(
                            RBACConstants.PROPERTY_USER_PASSWORD)) {
                        BasicTextEncryptor encryptor = new BasicTextEncryptor();
                        // setPassword uses hash to encrypt password which
                        // should be
                        // same as hash of encryptor
                        encryptor
                                .setPassword(DatabaseHelperUtil.ENCRYPTED_PASSWORD);
                        String decryptPassword = encryptor
                                .encrypt((String) prop.getValue());
                        user.setPassword(decryptPassword);
                    } else if (prop.getName().equals(
                            RBACConstants.PROPERTY_EMAIL))
                        user.setEmail((String) prop.getValue());
                    else if (prop.getName().equals(
                            RBACConstants.PROPERTY_FIRST_NAME))
                        user.setFirstName((String) prop.getValue());
                    else if (prop.getName().equals(
                            RBACConstants.PROPERTY_LAST_NAME))
                        user.setLastName((String) prop.getValue());
                    else if (prop.getName().equals(
                            RBACConstants.PROPERTY_ASSIGN_ROLES))
                        userRoles.add(getAssignedRoles(_dao,
                                (String) prop.getValue(), session));
                }
                _dao.save(user, session);
                transaction.commit();
            }
        } catch (Exception e) {
            if (transaction != null)
                transaction.rollback();
            log.error("Error occured while adding user " + userName, e);
            throw new RBACException("Error occured while adding user "
                    + userName, e);
        } finally {
            try {
                _dao.closeSession(session);
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
    }

    /**
     * @param userName
     * @param session
     * @return
     */
    private boolean isUserExists(String userName, Session session) {
        User user = null;
        try {
            user = _dao.getUser(_realm, userName, session);
            if (user != null)
                return true;
        } catch (Exception e) {
            log.error("Error occurred while checking existance of user "
                    + userName, e);
        }
        return false;
    }

    /**
     * @param dao
     * @param assignRole
     * @return
     * @throws RBACException
     */
    private Role getAssignedRoles(DAO dao, String assignRole, Session session)
            throws RBACException {
        Role role = null;
        try {
            role = dao.getRole(IdentifierUtils.getRealm(assignRole),
                    IdentifierUtils.stripRealm(assignRole), session);
        } catch (Exception e) {
            log.error("Error occurred while fetching assigned role "
                    + assignRole, e);
        }
        return role;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACAdmin#deleteUser(java.lang.String)
     */
    @Override
    public void deleteUser(String userName) throws RBACException,
            RemoteException {
        User user = null;
        Session session = null;
        Transaction transaction = null;
        Set<Role> roles = null;
        try {
            session = _dao.getSession();
            transaction = session.beginTransaction();
            user = _dao.getUser(_realm, userName, session);
            roles = user.getUserRoles();
            roles.clear();
            _dao.delete(user, session);
            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
            log.error("Error occured while deleting user " + userName, e);
            throw new RBACException("Error occured while deleting user "
                    + userName, e);
        } finally {
            try {
                _dao.closeSession(session);
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.rbac.RBACAdmin#addRole(java.lang.String,
     * org.intalio.tempo.security.Property[])
     */
    @Override
    public void addRole(String roleName, Property[] properties)
            throws RoleNotFoundException, RBACException, RemoteException {
        Session session = null;
        Transaction transaction = null;
        try {
            session = _dao.getSession();
            checkValidRoles(properties, session);
            if (isRoleExists(roleName, session)) {
                throw new RBACException("Role already exists in database");
            } else {
                transaction = session.beginTransaction();
                Set<RoleHierarchy> roleHierarchies = new HashSet<RoleHierarchy>();
                Role role = new Role();
                role.setIdentifier(roleName);
                Realm realm = _dao.getRealm(_realm, session);
                role.setRealm(realm);
                for (int i = 0; i < properties.length; i++) {
                    Property prop = properties[i];
                    if (prop.getName().equals(
                            RBACConstants.PROPERTY_DESCRIPTION))
                        role.setDescription((String) prop.getValue());
                    else if (prop.getName().equals(
                            RBACConstants.PROPERTY_DESCENDANT_ROLE))
                        roleHierarchies.add(getDescendantRoles(_dao,
                                (String) prop.getValue(), role, session));
                }
                role.setRoleHierarchies(roleHierarchies);
                _dao.save(role, session);
                transaction.commit();
            }
        } catch (Exception e) {
            if (transaction != null)
                transaction.rollback();
            log.error("Error occured while adding role " + roleName, e);
            throw new RBACException("Error occured while adding role "
                    + roleName, e);
        } finally {
            try {
                _dao.closeSession(session);
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
    }

    /**
     * @param roleName
     * @param session
     * @return
     */
    private boolean isRoleExists(String roleName, Session session) {
        Role role = null;
        try {
            role = _dao.getRole(roleName, _realm, session);
            if (role != null)
                return true;
        } catch (Exception e) {
            log.error("Error occurred while checking existance of role "
                    + roleName, e);
        }
        return false;
    }

    /**
     * @param dao
     * @param descendantRoleName
     * @param role
     * @return
     * @throws RBACException
     */
    private RoleHierarchy getDescendantRoles(DAO dao,
            String descendantRoleName, Role role, Session session)
            throws RBACException {
        Role descendantRole;
        RoleHierarchy roleHierarchy = null;
        try {
            descendantRole = dao.getRole(
                    IdentifierUtils.getRealm(descendantRoleName),
                    IdentifierUtils.stripRealm(descendantRoleName), session);
            roleHierarchy = new RoleHierarchy();
            roleHierarchy.setRole(role);
            roleHierarchy.setDescendantRole(descendantRole);
        } catch (Exception e) {
            log.error("Error occured while fetching descendant roles of role "
                    + role.getIdentifier(), e);
        }
        return roleHierarchy;
    }

    private RoleHierarchy getRoleHierarchy(DAO dao, String descendantRoleName,
            Role role, Session session) throws RBACException {
        Role descendantRole;
        RoleHierarchy roleHierarchy = null;
        try {
            descendantRole = dao.getRole(
                    IdentifierUtils.getRealm(descendantRoleName),
                    IdentifierUtils.stripRealm(descendantRoleName), session);
            roleHierarchy = dao.getRoleHierarchy(role.getRealm()
                    .getIdentifier(), role.getIdentifier(), descendantRole
                    .getIdentifier(), session);
            if (roleHierarchy == null) {
                roleHierarchy = new RoleHierarchy();
                roleHierarchy.setRole(role);
                roleHierarchy.setDescendantRole(descendantRole);
            }
        } catch (Exception e) {
            log.error("Error occured while fetching descendant roles of role "
                    + role.getIdentifier(), e);
        }
        return roleHierarchy;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACAdmin#deleteRole(java.lang.String)
     */
    @Override
    public void deleteRole(String roleName) throws RoleNotFoundException,
            RBACException, RemoteException {
        Session session = null;
        Transaction transaction = null;
        Set<User> users = null;
        Set<Role> assignedRoles = null;
        try {
            session = _dao.getSession();
            transaction = session.beginTransaction();
            Role role = _dao.getRole(_realm, roleName, session);
            users = _dao.authorizedUsers(role.getIdentifier(), role.getRealm()
                    .getIdentifier(), session);
            for (User user : users) {
                assignedRoles = user.getUserRoles();
                assignedRoles.remove(role);
                _dao.saveOrUpdate(user, session);
            }
            _dao.deleteAscDescRoleHierarchy(role.getId(), session);
            _dao.delete(role, session);
            transaction.commit();
        } catch (Exception e) {
            log.error("Error occurred while deleting role " + roleName, e);
            throw new RBACException("Error occurred while deleting role "
                    + roleName, e);
        } finally {
            try {
                _dao.closeSession(session);
            } catch (Exception ex) {
                log.error("Error occurred while closing session", ex);
            }
        }
    }

    @Override
    public void assignUser(String user, String role)
            throws UserNotFoundException, RoleNotFoundException, RBACException,
            RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void deassignUser(String user, String role)
            throws UserNotFoundException, RoleNotFoundException, RBACException,
            RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void grantPermission(String role, String operation, String object)
            throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void revokePermission(String role, String operation, String object)
            throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void addInheritance(String ascendant, String descendant)
            throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void deleteInheritance(String ascendant, String descendant)
            throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void addAscendant(String ascendant, Property[] properties,
            String descendant) throws RoleNotFoundException, RBACException,
            RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void addDescendant(String descendant, Property[] properties,
            String ascendant) throws RoleNotFoundException, RBACException,
            RemoteException {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACAdmin#setUserProperties(java.lang
     * .String, org.intalio.tempo.security.Property[])
     */
    @Override
    public void setUserProperties(String userName, Property[] properties)
            throws UserNotFoundException, RBACException, RemoteException {
        Set<Role> userRoles = null;
        Session session = null;
        Transaction transaction = null;
        User user = null;
        try {
            session = _dao.getSession();
            transaction = session.beginTransaction();
            checkValidRoles(properties, session);
            user = _dao.getUser(_realm, userName, session);
            userRoles = user.getUserRoles();
            userRoles.clear();
            for (int i = 0; i < properties.length; i++) {
                Property prop = properties[i];
                if (prop.getName().equals(RBACConstants.PROPERTY_DISPLAY_NAME))
                    user.setDisplayName((String) prop.getValue());
                else if (prop.getName().equals(
                        RBACConstants.PROPERTY_USER_PASSWORD)) {
                    BasicTextEncryptor encryptor = new BasicTextEncryptor();
                    // setPassword uses hash to encrypt password which should be
                    // same as hash of encryptor
                    encryptor
                            .setPassword(DatabaseHelperUtil.ENCRYPTED_PASSWORD);
                    String decryptPassword = encryptor.encrypt((String) prop
                            .getValue());
                    user.setPassword(decryptPassword);
                } else if (prop.getName().equals(RBACConstants.PROPERTY_EMAIL))
                    user.setEmail((String) prop.getValue());
                else if (prop.getName().equals(
                        RBACConstants.PROPERTY_FIRST_NAME))
                    user.setFirstName((String) prop.getValue());
                else if (prop.getName()
                        .equals(RBACConstants.PROPERTY_LAST_NAME))
                    user.setLastName((String) prop.getValue());
                else if (prop.getName().equals(
                        RBACConstants.PROPERTY_ASSIGN_ROLES))
                    userRoles.add(getAssignedRoles(_dao,
                            (String) prop.getValue(), session));
            }
            _dao.saveOrUpdate(user, session);
            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
            log.error("Error occured while updating user " + userName, e);
            throw new RBACException("Error occured while updating user "
                    + userName, e);
        } finally {
            try {
                _dao.closeSession(session);
            } catch (Exception ex) {
                log.error("Error occurred while closing session", ex);
            }
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACAdmin#setRoleProperties(java.lang
     * .String, org.intalio.tempo.security.Property[])
     */
    @Override
    public void setRoleProperties(String roleName, Property[] properties)
            throws RoleNotFoundException, RBACException, RemoteException {
        Transaction transaction = null;
        Session session = null;
        Set<RoleHierarchy> roleHierarchies = null;
        Set<RoleHierarchy> hierarchies = null;
        try {
            session = _dao.getSession();
            transaction = session.beginTransaction();
            checkValidRoles(properties, session);
            Role role = _dao.getRole(_realm, roleName, session);
            roleHierarchies = role.getRoleHierarchies();
            hierarchies = new HashSet<RoleHierarchy>();
            role.setIdentifier(roleName);
            for (int i = 0; i < properties.length; i++) {
                Property prop = properties[i];
                if (prop.getName().equals(RBACConstants.PROPERTY_DESCRIPTION))
                    role.setDescription((String) prop.getValue());
                else if (prop.getName().equals(
                        RBACConstants.PROPERTY_DESCENDANT_ROLE))
                    hierarchies.add(getRoleHierarchy(_dao,
                            (String) prop.getValue(), role, session));
            }
            for (RoleHierarchy roleHierarchy : roleHierarchies) {
                if (!hierarchies.contains(roleHierarchy))
                    _dao.delete(roleHierarchy, session);
            }
            roleHierarchies.clear();
            roleHierarchies.addAll(hierarchies);
            _dao.saveOrUpdate(role, session);
            transaction.commit();
        } catch (Exception e) {
            transaction.rollback();
            log.error("Error occured while updating role " + roleName, e);
            throw new RBACException("Error occured while updating role "
                    + roleName, e);
        } finally {
            try {
                _dao.closeSession(session);
            } catch (Exception ex) {
                log.error("Error occurred while closing session", ex);
            }
        }
    }

    private void checkValidRoles(Property[] props, Session session)
            throws RemoteException, RBACException {
        for (Property prop : props) {
            if (prop.getName().equals(RBACConstants.PROPERTY_ASSIGN_ROLES)
                    || prop.getName().equals(
                            RBACConstants.PROPERTY_DESCENDANT_ROLE)) {
                if (!checkRoleExists(prop.getValue().toString(), session))
                    throw new RBACException("Mentioned role: "
                            + prop.getValue().toString() + " does not exists");
            }
        }
    }

    /**
     * @param roleName
     * @return
     * @throws RemoteException
     * @throws RBACException
     */
    private boolean checkRoleExists(String roleName, Session session)
            throws RemoteException, RBACException {
        boolean exists = true;
        try {
            List<Property> properties = _dao.roleProperties(
                    IdentifierUtils.getRealm(roleName),
                    IdentifierUtils.stripRealm(roleName), session);
            Property[] props = properties.toArray(new Property[properties
                    .size()]);
            if (props == null || props.length == 0) {
                exists = false;
            }
        } catch (RoleNotFoundException re) {
            log.error("Role not found " + roleName, re);
            exists = false;
        } catch (Exception e) {
            log.error("Error occurred while fetching role " + roleName, e);
        }
        return exists;
    }
}
