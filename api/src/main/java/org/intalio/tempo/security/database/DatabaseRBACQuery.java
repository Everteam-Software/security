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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.database.dao.DAO;
import org.intalio.tempo.security.database.model.Role;
import org.intalio.tempo.security.database.model.RoleHierarchy;
import org.intalio.tempo.security.database.model.User;
import org.intalio.tempo.security.database.util.DatabaseHelperUtil;
import org.intalio.tempo.security.rbac.ObjectNotFoundException;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.RBACQuery;
import org.intalio.tempo.security.rbac.RoleNotFoundException;
import org.intalio.tempo.security.rbac.UserNotFoundException;
import org.intalio.tempo.security.util.IdentifierUtils;

/**
 * @author amit
 * 
 */
public class DatabaseRBACQuery implements RBACQuery {

    private static Logger log = Logger.getLogger(DatabaseRBACQuery.class);
    private String _realm;
    private DAO _dao;

    /**
     * @param realmName
     * @param dao
     */
    public DatabaseRBACQuery(String realmName, DAO dao) {
        _realm = realmName;
        _dao = dao;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#assignedUsers(java.lang.String)
     */
    public String[] assignedUsers(String roleName)
            throws RoleNotFoundException, RBACException, RemoteException {
        List<String> assignedUsers = null;
        try {
            _dao.getSession();
            assignedUsers = _dao.assignedUsers(
                    IdentifierUtils.stripRealm(roleName), _realm);
        } catch (Exception e) {
            log.error("Error occurred while fetching assigned users of role "
                    + roleName, e);
            throw new RBACException(
                    "Error occurred while fetching assigned users of role "
                            + roleName, e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return (String[]) assignedUsers
                .toArray(new String[assignedUsers.size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#assignedRoles(java.lang.String)
     */
    public String[] assignedRoles(String userName)
            throws UserNotFoundException, RBACException, RemoteException {
        List<String> assignedRoles = null;
        try {
            _dao.getSession();
            assignedRoles = _dao.assignedRoles(
                    IdentifierUtils.stripRealm(userName), _realm);
        } catch (Exception e) {
            log.error("Error occurred while fetching assigned roles of user "
                    + userName, e);
            throw new RBACException(
                    "Error occurred while fetching assigned roles of user "
                            + userName, e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return (String[]) assignedRoles
                .toArray(new String[assignedRoles.size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#roleOperationsOnObject(java
     * .lang.String, java.lang.String)
     */
    public String[] roleOperationsOnObject(String role, String object)
            throws RoleNotFoundException, ObjectNotFoundException,
            RBACException, RemoteException {
        // TODO
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#userOperationsOnObject(java
     * .lang.String, java.lang.String)
     */
    public String[] userOperationsOnObject(String user, String object)
            throws UserNotFoundException, ObjectNotFoundException,
            RBACException, RemoteException {
        // TODO
        return null;

    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#authorizedUsers(java.lang.String
     * )
     */
    public String[] authorizedUsers(String roleName)
            throws RoleNotFoundException, RBACException, RemoteException {
        Set<User> users = null;
        List<String> authorizedUsers = null;
        try {
            _dao.getSession();
            users = _dao.authorizedUsers(IdentifierUtils.stripRealm(roleName),
                    _realm);
            authorizedUsers = new ArrayList<String>();
            for (User user : users) {
                String authorizedUserName = DatabaseHelperUtil.normalize(
                        user.getIdentifier(), user.getRealm().getIdentifier());
                authorizedUsers.add(authorizedUserName);
            }
        } catch (Exception e) {
            log.error("Error while fetching authorized users of role "
                    + roleName, e);
            throw new RBACException(
                    "Error while fetching authorized users of role " + roleName,
                    e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return (String[]) authorizedUsers.toArray(new String[authorizedUsers
                .size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#authorizedRoles(java.lang.String
     * )
     */
    public String[] authorizedRoles(String userName)
            throws UserNotFoundException, RBACException, RemoteException {
        Set<Role> userRoles = null;
        Set<String> authorizedRoles = null;
        try {
            _dao.getSession();
            userRoles = _dao.authorizedRoles(
                    IdentifierUtils.stripRealm(userName), _realm);
            authorizedRoles = new HashSet<String>();
            for (Role useRole : userRoles) {
                String userRoleName = DatabaseHelperUtil.normalize(useRole
                        .getIdentifier(), useRole.getRealm().getIdentifier());
                authorizedRoles.add(userRoleName);
                Set<RoleHierarchy> roleHierarchies = useRole
                        .getRoleHierarchies();
                for (RoleHierarchy roleHierarchy : roleHierarchies) {
                    String descendantRoleName = DatabaseHelperUtil.normalize(
                            roleHierarchy.getDescendantRole().getIdentifier(),
                            roleHierarchy.getDescendantRole().getRealm()
                                    .getIdentifier());
                    authorizedRoles.add(descendantRoleName);
                }
            }
        } catch (Exception e) {
            log.error("Error while fetching authorized roles of user "
                    + userName, e);
            throw new RBACException(
                    "Error while fetching authorized roles of user " + userName,
                    e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return (String[]) authorizedRoles.toArray(new String[authorizedRoles
                .size()]);

    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.rbac.RBACQuery#topRoles(java.lang.String)
     */
    public String[] topRoles(String realmName) throws RBACException,
            RemoteException {
        List<String> topRoles = null;
        try {
            _dao.getSession();
            topRoles = _dao.topRoles(realmName);
        } catch (Exception e) {
            log.error("Error while fetching top roles of realm " + realmName, e);
            throw new RBACException("Error while fetching top roles of realm "
                    + realmName, e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return (String[]) topRoles.toArray(new String[topRoles.size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#ascendantRoles(java.lang.String
     * )
     */
    public String[] ascendantRoles(String roleName)
            throws RoleNotFoundException, RBACException, RemoteException {
        List<RoleHierarchy> roleHierarchies = null;
        List<String> ascendantRoles = null;
        try {
            _dao.getSession();
            roleHierarchies = _dao.ascendantRoles(IdentifierUtils
                    .stripRealm(roleName));
            ascendantRoles = new ArrayList<String>();
            for (RoleHierarchy roleHierarchy : roleHierarchies) {
                String ascendantRolesName = DatabaseHelperUtil.normalize(
                        roleHierarchy.getRole().getIdentifier(), roleHierarchy
                                .getRole().getRealm().getIdentifier());
                ascendantRoles.add(ascendantRolesName);
            }
        } catch (Exception e) {
            log.error("Error while fetching ascendant roles of role "
                    + roleName, e);
            throw new RBACException(
                    "Error while fetching ascendant roles of role " + roleName,
                    e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return (String[]) ascendantRoles.toArray(new String[ascendantRoles
                .size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#descendantRoles(java.lang.String
     * )
     */
    public String[] descendantRoles(String roleName)
            throws RoleNotFoundException, RBACException, RemoteException {
        List<String> descendantRoles = null;
        try {
            _dao.getSession();
            descendantRoles = _dao.descendantRoles(IdentifierUtils
                    .stripRealm(roleName));
        } catch (Exception e) {
            log.error("Error while fetching descendant roles of role "
                    + roleName, e);
            throw new RBACException(
                    "Error while fetching descendant roles of role " + roleName,
                    e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return (String[]) descendantRoles.toArray(new String[descendantRoles
                .size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#userProperties(java.lang.String
     * )
     */
    public Property[] userProperties(String userName)
            throws UserNotFoundException, RBACException, RemoteException {
        List<Property> properties = null;
        try {
            _dao.getSession();
            properties = _dao.userProperties(
                    IdentifierUtils.stripRealm(userName), _realm);
        } catch (Exception e) {
            log.error("Error while fetching user properties of user "
                    + userName, e);
            throw new RBACException(
                    "Error while fetching user properties of user " + userName,
                    e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return properties.toArray(new Property[properties.size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACQuery#roleProperties(java.lang.String
     * )
     */
    public Property[] roleProperties(String roleName)
            throws RoleNotFoundException, RBACException, RemoteException {
        List<Property> properties = null;
        try {
            _dao.getSession();
            properties = _dao.roleProperties(IdentifierUtils
                    .stripRealm(roleName));
        } catch (Exception e) {
            log.error("Error while fetching role properties of role "
                    + roleName, e);
            throw new RBACException(
                    "Error while fetching role properties of role " + roleName,
                    e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return properties.toArray(new Property[properties.size()]);

    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.rbac.RBACQuery#getRoles(java.lang.String)
     */
    @Override
    public String[] getRoles(String realmName) throws RBACException,
            RemoteException {
        List<Role> roles;
        List<String> roleList = null;
        try {
            _dao.getSession();
            roleList = new ArrayList<String>();
            roles = _dao.getRoles(realmName);
            for (Role role : roles) {
                String roleName = DatabaseHelperUtil.normalize(
                        role.getIdentifier(), realmName);
                roleList.add(roleName);
            }
        } catch (Exception e) {
            log.error("Error while fetching roles of realm " + realmName, e);
            throw new RBACException("Error while fetching roles of realm "
                    + realmName, e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return (String[]) roleList.toArray(new String[roleList.size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.rbac.RBACQuery#getUsers(java.lang.String)
     */
    @Override
    public String[] getUsers(String realmName) throws RBACException,
            RemoteException {
        List<User> users;
        List<String> userList = null;
        try {
            _dao.getSession();
            users = _dao.getUsers(realmName);
            userList = new ArrayList<String>();
            for (User usr : users) {
                String userName = DatabaseHelperUtil.normalize(
                        usr.getIdentifier(), realmName);
                userList.add(userName);
            }

        } catch (Exception e) {
            log.error("Error while fetching users of realm " + realmName, e);
            throw new RBACException("Error while fetching users of realm "
                    + realmName, e);
        } finally {
            try {
                _dao.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return (String[]) userList.toArray(new String[userList.size()]);
    }

}
