package org.intalio.tempo.security.ws;

import static org.intalio.tempo.security.ws.Constants.OM_FACTORY;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMException;
import org.apache.axis2.AxisFault;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.rbac.RBACAdmin;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.RBACQuery;
import org.intalio.tempo.security.rbac.RoleExistsException;
import org.intalio.tempo.security.rbac.RoleNotFoundException;
import org.intalio.tempo.security.rbac.UserExistsException;
import org.intalio.tempo.security.rbac.UserNotFoundException;
import org.intalio.tempo.security.rbac.provider.RBACProvider;
import org.intalio.tempo.security.simple.SimpleSecurityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RBACAdminWS extends BaseWS {
    private static final Logger LOG = LoggerFactory.getLogger(RBACAdminWS.class);

    /**This method performs either add, delete or edit action for user
     * @param requestEl
     * @return
     */
    public OMElement modifyUser(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String realm = request.getRequiredString(RBACAdminConstants.REALM);
        String user = request.getRequiredString(RBACAdminConstants.USER);
        String action = request.getRequiredString(RBACAdminConstants.ACTION);
        LOG.debug("Realm: " + realm + " User: " + user + " Action " + action);
        try {
            RBACProvider usersRBACProvider = _securityProvider.getRBACProvider(realm);
            RBACAdmin usersRBACAdmin = usersRBACProvider.getAdmin();
            synchronized (this) {
                LOG.debug("Executing synchronized block");
                if (!checkUserExists(user, usersRBACProvider)) {
                    if (action.equals(RBACAdminConstants.ADD_ACTION)) {
                        Property[] props = request.getProperties(RBACAdminConstants.DETAILS);
                        usersRBACAdmin.addUser(user, props);
                    } else if (action.equals(RBACAdminConstants.EDIT_ACTION)
                            || action.equals(RBACAdminConstants.DELETE_ACTION)) {
                        UserNotFoundException e = new UserNotFoundException("User: " + user + " was not found.");
                        LOG.error("User: " + user + " was not found.");
                        throw new Fault(e, getUserNotFoundExceptionResponse(e));
                    }
                } else {
                    if (action.equals(RBACAdminConstants.EDIT_ACTION)) {
                        Property[] props = request.getProperties(RBACAdminConstants.DETAILS);
                        usersRBACAdmin.setUserProperties(user, props);
                    } else if (action.equals(RBACAdminConstants.DELETE_ACTION)) {
                        usersRBACAdmin.deleteUser(user);
                    } else if (action.equals(RBACAdminConstants.ADD_ACTION)) {
                        UserExistsException e = new UserExistsException("User: " + user + " already exists");
                        LOG.error("User: " + user + " already exists");
                        throw new Fault(e, getUserExistsExceptionResponse(e));
                    }
                }
                LOG.debug("Executed synchronized block");
            }
        } catch (RBACException e) {
            LOG.error("Error occured while modifying user for user: " + user + " action " + action + " realm: " + realm, e);
            throw new Fault(e, getRBACExceptionResponse(e));
        } catch (RemoteException e) {
            LOG.error("Error occured while modifying user for user: " + user + " action " + action + " realm: " + realm, e);
            throw new Fault(e, getRemoteExceptionResponse(e));
        }
        return getResponseElement(RBACAdminConstants.SUCCESS);
    }

    /**This method performs either add, delete or edit action for role
     * @param requestEl
     * @return
     */
    public OMElement modifyRole(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String realm = request.getRequiredString(RBACAdminConstants.REALM);
        String role = request.getRequiredString(RBACAdminConstants.ROLE);
        String action = request.getRequiredString(RBACAdminConstants.ACTION);
        LOG.debug("Realm: " + realm + " Role: " + role + " Action " + action);
        try {
            RBACProvider usersRBACProvider = _securityProvider.getRBACProvider(realm);
            RBACAdmin usersRBACAdmin = usersRBACProvider.getAdmin();
            synchronized (this) {
                LOG.debug("Executing synchronized block");
                if (!checkRoleExists(role, usersRBACProvider)) {
                    if (action.equals(RBACAdminConstants.ADD_ACTION)) {
                        synchronized (this) {
                            usersRBACAdmin.addRole(role, request.getProperties(RBACAdminConstants.DETAILS));
                        }
                    } else if (action.equals(RBACAdminConstants.EDIT_ACTION)
                            || action.equals(RBACAdminConstants.DELETE_ACTION)) {
                        RoleNotFoundException e = new RoleNotFoundException("Role: " + role + " was not found.");
                        LOG.error("Role: " + role + " was not found.");
                        throw new Fault(e, getRoleNotFoundExceptionResponse(e));
                    }
                } else {
                    if (action.equals(RBACAdminConstants.EDIT_ACTION)) {
                        synchronized (this) {
                            usersRBACAdmin.setRoleProperties(role, request.getProperties(RBACAdminConstants.DETAILS));
                        }
                    } else if (action.equals(RBACAdminConstants.DELETE_ACTION)) {
                        if (!checkRoleAssigned(role, usersRBACProvider)) {
                            usersRBACAdmin.deleteRole(role);
                        } else {
                            RoleExistsException e = new RoleExistsException(
                                    "Cannot delete role : " + role
                                            + " is assigned to some user");
                            LOG.error("Cannot delete role : " + role
                                    + " is assigned to some user");
                            throw new Fault(e,
                                    getRoleExistsExceptionResponse(e));
                        }
                    } else if (action.equals(RBACAdminConstants.ADD_ACTION)) {
                        RoleExistsException e = new RoleExistsException("Role: " + role + " already exists");
                        LOG.error("Role: " + role + " already exists");
                        throw new Fault(e, getRoleExistsExceptionResponse(e));
                    }
                }
                LOG.debug("Executed synchronized block");
            }
        } catch (RBACException e) {
            LOG.error("Error occured while modifying role for role: " + role + " action " + action + " realm: " + realm, e);
            throw new Fault(e, getRBACExceptionResponse(e));
        } catch (RemoteException e) {
            LOG.error("Error occured while modifying role for role: " + role + " action " + action + " realm: " + realm, e);
            throw new Fault(e, getRemoteExceptionResponse(e));
        }
        return getResponseElement(RBACAdminConstants.SUCCESS);
    }

    /**This gets existing realms in security provider
     * @param requestEl
     * @return
     * @throws AxisFault
     */
    public OMElement getRealms(OMElement requestEl) throws AxisFault {
        String[] realms;
        try {
            realms = _securityProvider.getRealms();
        } catch (AuthenticationException e) {
            LOG.error("Error occured while gettings realms", e);
            throw new Fault(e, getAuthenticationExceptionResponse(e));
        } catch (RBACException e) {
            LOG.error("Error occured while gettings realms", e);
            throw new Fault(e, getRBACExceptionResponse(e));
        }
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.REALMS);
        if (realms != null) {
            for (String realm : realms) {
                if (!realm.equals("")) {
                    OMElement responseToken = OM_FACTORY.createOMElement(RBACAdminConstants.REALM, response);
                    responseToken.setText(realm);
                }
            }
        }
        return response;
    }

    /**This gets the existing roles
     * @param requestEl
     * @return
     * @throws AxisFault
     */
    public OMElement getRoles(OMElement requestEl) throws AxisFault {
        String[] roles = null;
        RBACQuery query;
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.ROLES);
        try {
            for (String realm : _securityProvider.getRealms()) {
                query = _securityProvider.getRBACProvider(realm).getQuery();
                if (realm != null && !realm.equals("")) {
                    roles = query.getRoles(realm);
                    if (roles != null) {
                        for (String role : roles) {
                            OMElement responseToken = OM_FACTORY
                                    .createOMElement(RBACAdminConstants.ROLE_TYPE, response);
                            responseToken.addChild(elementText(RBACAdminConstants.ID, role));
                            responseToken.addChild(elementText(RBACAdminConstants.REALMS, realm));
                            OMElement details = OM_FACTORY.createOMElement(RBACAdminConstants.DETAILS, responseToken);
                            for (Property prop : query.roleProperties(role)) {
                                details.addChild(elementProperty(prop.getName(), prop.getValue().toString()));
                            }
                            response.addChild(responseToken);
                        }
                    }
                }
            }
        } catch (RBACException e) {
            LOG.error("Error occured while gettings roles", e);
            throw new Fault(e, getRBACExceptionResponse(e));
        } catch (RemoteException e) {
            LOG.error("Error occured while gettings roles", e);
            throw new Fault(e, getRemoteExceptionResponse(e));
        } catch (AuthenticationException e) {
            LOG.error("Error occured while gettings roles", e);
            throw new Fault(e, getAuthenticationExceptionResponse(e));
        }
        return response;
    }

    /**This gets the existing roles
     * @param requestEl
     * @return
     * @throws AxisFault
     */
    public OMElement getUsers(OMElement requestEl) throws AxisFault {
        RBACQuery query;
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.USERS);
        try {
            for (String realm : _securityProvider.getRealms()) {
                query = _securityProvider.getRBACProvider(realm).getQuery();
                if (realm != null && !realm.equals("")) {
                    Set<String> userSet = new HashSet<String>();
                    String[] users = query.getUsers(realm);
                    for (String user : users) {
                        userSet.add(user);
                    }
                    if (users != null) {
                        for (String user : userSet) {
                            OMElement responseToken = OM_FACTORY
                                    .createOMElement(RBACAdminConstants.USER_TYPE, response);
                            responseToken.addChild(elementText(RBACAdminConstants.ID, user));
                            responseToken.addChild(elementText(RBACAdminConstants.REALMS, realm));
                            OMElement details = OM_FACTORY.createOMElement(RBACAdminConstants.DETAILS, responseToken);
                            for (Property prop : query.userProperties(user)) {
                                details.addChild(elementProperty(prop.getName(), prop.getValue().toString()));
                            }
                            response.addChild(responseToken);
                        }
                    }
                }
            }
        } catch (RBACException e) {
            LOG.error("Error occured while gettings users", e);
            throw new Fault(e, getRBACExceptionResponse(e));
        } catch (RemoteException e) {
            LOG.error("Error occured while gettings users", e);
            throw new Fault(e, getRemoteExceptionResponse(e));
        } catch (AuthenticationException e) {
            LOG.error("Error occured while gettings users", e);
            throw new Fault(e, getAuthenticationExceptionResponse(e));
        }
        return response;
    }

    /**This returns list of attributes depending on request, which either can be role or user.
     * @param requestEl
     * @return
     * @throws AxisFault
     */
    public OMElement getAttributes(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String element = request.getRequiredString(RBACAdminConstants.TOKEN);
        Set<String> attributes = null;
        LOG.debug("Getting Attributes for " + element);
        try {
            attributes = _securityProvider.getAttributes(element);
        } catch (RBACException e) {
            LOG.error("Error occured while gettings attributes for " + element, e);
            throw new Fault(e, getRBACExceptionResponse(e));
        } catch (Exception e) {
            LOG.error("Error occured while gettings attributes for " + element, e);
        }
        LOG.debug("Got set Attributes of sze " + attributes.size());
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.ATTRIBUTES);
        if (attributes != null) {
            for (String attri : attributes) {
                response.addChild(elementText(RBACAdminConstants.ATTRIBUTE, attri));
            }
        }
        return response;
    }

    /**This returns list of properties depending on request, which either can be role or user.
     * @param requestEl
     * @return
     * @throws AxisFault
     */
    public OMElement getProperties(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String user = request.getRequiredString(RBACAdminConstants.USER);
        String role = request.getRequiredString(RBACAdminConstants.ROLE);
        String realm = request.getRequiredString(RBACAdminConstants.REALM);
        Property[] properties = null;
        try {
            if (user != null && !user.equals("null")) {
                properties = _securityProvider.getRBACProvider(realm).getQuery().userProperties(user);
            } else if (role != null && !role.equals("null")) {
                properties = _securityProvider.getRBACProvider(realm).getQuery().roleProperties(role);
            }
        } catch (RBACException e) {
            LOG.error("Error occured while gettings properties for user: " + user + " role " + role + " realm: "
                    + realm, e);
            throw new Fault(e, getRBACExceptionResponse(e));
        } catch (RemoteException e) {
            LOG.error("Error occured while gettings properties for user: " + user + " role " + role + " realm: "
                    + realm, e);
            throw new Fault(e, getRemoteExceptionResponse(e));
        }
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.GET_PROPERTIES);
        OMElement responseToken = OM_FACTORY.createOMElement(RBACAdminConstants.DETAILS, response);
        for (Property prop : properties) {
            responseToken.addChild(elementProperty(prop.getName(), prop.getValue().toString()));
        }
        return response;
    }

    private static OMElement getResponseElement(String token) {
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.RESPONSE);
        OMElement responseToken = OM_FACTORY.createOMElement(RBACAdminConstants.TOKEN, response);
        responseToken.setText(token);
        return response;
    }

    private static OMElement getRBACExceptionResponse(RBACException e) {
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.RBAC_EXCEPTION);
        response.setText(e.getMessage());
        return response;
    }

    private static OMElement getAuthenticationExceptionResponse(AuthenticationException e) {
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.AUTHENTICATION_EXCEPTION);
        response.setText(e.getMessage());
        return response;
    }

    private static OMElement getRemoteExceptionResponse(RemoteException e) {
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.REMOTE_EXCEPTION);
        response.setText(e.getMessage());
        return response;
    }

    private static OMElement getUserExistsExceptionResponse(UserExistsException e) {
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.USER_EXISTS_EXCEPTION);
        response.setText(e.getMessage());
        return response;
    }

    private static OMElement getUserNotFoundExceptionResponse(UserNotFoundException e) {
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.USER_NOT_FOUND_EXCEPTION);
        response.setText(e.getMessage());
        return response;
    }

    private static OMElement getRoleNotFoundExceptionResponse(RoleNotFoundException e) {
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.ROLE_NOT_FOUND_EXCEPTION);
        response.setText(e.getMessage());
        return response;
    }

    private static OMElement getRoleExistsExceptionResponse(RoleExistsException e) {
        OMElement response = OM_FACTORY.createOMElement(RBACAdminConstants.ROLE_EXISTS_EXCEPTION);
        response.setText(e.getMessage());
        return response;
    }

    private static boolean checkUserExists(String user, RBACProvider usersRBACProvider) throws RemoteException, RBACException {
        boolean exists = true;
        try {
            Property[] props = usersRBACProvider.getQuery().userProperties(user);
            if (props == null || props.length == 0) {
                exists = false;
            }
        } catch (UserNotFoundException e) {
            exists = false;
        }
        return exists;
    }

    private static boolean checkRoleExists(String role, RBACProvider usersRBACProvider) throws RemoteException, RBACException {
        boolean exists = true;
        try {
            Property[] props = usersRBACProvider.getQuery().roleProperties(role);
            if (props == null || props.length == 0) {
                exists = false;
            }
        } catch (RoleNotFoundException e) {
            exists = false;
        }
        return exists;
    }

    private static boolean checkRoleAssigned(String role,
            RBACProvider usersRBACProvider) {
        boolean assigned = true;
        try {
            if (_securityProvider instanceof SimpleSecurityProvider) {
                String[] roles = usersRBACProvider.getQuery().assignedUsers(
                        role);
                if (roles == null || roles.length == 0) {
                    assigned = false;
                }
            }
        } catch (Exception e) {
            assigned = false;
        }
        return assigned;
    }
    private static OMElement elementProperty(String name, String Value) {
        OMElement prop = element(RBACAdminConstants.PROPERTY);
        prop.addChild(elementText(RBACAdminConstants.NAME, name));
        prop.addChild(elementText(RBACAdminConstants.VALUE, Value));
        return prop;
    }

    private static OMElement element(QName name) {
        return OM_FACTORY.createOMElement(name);
    }

    private static OMElement elementText(QName name, String text) {
        OMElement element = OM_FACTORY.createOMElement(name);
        element.setText(text);
        return element;
    }

}
