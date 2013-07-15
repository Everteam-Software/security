package org.intalio.tempo.security.ws;

import static org.intalio.tempo.security.ws.Constants.RBACADMIN_NS;

import javax.xml.namespace.QName;

public class RBACAdminConstants {
    public static final String RBAC_ADMIN_PREFIX = "rbacadmin";
    public static final String ADD_ACTION = "add";
    public static final String DELETE_ACTION = "delete";
    public static final String EDIT_ACTION = "edit";
    public static final String SUCCESS = "success";
    public static final QName NAME = new QName(RBACADMIN_NS.getNamespaceURI(), "name", RBAC_ADMIN_PREFIX);

    public static final QName VALUE = new QName(RBACADMIN_NS.getNamespaceURI(), "value", RBAC_ADMIN_PREFIX);


    public static final QName MODIFY_USER = new QName(RBACADMIN_NS.getNamespaceURI(), "modifyUser", RBAC_ADMIN_PREFIX);
    public static final QName MODIFY_ROLE = new QName(RBACADMIN_NS.getNamespaceURI(), "modifyRole", RBAC_ADMIN_PREFIX);
    public static final QName GET_REALMS = new QName(RBACADMIN_NS.getNamespaceURI(), "getRealms", RBAC_ADMIN_PREFIX);
    public static final QName GET_ROLES = new QName(RBACADMIN_NS.getNamespaceURI(), "getRoles", RBAC_ADMIN_PREFIX);
    public static final QName GET_USERS = new QName(RBACADMIN_NS.getNamespaceURI(), "getUsers", RBAC_ADMIN_PREFIX);
    public static final QName GET_ATTRIBUTES = new QName(RBACADMIN_NS.getNamespaceURI(), "getAttributes", RBAC_ADMIN_PREFIX);
    public static final QName GET_PROPERTIES = new QName(RBACADMIN_NS.getNamespaceURI(), "getProperties", RBAC_ADMIN_PREFIX);
    public static final QName GET_PROPERTIES_RESPONSE = new QName(RBACADMIN_NS.getNamespaceURI(), "getPropertiesResponse", RBAC_ADMIN_PREFIX);

    public static final QName ACTION = new QName(RBACADMIN_NS.getNamespaceURI(), "action", RBAC_ADMIN_PREFIX);
    public static final QName REALM = new QName(RBACADMIN_NS.getNamespaceURI(), "realm", RBAC_ADMIN_PREFIX);
    public static final QName REALMS = new QName(RBACADMIN_NS.getNamespaceURI(), "realms", RBAC_ADMIN_PREFIX);
    public static final QName USER = new QName(RBACADMIN_NS.getNamespaceURI(), "user", RBAC_ADMIN_PREFIX);
    public static final QName ROLE = new QName(RBACADMIN_NS.getNamespaceURI(), "role", RBAC_ADMIN_PREFIX);
    public static final QName ROLES = new QName(RBACADMIN_NS.getNamespaceURI(), "roles", RBAC_ADMIN_PREFIX);
    public static final QName USERS = new QName(RBACADMIN_NS.getNamespaceURI(), "users", RBAC_ADMIN_PREFIX);
    public static final QName PROPERTY = new QName(RBACADMIN_NS.getNamespaceURI(), "property", RBAC_ADMIN_PREFIX);
    public static final QName PROPERTIES = new QName(RBACADMIN_NS.getNamespaceURI(), "properties", RBAC_ADMIN_PREFIX);
    public static final QName DETAILS = new QName(RBACADMIN_NS.getNamespaceURI(), "details", RBAC_ADMIN_PREFIX);
    public static final QName RESPONSE = new QName(RBACADMIN_NS.getNamespaceURI(), "response", RBAC_ADMIN_PREFIX);
    public static final QName TOKEN = new QName(RBACADMIN_NS.getNamespaceURI(), "token", RBAC_ADMIN_PREFIX);
    public static final QName ATTRIBUTES = new QName(RBACADMIN_NS.getNamespaceURI(), "attributes", RBAC_ADMIN_PREFIX);
    public static final QName ATTRIBUTE = new QName(RBACADMIN_NS.getNamespaceURI(), "attribute", RBAC_ADMIN_PREFIX);
    public static final QName ROLE_TYPE = new QName(RBACADMIN_NS.getNamespaceURI(), "roleType", RBAC_ADMIN_PREFIX);
    public static final QName USER_TYPE = new QName(RBACADMIN_NS.getNamespaceURI(), "userType", RBAC_ADMIN_PREFIX);
    public static final QName ID = new QName(RBACADMIN_NS.getNamespaceURI(), "id", RBAC_ADMIN_PREFIX);
    public static final QName OBJECT = new QName(RBACADMIN_NS.getNamespaceURI(), "object", RBAC_ADMIN_PREFIX);

    public static final QName AUTHENTICATION_EXCEPTION = new QName(RBACADMIN_NS.getNamespaceURI(), "AuthenticationFault", RBAC_ADMIN_PREFIX);
    public static final QName RBAC_EXCEPTION = new QName(RBACADMIN_NS.getNamespaceURI(), "RBACFault", RBAC_ADMIN_PREFIX);
    public static final QName REMOTE_EXCEPTION = new QName(RBACADMIN_NS.getNamespaceURI(), "RemoteFault", RBAC_ADMIN_PREFIX);
    public static final QName USER_EXISTS_EXCEPTION = new QName(RBACADMIN_NS.getNamespaceURI(), "UserExistsFault", RBAC_ADMIN_PREFIX);
    public static final QName ROLE_EXISTS_EXCEPTION = new QName(RBACADMIN_NS.getNamespaceURI(), "RoleExistsFault", RBAC_ADMIN_PREFIX);
    public static final QName USER_NOT_FOUND_EXCEPTION = new QName(RBACADMIN_NS.getNamespaceURI(), "UserNotFoundFault", RBAC_ADMIN_PREFIX);
    public static final QName ROLE_NOT_FOUND_EXCEPTION = new QName(RBACADMIN_NS.getNamespaceURI(), "RoleNotFoundFault", RBAC_ADMIN_PREFIX);
}
