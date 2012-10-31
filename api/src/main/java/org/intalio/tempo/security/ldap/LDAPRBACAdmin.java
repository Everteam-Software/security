package org.intalio.tempo.security.ldap;

import java.rmi.RemoteException;
import java.util.Map;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;

import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.rbac.RBACAdmin;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.RoleNotFoundException;
import org.intalio.tempo.security.rbac.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LDAPRBACAdmin implements RBACAdmin {

    protected final static Logger LOG = LoggerFactory.getLogger(LDAPRBACAdmin.class);

    private String _baseDN;
    private LDAPSecurityProvider _provider;
    private Map _config;

    public LDAPRBACAdmin(LDAPSecurityProvider provider, String baseDN, Map map) {
        _provider = provider;
        _baseDN = baseDN;
        _config = map;
    }

    @Override
    public void addUser(String user, Property[] properties) throws RBACException, RemoteException {
        Attributes attr = getAttributes(properties);
        attr.put(LDAPProperties.SECURITY_LDAP_USER_ID, user);
        String dn = getUserId(user);
        createSubContext(dn, attr);

    }

    @Override
    public void deleteUser(String user) throws RBACException, RemoteException {
        String dn = getUserId(user);
        removeSubContext(dn);
    }

    @Override
    public void addRole(String role, Property[] properties) throws RoleNotFoundException, RBACException, RemoteException {
        Attributes attr = getAttributes(properties);
        attr.put(LDAPProperties.SECURITY_LDAP_ROLE_ID, role);
        String dn = getRoleId(role);
        createSubContext(dn, attr);
    }

    @Override
    public void deleteRole(String role) throws RoleNotFoundException, RBACException, RemoteException {
        String dn = getRoleId(role);
        removeSubContext(dn);
    }

    @Override
    public void assignUser(String user, String role) throws UserNotFoundException, RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void deassignUser(String user, String role) throws UserNotFoundException, RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void grantPermission(String role, String operation, String object) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void revokePermission(String role, String operation, String object) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void addInheritance(String ascendant, String descendant) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void deleteInheritance(String ascendant, String descendant) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void addAscendant(String ascendant, Property[] properties, String descendant) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void addDescendant(String descendant, Property[] properties, String ascendant) throws RoleNotFoundException, RBACException, RemoteException {
        // TODO Auto-generated method stub

    }

    @Override
    public void setUserProperties(String user, Property[] properties) throws UserNotFoundException, RBACException, RemoteException {
        String dn = getUserId(user);
        modifyAttributes(dn, properties);

    }

    @Override
    public void setRoleProperties(String role, Property[] properties) throws RoleNotFoundException, RBACException, RemoteException {
        String dn = getRoleId(role);
        modifyAttributes(dn, properties);

    }

    static private Attributes getAttributes(Property[] properties) {
        BasicAttributes myAttri = new BasicAttributes(true);
        for (Property prop : properties)
            myAttri.put(prop.getName(), prop.getValue());
        return myAttri;
    }

    private String getUserId(String user) {
        String userBase = (String) _config.get(LDAPProperties.SECURITY_LDAP_USER_BASE);
        String userId = (String) _config.get(LDAPProperties.SECURITY_LDAP_USER_ID);
        String dn = userId + "=" + user + "," + userBase;
        return dn;
    }

    private String getRoleId(String role) {
        String roleBase = (String) _config.get(LDAPProperties.SECURITY_LDAP_ROLE_BASE);
        String roleId = (String) _config.get(LDAPProperties.SECURITY_LDAP_ROLE_ID);
        String dn = roleId + "=" + role + "," + roleBase;
        return dn;
    }

    private void createSubContext(String dn, Attributes attr) throws RBACException {
        try {
            DirContext context = _provider.getContext(_baseDN);
            context.createSubcontext(dn, attr);
            context.close();
        } catch (NamingException e) {
            LOG.error("Error occured while creating new subContext in LDAP", e);
            throw new RBACException(e);
        }
    }

    private void removeSubContext(String dn) throws RBACException {
        try {
            DirContext context = _provider.getContext(_baseDN);
            context.destroySubcontext(dn);
            context.close();
        } catch (NamingException e) {
            LOG.error("Error occured while removing subContext from LDAP", e);
            throw new RBACException(e);
        }
    }

    private void modifyAttributes(String dn, Property[] props) throws RBACException {
        try {
            DirContext context = _provider.getContext(_baseDN);
            ModificationItem[] mods = new ModificationItem[props.length];
            int i = 0;
            for (Property prop : props) {
                Attribute attri = new BasicAttribute(prop.getName(), prop.getValue());
                mods[i++] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, attri);
            }
            context.modifyAttributes(dn, mods);
        } catch (Exception e) {
            LOG.error("Error occured while modifying attributes for context", e);
            throw new RBACException(e);
        }
    }
}
