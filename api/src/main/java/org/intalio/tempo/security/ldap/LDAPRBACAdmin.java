package org.intalio.tempo.security.ldap;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

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
    private String _realm;
    private LDAPSecurityProvider _provider;
    private Map<String, String> _env;
    private HashMap<String, String> _keyValue;

    public LDAPRBACAdmin(LDAPSecurityProvider provider, String baseDN, Map<String, String> map, String realm) {
        _realm = realm;
        _provider = provider;
        _baseDN = baseDN;
        _env = map;
        _keyValue = new HashMap<String, String>();
        getLdapKeys(_keyValue, "user");
        getLdapKeys(_keyValue, "role");

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
        Property[] oldProps = _provider.getRBACProvider(_realm).getQuery().userProperties(user);
        List<Property> oldOnes = new ArrayList<Property>(Arrays.asList(oldProps));
        List<Property> newOnes = new ArrayList<Property>(Arrays.asList(properties));
        modifyAttributes(dn, oldOnes, newOnes);

    }

    @Override
    public void setRoleProperties(String role, Property[] properties) throws RoleNotFoundException, RBACException, RemoteException {
        String dn = getRoleId(role);
        Property[] oldProps = _provider.getRBACProvider(_realm).getQuery().roleProperties(role);
        List<Property> oldOnes = new ArrayList<Property>(Arrays.asList(oldProps));
        List<Property> newOnes = new ArrayList<Property>(Arrays.asList(properties));
        modifyAttributes( dn, oldOnes, newOnes);

    }

    private Attributes getAttributes(Property[] properties) {
        BasicAttributes myAttri = new BasicAttributes(true);
        for (Property prop : properties) {
            String key = _keyValue.get(prop.getName());
            Attribute attr = myAttri.get(key);
            if (attr == null) {
                myAttri.put(new BasicAttribute(key, prop.getValue()));
            } else {
                attr.add(prop.getValue());
            }
        }
        return myAttri;
    }

    private String getUserId(String user) {
        String userBase = (String) _env.get(LDAPProperties.SECURITY_LDAP_USER_BASE);
        String userId = (String) _env.get(LDAPProperties.SECURITY_LDAP_USER_ID);
        String dn = userId + "=" + user + "," + userBase;
        return dn;
    }

    private String getRoleId(String role) {
        String roleBase = (String) _env.get(LDAPProperties.SECURITY_LDAP_ROLE_BASE);
        String roleId = (String) _env.get(LDAPProperties.SECURITY_LDAP_ROLE_ID);
        String dn = roleId + "=" + role + "," + roleBase;
        return dn;
    }

    private void createSubContext(String dn, Attributes attr) throws RBACException {
        DirContext root = null;
        try {
            root = _provider.getRootContext();
            DirContext context = getContext(root, _baseDN);
            context.createSubcontext(dn, attr);
            context.close();
        } catch (NamingException e) {
            LOG.error("Error occured while creating new subContext in LDAP", e);
            throw new RBACException(e);
        } finally {
            close(root);
        }
    }

    private void removeSubContext(String dn) throws RBACException {
        DirContext root = null;
        try {
            root = _provider.getRootContext();
            DirContext context = getContext(root, _baseDN);
            context.destroySubcontext(dn);
            context.close();
        } catch (NamingException e) {
            LOG.error("Error occured while removing subContext from LDAP", e);
            throw new RBACException(e);
        } finally {
            close(root);
        }
    }

    private void modifyAttributes(String dn, List<Property> oldProps, List<Property> newProps) throws RBACException {
        DirContext root = null;
        try {
            String password = null;
            if (_env.containsKey(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".0")) {
                password =_env.get(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".0").split(":")[0];
            } else if (_env.containsKey(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".1")) {
                password =_env.get(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".1").split(":")[0];
            }
            root = _provider.getRootContext();
            DirContext context = getContext(root, _baseDN);
            ArrayList<ModificationItem> mods = new ArrayList<ModificationItem>();
            HashMap<String, Attribute> attris = new HashMap<String, Attribute>();
            Iterator<Property> iter = newProps.iterator();
            while(iter.hasNext()){
                Property nProp = iter.next();
                String name = _keyValue.get(nProp.getName());
                LOG.debug("Iterating new property name: " +name+" value: "+nProp.getValue());

                if (name.equalsIgnoreCase("objectclass")) {
                    if(oldProps.contains(nProp)) {
                        oldProps.remove(nProp);
                    }
                    iter.remove();
                } else if (name.equalsIgnoreCase(password)) {
                    Attribute attri = new BasicAttribute(name, nProp.getValue());
                    mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, attri));
                    iter.remove();
                } else {
                    if(oldProps.contains(nProp)) {
                        oldProps.remove(nProp);
                        iter.remove();
                        continue;
                    } else {
                        boolean found = false;
                        int whatToDo = 0;
                        Iterator<Property> oIter = oldProps.iterator();
                        while(oIter.hasNext()){
                            Property oProp = oIter.next();
                            LOG.debug("new property: " +nProp.toString());
                            LOG.debug("Old property: " +oProp.toString());

                            if(name.equalsIgnoreCase(_keyValue.get(oProp.getName()))) {
                                LOG.debug("Adding to replace name: " +name);
                                oIter.remove();
                                whatToDo = DirContext.REPLACE_ATTRIBUTE;
                                found = true;
                                break;
                            }
                        }
                        if(!found) {
                            whatToDo = DirContext.ADD_ATTRIBUTE;
                            LOG.debug("Adding to add name: " +name);
                        }
                        if(attris.containsKey(name)) {
                            Attribute attri = attris.get(name);
                            attri.add(nProp.getValue());
                            LOG.debug("Adding to existing attribute: " +name);
                        } else {
                            Attribute attri = new BasicAttribute(name, nProp.getValue());
                            mods.add(new ModificationItem(whatToDo, attri));
                            attris.put(name, attri);
                        }
                        iter.remove();
                    }
                }
            }
            for (Property oProp : oldProps) {
                String name = oProp.getName();
                if(!name.equalsIgnoreCase("objectclass")) {
                    Attribute attri = new BasicAttribute(name);
                    mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, attri));
                    LOG.debug("Adding to remove name: " +name);
                }
            }
            context.modifyAttributes(dn, mods.toArray(new ModificationItem[mods.size()]));
        } catch (Exception e) {
            LOG.error("Error occured while modifying attributes for context", e);
            throw new RBACException(e);
        } finally {
            close(root);
        }
    }

    public void getLdapKeys(HashMap<String, String> map, String forObject) {
        String propertyName = "";
        if (forObject.equals("user")) {
            propertyName = LDAPProperties.SECURITY_LDAP_USER_PROP;
            if (_env.containsKey(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".0")) {
                map.put(_env.get(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".0").split(":")[0], _env
                        .get(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".0").split(":")[0]);
            } else if (_env.containsKey(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".1")) {
                map.put(_env.get(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".1").split(":")[0], _env
                        .get(LDAPProperties.SECURITY_LDAP_USER_CREDENTIAL + ".1").split(":")[0]);
            }
        } else if (forObject.equals("role")) {
            propertyName = LDAPProperties.SECURITY_LDAP_ROLE_PROP;
        }
        for (int i = 0; true; i++) {
            String key = propertyName + '.' + i;
            if (_env.containsKey(key)) {
                String value = (String) _env.get(key);
                String[] temp = value.split(":");
                if (temp != null && temp.length > 0) {
                    if (temp.length == 1) {
                        map.put(value.split(":")[0], value.split(":")[0]);
                    } else {
                        map.put(value.split(":")[1], value.split(":")[0]);
                    }
                }
            } else {
                break;
            }
        }
    }

    private synchronized DirContext getContext(DirContext root, String branch) throws NamingException {
        try {
            return (DirContext) root.lookup(branch);
        } catch (NamingException ne) {
            throw ne;
        } finally {
            close(root);
        }
    }

    static final void close(Context context) {
        if (context != null) {
            try {
                context.close();
            } catch (Exception except) {
                // ignore
            }
        }
    }
}
