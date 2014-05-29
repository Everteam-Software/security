package org.intalio.tempo.security.database;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.authentication.provider.AuthenticationProvider;
import org.intalio.tempo.security.database.dao.DAO;
import org.intalio.tempo.security.database.model.Realm;
import org.intalio.tempo.security.database.util.DatabaseHelperUtil;
import org.intalio.tempo.security.provider.SecurityProvider;
import org.intalio.tempo.security.rbac.RBACConstants;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.provider.RBACProvider;

public class DatabaseSecurityProvider implements SecurityProvider {

    private static Logger log = Logger
            .getLogger(DatabaseSecurityProvider.class);

    private String _filename;
    private String _name = "database";
    private String _defaultrealm = "";
    private Set<String> _workflowAdminUsers;
    private Set<String> _workflowAdminRoles;
    private DAO _dao;

    /**
     * RBAC providers: Map of { String, RBACProvider }.
     */
    private HashMap<String, RBACProvider> _rbacMap;

    /**
     * Authentication providers: Map of { String, AuthenticationProvider }.
     */
    private HashMap<String, AuthenticationProvider> _authMap;

    public DAO getDao() {
        return _dao;
    }

    public void setDao(DAO dao) {
        this._dao = dao;
    }

    public Set<String> getWorkflowAdminUsers() {
        return _workflowAdminUsers;
    }

    public void setWorkflowAdminUsers(Set<String> workflowAdminUsers) {
        this._workflowAdminUsers = workflowAdminUsers;
    }

    public Set<String> getWorkflowAdminRoles() {
        return _workflowAdminRoles;
    }

    public void setWorkflowAdminRoles(Set<String> workflowAdminRoles) {
        this._workflowAdminRoles = workflowAdminRoles;
    }

    public void init() throws AuthenticationException, RBACException {
        checkFilename();

        initializehibernate();
    }

    public void initialize(Object config) throws AuthenticationException,
            RBACException {
        checkFilename();
        initializehibernate();
    }

    public void setPropertiesfile(String filename) {
        _filename = filename;
    }

    public void setDefaultrealm(String defaultrealm) {
        _defaultrealm = defaultrealm;
        DatabaseHelperUtil.setdefaultrealm(defaultrealm);
    }

    private void initializehibernate() {

        List<Realm> allrealms;
        try {
            _dao.getSession();
            allrealms = _dao.getRealms();
            _rbacMap = new HashMap<String, RBACProvider>();
            _authMap = new HashMap<String, AuthenticationProvider>();
            for (Realm r : allrealms) {
                _rbacMap.put(r.getIdentifier(),
                        new DatabaseRBACProvider(r.getIdentifier(), _dao));
                _authMap.put(r.getIdentifier(),
                        new DatabaseAuthenticationProvider(r.getIdentifier(),
                                DatabaseSecurityProvider.this, _dao));
            }

            // bind default realm
            _rbacMap.put("", new DatabaseRBACProvider(_defaultrealm, _dao));
            _authMap.put("", new DatabaseAuthenticationProvider(_defaultrealm,
                    DatabaseSecurityProvider.this, _dao));
        } catch (Exception e) {
            log.error("Error while fetching realms", e);
        } finally {
            try {
                DAO.closeSession();
            } catch (Exception ex) {
                log.error("Error occurred while closing session", ex);
            }
        }
    }

    private void checkFilename() {
        if (_filename == null) {
            throw new IllegalStateException(
                    "Missing configuration property 'configFile'");
        }
    }

    public String getName() {
        return _name;
    }

    public void setName(String name) {
        _name = name;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.provider.SecurityProvider#getRealms()
     */
    public String[] getRealms() throws AuthenticationException, RBACException {
        return _authMap.keySet().toArray(new String[_authMap.size()]);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.provider.SecurityProvider#getRBACProvider(
     * java.lang.String)
     */
    public RBACProvider getRBACProvider(String realm) throws RBACException {
        if (!_rbacMap.containsKey(realm))
            throw new RBACException("Realm, " + realm
                    + ", is not supported by this Security Provider!");
        return (RBACProvider) _rbacMap.get(realm);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.provider.SecurityProvider#
     * getAuthenticationProvider(java.lang.String)
     */
    public AuthenticationProvider getAuthenticationProvider(String realm)
            throws AuthenticationException {
        return (AuthenticationProvider) _authMap.get(realm);
    }

    public void dispose() throws RBACException {
        _rbacMap = null;
        _authMap = null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.provider.SecurityProvider#getAttributes(java
     * .lang.String)
     */
    @Override
    public Set<String> getAttributes(String forObject) throws RBACException {
        Set<String> properties = new LinkedHashSet<String>();
        if (forObject.equalsIgnoreCase("user")) {
            properties.add(RBACConstants.PROPERTY_DISPLAY_NAME);
            properties.add(RBACConstants.PROPERTY_EMAIL);
            properties.add(RBACConstants.PROPERTY_PASSWORD);
            properties.add(RBACConstants.PROPERTY_ASSIGN_ROLES);
            properties.add(RBACConstants.PROPERTY_FIRST_NAME);
            properties.add(RBACConstants.PROPERTY_LAST_NAME);
        } else if (forObject.equalsIgnoreCase("role")) {
            properties.add(RBACConstants.PROPERTY_DESCRIPTION);
            properties.add(RBACConstants.PROPERTY_DESCENDANT_ROLE);
        }
        return properties;
    }
}
