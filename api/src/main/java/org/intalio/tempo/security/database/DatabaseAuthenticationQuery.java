package org.intalio.tempo.security.database;

import java.rmi.RemoteException;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.authentication.AuthenticationQuery;
import org.intalio.tempo.security.database.dao.DAO;
import org.intalio.tempo.security.database.model.Role;
import org.intalio.tempo.security.database.model.RoleHierarchy;
import org.intalio.tempo.security.database.util.DatabaseHelperUtil;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.util.IdentifierUtils;
import org.intalio.tempo.security.authentication.UserNotFoundException;

public class DatabaseAuthenticationQuery implements AuthenticationQuery {

    private static Logger log = Logger
            .getLogger(DatabaseAuthenticationQuery.class);

    private String _realm;
    private DatabaseSecurityProvider _provider;
    private DAO _dao;

    /**
     * @param realmName
     * @param provider
     * @param dao
     */
    public DatabaseAuthenticationQuery(String realmName,
            DatabaseSecurityProvider provider, DAO dao) {
        _realm = realmName;
        _provider = provider;
        _dao = dao;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.intalio.tempo.security.authentication.AuthenticationQuery#
     * getUserCredentials(java.lang.String)
     */
    public Property[] getUserCredentials(String username)
            throws AuthenticationException, RemoteException {
        Property[] properties = null;
        try {
            _dao.getSession();
            properties = _dao.getUserCredentials(
                    IdentifierUtils.stripRealm(username), _realm);
        } catch (UserNotFoundException ue) {
            log.error("User not found: " + username, ue);
            throw new UserNotFoundException("User not found: " + username);
        } catch (Exception e) {
            log.error("Error occurred while fetching user credential of user "
                    + username, e);
            throw new AuthenticationException(
                    "Error occurred while fetching user credential of user "
                            + username, e);
        } finally {
            try {
                DAO.closeSession();
            } catch (Exception ex) {
                log.error("Error while closing session", ex);
            }
        }
        return properties;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.authentication.AuthenticationQuery#isWorkflowAdmin
     * (java.lang.String)
     */
    @Override
    public boolean isWorkflowAdmin(String userName)
            throws AuthenticationException, RemoteException, RBACException {
        Set<Role> userRoles = null;
        boolean isAdmin = false;
        Set<String> authorizedRoles = null;
        String[] authorizedRoleNames = null;
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
            authorizedRoleNames = authorizedRoles
                    .toArray(new String[authorizedRoles.size()]);
            Set<String> workflowAdminRoles = _dao
                    .getWorkflowAdminRoles(_provider.getWorkflowAdminRoles());
            Set<String> workflowAdminUsers = _dao
                    .getWorkflowAdminUsers(_provider.getWorkflowAdminUsers());
            for (int i = 0; i < authorizedRoleNames.length
                    && workflowAdminRoles != null; i++) {
                isAdmin = workflowAdminRoles.contains(authorizedRoleNames[i]);
                if (isAdmin)
                    break;
            }
            if (workflowAdminUsers != null)
                return (isAdmin || workflowAdminUsers.contains(userName));
        } catch (Exception e) {
            log.error("Error occurred while validating workflow admin of user "
                    + userName, e);
            throw new AuthenticationException(
                    "Error occurred while validating workflow admin of user "
                            + userName, e);
        } finally {
            try {
                DAO.closeSession();
            } catch (Exception e) {
                log.error("Error while closing session", e);
            }
        }
        return isAdmin;
    }
}
