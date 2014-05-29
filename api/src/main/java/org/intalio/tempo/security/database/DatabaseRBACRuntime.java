package org.intalio.tempo.security.database;

import java.rmi.RemoteException;

import org.apache.log4j.Logger;
import org.intalio.tempo.security.database.dao.DAO;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.rbac.RBACRuntime;

public class DatabaseRBACRuntime implements RBACRuntime {

    private static Logger log = Logger.getLogger(DatabaseRBACRuntime.class);

    private String _realm;
    private DAO _dao;

    /**
     * @param realmName
     * @param dao
     */
    public DatabaseRBACRuntime(String realmName, DAO dao) {
        _realm = realmName;
        _dao = dao;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.rbac.RBACRuntime#checkAccess(java.lang.String,
     * java.lang.String[], java.lang.String, java.lang.String)
     */
    public boolean checkAccess(String userName, String[] roles,
            String operation, String object) throws RBACException,
            RemoteException {
        boolean access = false;
        // TODO
        return access;
    }
}
