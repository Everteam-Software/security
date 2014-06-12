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

import org.apache.log4j.Logger;
import org.hibernate.Session;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationConstants;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.authentication.AuthenticationRuntime;
import org.intalio.tempo.security.authentication.UserNotFoundException;
import org.intalio.tempo.security.database.dao.DAO;
import org.intalio.tempo.security.database.util.DatabaseHelperUtil;
import org.intalio.tempo.security.util.IdentifierUtils;
import org.intalio.tempo.security.util.PropertyUtils;
import org.jasypt.util.text.BasicTextEncryptor;

public class DatabaseAuthenticationRunTime implements AuthenticationRuntime {

    private static Logger log = Logger
            .getLogger(DatabaseAuthenticationRunTime.class);
    private String _realm;
    private DAO _dao;

    /**
     * @param realm
     * @param dao
     */
    public DatabaseAuthenticationRunTime(String realm, DAO dao) {
        _realm = realm;
        _dao = dao;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.intalio.tempo.security.authentication.AuthenticationRuntime#authenticate
     * (java.lang.String, org.intalio.tempo.security.Property[])
     */
    public boolean authenticate(String userName, Property[] credentials)
            throws UserNotFoundException, AuthenticationException,
            RemoteException {
        Property password = null;
        Property autheticatepassword = null;
        String decryptedPassword = "";
        Session session = null;
        try {
            session = _dao.getSession();
            autheticatepassword = PropertyUtils.getProperty(
                    _dao.getUserCredentials(
                            IdentifierUtils.stripRealm(userName), _realm, session),
                    AuthenticationConstants.PROPERTY_PASSWORD);
            BasicTextEncryptor encryptor = new BasicTextEncryptor();
            // setPassword uses hash to decrypt password which should be same as
            // hash of encryptor
            encryptor.setPassword(DatabaseHelperUtil.ENCRYPTED_PASSWORD);
            decryptedPassword = encryptor.decrypt((String) autheticatepassword
                    .getValue());
        } catch (org.intalio.tempo.security.rbac.UserNotFoundException re) {
            log.error("User not found " + userName, re);
            throw new UserNotFoundException("User not found " + userName);
        } catch (Exception e) {
            log.error("Error occured while authentication", e);
        } finally {
            try {
                _dao.closeSession(session);
            } catch (Exception ex) {
                log.error("Error while closing session", ex);
            }
        }
        password = PropertyUtils.getProperty(credentials,
                AuthenticationConstants.PROPERTY_PASSWORD);
        if (password == null) {
            return false;
        }
        return decryptedPassword.equals(password.getValue());
    }
}
