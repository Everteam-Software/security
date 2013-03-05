/**
 * Copyright (C) 2003-2008, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with the
 * written permission of Intalio Inc. or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package org.intalio.tempo.security.impl;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationConstants;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.token.TokenService;
import org.intalio.tempo.security.util.IdentifierUtils;
import org.intalio.tempo.security.util.MD5;
import org.intalio.tempo.security.util.PropertyUtils;
import org.intalio.tempo.security.util.StringArrayUtils;
import org.intalio.tempo.security.util.TimeExpirationMap;
import org.intalio.tempo.security.simple.SimpleSecurityProvider;

import org.jasypt.util.text.BasicTextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdUtils;

import edu.yale.its.tp.cas.client.ProxyTicketValidator;

/**
 * Implementation of TokenIssuer that uses local authentication and RBAC
 * services.
 *
 * @author <a href="http://www.intalio.com">&copy; Intalio Inc.</a>
 */
public class TokenServiceImpl implements TokenService {
    Logger _logger = LoggerFactory.getLogger(TokenServiceImpl.class);

    Realms _realms;
    TokenHandler _tokenHandler;

    String _validateURL;

    // should we try to put the password in the token itself
    boolean _passwordAsAProperty;

    // if true, roles are not encoded in token and cached in memory instead
    boolean _cacheRoles = false;

    // cache token properties
    boolean _cacheProperties = false;

    // check every minute, expire after one hour
    TimeExpirationMap _userAndRoles = new TimeExpirationMap(1000 * 60 * 30, 1000 * 60);
    TimeExpirationMap _tokenAndProperties = new TimeExpirationMap(1000 * 60 * 30, 1000 * 60);

    public TokenServiceImpl() {
        // nothing
    }

    /**
     * Default no-arg constructor for Java Connector.
     */
    public TokenServiceImpl(Realms realms) {
        _realms = realms;
        _tokenHandler = new TokenHandler();
    }

    public TokenServiceImpl(Realms realms, String validateURL) {
        _realms = realms;
        _tokenHandler = new TokenHandler();
        _validateURL = validateURL;
    }

    public final boolean isCacheRoles() {
        return _cacheRoles;
    }

    public final void setCacheRoles(boolean cacheRoles) {
        _cacheRoles = cacheRoles;
    }

    public final boolean isCacheProperties() {
        return _cacheProperties;
    }

    public final void setCacheProperties(boolean cacheProperties) {
        _cacheProperties = cacheProperties;
    }

    public void setPasswordAsAProperty(Boolean asAProperty) {
        _passwordAsAProperty = asAProperty;
    }

    public void setRealms(Realms realms) {
        _realms = realms;
    }

    public void setTokenHandler(TokenHandler handler) {
        _tokenHandler = handler;
    }

    /**
     * Internal (non-public) method to create a token without credential
     * verification.
     *
     * @param user
     *            user identifier
     * @return cryptographic token
     * @throws AuthenticationException 
     */
    public String createToken(String user) throws RBACException, RemoteException, AuthenticationException {
        return createToken(user, null);
    }

    public String createToken(String user, String password) throws RBACException, RemoteException, AuthenticationException {
        // TODO we should use _realms to normalize
//        user = IdentifierUtils.normalize(user, _realms.getDefaultRealm(), false, '\\');
	    boolean caseSensitive = true;
	    String realms = (IdentifierUtils.getRealm(user).equals(""))?_realms.getDefaultRealm():IdentifierUtils.getRealm(user);
        caseSensitive = _realms.isCaseSensitive();
	    user = IdentifierUtils.normalize(user, _realms.getDefaultRealm(), caseSensitive, '\\');

        // place session information in token
        Property userProp = new Property(AuthenticationConstants.PROPERTY_USER, user);
        Property issueProp = new Property(AuthenticationConstants.PROPERTY_ISSUED, Long.toString(System.currentTimeMillis()));

        // add all user properties to token properties
        Property[] userProps = _realms.userProperties(user);
        List<Property> props = new ArrayList<Property>();

        props.add(userProp);
        props.add(issueProp);
        props.add(new Property(AuthenticationConstants.PROPERTY_IS_WORKFLOW_ADMIN, Boolean.toString(isWorkflowAdmin(user))));
        if (!_cacheRoles) {
            String roles = StringArrayUtils.toCommaDelimited(_realms.authorizedRoles(user));
            if(!caseSensitive)
                roles = roles.toLowerCase();
            props.add(new Property(AuthenticationConstants.PROPERTY_ROLES, roles));
        }
        if ((password != null && _passwordAsAProperty))
            props.add(new Property(AuthenticationConstants.PROPERTY_PASSWORD, password));
        for (Property p : userProps) props.add(p);
        return _tokenHandler.createToken(props.toArray(new Property[props.size()]));
    }

    /**
     * Authenticate a user and return a cryptographic token containing session
     * information.
     *
     * @param user
     *            user identifier
     * @param password
     *            password
     * @return cryptographic token
     */
    public String authenticateUser(String user, String password) throws AuthenticationException, RBACException, RemoteException {
        Property[] props;
        Property passwordProp;
        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        // setPassword uses hash to decrypt password which should be same as hash of encryptor
		encryptor.setPassword("IntalioEncryptedpassword#123");
        // This is where we need to send the password in decrypted form
		passwordProp = new Property(AuthenticationConstants.PROPERTY_PASSWORD, encryptor.decrypt(password));
        props = new Property[] { passwordProp };

        if (!_realms.authenticate(user, props)) {
            throw new AuthenticationException("Authentication failed: User '" + user + "'");
        }

        return createToken(user, password);
    }

    /**
     * Authenticate a user and return a cryptographic token containing session
     * information.
     *
     * @param user
     *            user identifier
     * @param credentials
     *            set of credentials
     * @return cryptographic token
     */
    public String authenticateUser(String user, Property[] credentials) throws AuthenticationException, RBACException, RemoteException {
        if (!_realms.authenticate(user, credentials)) {
            throw new AuthenticationException("Authentication failed: User '" + user + "'");
        }

        return createToken(user);
    }

    /**
     * Return the properties encoded in the cryptographic token.
     *
     * @param token
     *            token
     * @return properties encoded in token
     */
    public Property[] getTokenProperties(String token) throws AuthenticationException, RemoteException {
        if (token==null) return null;

        String hash = MD5.compute(token);

        if (_cacheProperties) {
            Property[] props = (Property[]) _tokenAndProperties.get(hash);
            if (props!=null) {
                _logger.debug("Retrieving token properties from cache for:"+hash);
                return props;
            }
        }

        Property[] props = _tokenHandler.parseToken(token);
        Map<String, Object> map = PropertyUtils.toMap(props);

        // check for cache roles
        String user = ((Property) map.get(AuthenticationConstants.PROPERTY_USER)).getValue().toString();
        Property rolesForUser = null;
        if (_cacheRoles) {
            rolesForUser = (Property) _userAndRoles.get(user);
            if (rolesForUser == null) {
                try {
                    String roles = StringArrayUtils.toCommaDelimited(_realms.authorizedRoles(user));
                    boolean caseSensitive = _realms.isCaseSensitive();
                    if(!caseSensitive)
                        roles = roles.toLowerCase();
                    rolesForUser = new Property(AuthenticationConstants.PROPERTY_ROLES, roles);
                } catch (RBACException e) {
                    throw new AuthenticationException("Could not get roles for user:"+user);
                }
                _userAndRoles.put(user, rolesForUser);
            }
            map.put(AuthenticationConstants.PROPERTY_ROLES, rolesForUser);
        }

        Property[] propsArray = map.values().toArray(new Property[map.size()]);
        if (_cacheProperties) {
            _logger.debug("Caching token properties to cache for:"+hash);
            _tokenAndProperties.put(hash, propsArray);
        }
        return propsArray;
    }

    public ProxyTicketValidator getProxyTicketValidator() {
        return new ProxyTicketValidator();
    }

    public String getTokenFromTicket(String proxyTicket, String serviceURL) throws AuthenticationException, RBACException, RemoteException {
        ProxyTicketValidator pv = getProxyTicketValidator();
        pv.setCasValidateUrl(_validateURL);
        pv.setService(serviceURL);
        pv.setServiceTicket(proxyTicket);

        try {
            pv.validate();
        } catch (Exception e) {
            throw new AuthenticationException("Authentication failed! Proxy ticket invalid!");
        }

        if (pv.isAuthenticationSuccesful()) {
            String user = pv.getUser();

            if (user == null) {
                throw new AuthenticationException("Authentication failed: Null User");
            }
            return createToken(user);
        } else {
            throw new AuthenticationException("Authentication failed! Proxy ticket authentication failed!");
        }

    }

    public String getTokenFromOpenSSOToken(String tokenId)
        throws AuthenticationException, RBACException, RemoteException {
        try {
            SSOTokenManager tokenManager = SSOTokenManager.getInstance();
            SSOToken token = tokenManager.createSSOToken(
                            tokenId);
            if (token == null) {
                    throw new AuthenticationException(
                                    "Failed to get the sso token with token ID: " + tokenId);
            }

            // check the token validity
            SSOTokenManager manager = tokenManager;
            if (!manager.isValidToken(token)) {
                    throw new AuthenticationException("Token with ID: " + tokenId
                                    + " is invalid.");
            }

            // get the user with sso token
            AMIdentity userIdentity = IdUtils.getIdentity(token);
            String user = userIdentity.getName();

            return createToken(user);
        } catch (Exception e) {
            _logger.error("OpenSSO Token Error",e);
            throw new AuthenticationException("Authentication failed! OpenSSO ticket authentication failed!");
        }
    }
    public boolean isWorkflowAdmin(String user) throws AuthenticationException, RemoteException, RBACException{
    	
    	return _realms.isWorkflowAdmin(user);
    	
    	
    }
}
