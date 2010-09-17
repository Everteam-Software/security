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
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.proxy.Cas20ProxyRetriever;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.ProxyList;
import org.jasig.cas.client.validation.TicketValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Implementation of TokenIssuer that uses local authentication and RBAC
 * services.
 *
 * @author <a href="http://www.intalio.com">&copy; Intalio Inc.</a>
 */
public class TokenServiceImpl implements TokenService {

    Logger _logger = LoggerFactory.getLogger(TokenServiceImpl.class);

	public static final String SYS_PROP_DEFAULT_OPENSSO_TICKET_VALIDATOR =
		"org.intalio.tempo.security.impl.defaultopenssoticketvalidator";
	
	static Class __default_open_sso_ticket_validator;
	static {
		String className = System.getProperty(SYS_PROP_DEFAULT_OPENSSO_TICKET_VALIDATOR,
				"org.intalio.tempo.security.impl.openssoiplanet.DefaultIPlanetOpenSSOTicketValidator");
		try {
			__default_open_sso_ticket_validator =
				TokenServiceImpl.class.getClass().getClassLoader()
					.loadClass("org.intalio.tempo.security.impl.DefaultIPlanetOpenSSOTicketValidator");
		} catch (Throwable t) {
			LoggerFactory.getLogger(TokenServiceImpl.class)
				.warn("No opensso default implemntation available here. Could not find the class " + className);
		}
	}
	

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

    IOpenSSOTicketValidator _openssoTicketValidator;
    
    public TokenServiceImpl() {
        // nothing
    	if (__default_open_sso_ticket_validator != null) {
    		try {
				setIOpenSSOTicketValidator((IOpenSSOTicketValidator)__default_open_sso_ticket_validator.newInstance());
			} catch (Exception e) {
				_logger.warn("Unable to set the __default_open_sso_ticket_validator", e);
			}
    	}
    }
    
    public void setIOpenSSOTicketValidator(IOpenSSOTicketValidator openSSOTicketValidator) {
    	_openssoTicketValidator = openSSOTicketValidator;
    	_openssoTicketValidator.setTokenServiceImpl(this);
    }
    
    public IOpenSSOTicketValidator getIOpenSSOTicketValidator() {
    	return _openssoTicketValidator;
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
     */
    public String createToken(String user) throws RBACException, RemoteException {
        return createToken(user, null);
    }

    public String createToken(String user, String password) throws RBACException, RemoteException {
        // TODO we should use _realms to normalize
        user = IdentifierUtils.normalize(user, _realms.getDefaultRealm(), false, '\\');

        // place session information in token
        Property userProp = new Property(AuthenticationConstants.PROPERTY_USER, user);
        Property issueProp = new Property(AuthenticationConstants.PROPERTY_ISSUED, Long.toString(System.currentTimeMillis()));

        // add all user properties to token properties
        Property[] userProps = _realms.userProperties(user);
        List<Property> props = new ArrayList<Property>();

        props.add(userProp);
        props.add(issueProp);
        if (!_cacheRoles) {
            String[] roles = _realms.authorizedRoles(user);
            props.add(new Property(AuthenticationConstants.PROPERTY_ROLES, StringArrayUtils.toCommaDelimited(roles)));
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

        passwordProp = new Property(AuthenticationConstants.PROPERTY_PASSWORD, password);
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
                    String[] roles = _realms.authorizedRoles(user);
                    rolesForUser = new Property(AuthenticationConstants.PROPERTY_ROLES, StringArrayUtils.toCommaDelimited(roles));
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

//    public ProxyTicketValidator getProxyTicketValidator() {
//        return new ProxyTicketValidator();
//    }

    public Cas20ProxyTicketValidator getProxyTicketValidator() {
        return new Cas20ProxyTicketValidator(_validateURL);
    }
    
    public String getTokenFromTicket(String proxyTicket, String serviceURL) throws AuthenticationException, RBACException, RemoteException {
//    	ProxyTicketValidator pv = getProxyTicketValidator();
//        pv.setCasValidateUrl(_validateURL);
//        pv.setService(serviceURL);
//        pv.setServiceTicket(proxyTicket);
//        try {
//            pv.validate();
//        } catch (Exception e) {
//            throw new AuthenticationException("Authentication failed! Proxy ticket invalid!");
//        }
//        if (pv.isAuthenticationSuccesful()) {
//            String user = pv.getUser();
//
//            if (user == null) {
//                throw new AuthenticationException("Authentication failed: Null User");
//            }
//            return createToken(user);
//        } else {
//            throw new AuthenticationException("Authentication failed! Proxy ticket authentication failed!");
//        }
    	Cas20ProxyTicketValidator pv = getProxyTicketValidator();
    	pv.setAcceptAnyProxy(true);
    	pv.setProxyRetriever(new Cas20ProxyRetriever(_validateURL));
    	pv.setAllowedProxyChains(new ProxyList());
    	pv.setRenew(false);// by default as shown in the CAS default implementations.
//        pv.setProxyCallbackUrl(_validateURL);
        Assertion asser;
		try {
			asser = pv.validate(proxyTicket, serviceURL);
		} catch (TicketValidationException e) {
			throw new AuthenticationException("Authentication failed! Proxy ticket invalid!", e);
		}
        
        AttributePrincipal princip = asser.getPrincipal();


        if (princip != null) {
            String user = princip.getName();
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
	    if (_openssoTicketValidator != null) {
	    	return _openssoTicketValidator.getTokenFromOpenSSOToken(tokenId);
	    } else {
	    	_logger.error("OpenSSO Token Error: no opensso integration available here");
            throw new AuthenticationException("Authentication failed! No OpenSSO available in this runtime!");
	    }
     }
}
