/**
 * Copyright (c) 2005-2007 Intalio inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * Intalio inc. - initial API and implementation
 */

package org.intalio.tempo.security.ws;

import static org.intalio.tempo.security.ws.Constants.OM_FACTORY;
import static org.intalio.tempo.security.ws.TokenConstants.AUTHENTICATE_USER_RESPONSE;
import static org.intalio.tempo.security.ws.TokenConstants.CREDENTIALS;
import static org.intalio.tempo.security.ws.TokenConstants.GET_TOKEN_PROPERTIES_RESPONSE;
import static org.intalio.tempo.security.ws.TokenConstants.PASSWORD;
import static org.intalio.tempo.security.ws.TokenConstants.SERVICE_URL;
import static org.intalio.tempo.security.ws.TokenConstants.TICKET;
import static org.intalio.tempo.security.ws.TokenConstants.TOKEN;
import static org.intalio.tempo.security.ws.TokenConstants.USER;
import static org.intalio.tempo.security.ws.TokenConstants.IS_WORKFLOW_ADMIN;
import static org.intalio.tempo.security.ws.TokenConstants.IS_WORKFLOW_ADMIN_RESPONSE;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.AxisFault;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.jasypt.util.text.BasicTextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenWS extends BaseWS {
    private static final Logger LOG = LoggerFactory.getLogger(TokenConstants.class);

    public OMElement authenticateEncryptedUser(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String user = request.getRequiredString(USER);
        String password = request.getRequiredString(PASSWORD);
        String token;
        try {
        	initStatics();
        	// user password coming is already encryptd so we dont need to do anything
            token = _tokenService.authenticateUser(user,password);
        } catch (AuthenticationException except) {
            if (LOG.isDebugEnabled())
                LOG.debug("authenticateUser:\n" + requestEl, except);
            throw AxisFault.makeFault(except);
        } catch (Exception except) {
            if (LOG.isDebugEnabled())
                LOG.debug("authenticateUser:\n" + requestEl, except);
            LOG.error("User : " + user + " , Password : " + password);
            throw new RuntimeException(except);
        }

        return authenticateUserResponse(token);
    }
    
    public OMElement authenticateUser(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String user = request.getRequiredString(USER);
        String password = request.getRequiredString(PASSWORD);

        String token;
        try {
        	initStatics();
        	 BasicTextEncryptor encryptor = new BasicTextEncryptor();
             // setPassword uses hash to decrypt password which should be same as hash of encryptor
     		encryptor.setPassword("IntalioEncryptedpassword#123");
            token = _tokenService.authenticateUser(user,encryptor.encrypt(password));
        } catch (AuthenticationException except) {
            if (LOG.isDebugEnabled())
                LOG.debug("authenticateUser:\n" + requestEl, except);
            throw AxisFault.makeFault(except);
        } catch (Exception except) {
            if (LOG.isDebugEnabled())
                LOG.debug("authenticateUser:\n" + requestEl, except);
            LOG.error("User : " + user + " , Password : " + password);
            throw new RuntimeException(except);
        }

        return authenticateUserResponse(token);
    }

    public OMElement authenticateUserWithCredentials(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String user = request.getRequiredString(USER);
        Property[] credentials = request.getProperties(CREDENTIALS);

        String token;
        try {
        	initStatics();
            token = _tokenService.authenticateUser(user, credentials);
        } catch (AuthenticationException except) {
            if (LOG.isDebugEnabled())
                LOG.debug("authenticateUserWithCredentials:\n" + requestEl, except);
            throw AxisFault.makeFault(except);
        } catch (Exception except) {
            if (LOG.isDebugEnabled())
                LOG.debug("authenticateUserWithCredentials:\n" + requestEl, except);
            throw new RuntimeException(except);
        }

        return authenticateUserResponse(token);
    }

    public OMElement getTokenProperties(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String token = request.getRequiredString(TOKEN);

        Property[] props;
        try {
        	initStatics();
            props = _tokenService.getTokenProperties(token);
        } catch (AuthenticationException except) {
            if (LOG.isDebugEnabled())
                LOG.debug("getTokenProperties:\n" + requestEl, except);
            throw AxisFault.makeFault(except);
        } catch (Exception except) {
            if (LOG.isDebugEnabled())
                LOG.debug("getTokenProperties:\n" + requestEl, except);
            throw new RuntimeException(except);
        }
        return tokenPropertiesResponse(props);
    }
    
    public OMElement isWorkflowAdmin(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String user = request.getRequiredString(TOKEN);

        boolean isWorkflowAdmin;
        try {
        	initStatics();
            isWorkflowAdmin = _tokenService.isWorkflowAdmin(user);
        } catch (AuthenticationException except) {
            if (LOG.isDebugEnabled())
                LOG.debug("isWorkflowAdmin:\n" + requestEl, except);
            throw AxisFault.makeFault(except);
        } catch (Exception except) {
            if (LOG.isDebugEnabled())
                LOG.debug("isWorkflowAdmin:\n" + requestEl, except);
            throw new RuntimeException(except);
        }
        return isWorkflowAdminResponse(isWorkflowAdmin);
    }

    private OMElement authenticateUserResponse(String token) {
        OMElement response = OM_FACTORY.createOMElement(AUTHENTICATE_USER_RESPONSE);
        OMElement responseToken = OM_FACTORY.createOMElement(TOKEN, response);
        responseToken.setText(token);
        return response;
    }

    private OMElement tokenPropertiesResponse(Property[] props) {
        OMElement response = OM_FACTORY.createOMElement(GET_TOKEN_PROPERTIES_RESPONSE);
        OMElement responseProperties = OM_FACTORY.createOMElement(Constants.PROPERTIES, response);
        for (int i = 0; i < props.length; i++) {
            OMElement prop = OM_FACTORY.createOMElement(Constants.PROPERTY, responseProperties);

            OMElement name = OM_FACTORY.createOMElement(Constants.NAME, prop);
            name.setText(props[i].getName());

            OMElement value = OM_FACTORY.createOMElement(Constants.VALUE, prop);
            value.setText(props[i].getValue().toString());

        }
        return response;
    }

    private OMElement isWorkflowAdminResponse(boolean isWorkflowAdmin) {
        OMElement response = OM_FACTORY.createOMElement(IS_WORKFLOW_ADMIN_RESPONSE);
        OMElement responseToken = OM_FACTORY.createOMElement(IS_WORKFLOW_ADMIN, response);
        responseToken.setText(String.valueOf(isWorkflowAdmin));
        return response;    
    
    }

    
    public OMElement getTokenFromTicket(OMElement requestEl) throws AxisFault {
        OMParser request = new OMParser(requestEl);
        String ticket = request.getRequiredString(TICKET);
        String serviceURL = request.getRequiredString(SERVICE_URL);

        String token;
        try {
        	initStatics();
            token = _tokenService.getTokenFromTicket(ticket, serviceURL);
        } catch (AuthenticationException except) {
            if (LOG.isDebugEnabled())
                LOG.debug("authenticateUser:\n" + requestEl, except);
            throw AxisFault.makeFault(except);
        } catch (Exception except) {
            if (LOG.isDebugEnabled())
                LOG.debug("authenticateUser:\n" + requestEl, except);
            throw new RuntimeException(except);
        }

        return authenticateUserResponse(token);
    }
}
