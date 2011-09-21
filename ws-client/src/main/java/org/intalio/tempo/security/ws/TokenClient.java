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

import java.rmi.RemoteException;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.httpclient.HttpClient;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.token.TokenService;
import org.jasypt.util.text.BasicTextEncryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client web services API for the Token Service.
 */
public class TokenClient implements TokenService {

	Logger _logger = LoggerFactory.getLogger(TokenClient.class);
    String _endpoint;

    /**
     * Create a token service client
     * 
     * @param endpointUrl
     *            endpoint of the token service
     */
    public TokenClient(String endpointUrl) {
        _endpoint = endpointUrl;
    }

    public String getEndpoint() {
    	return _endpoint;
    }

    public String authenticateUser(String user, String password) throws AuthenticationException, RBACException, RemoteException {
        OMElement request = element(TokenConstants.AUTHENTICATE_USER);
        request.addChild(elementText(TokenConstants.USER, user));
        BasicTextEncryptor encryptor = new BasicTextEncryptor();
        // time to encrypt before sending
		encryptor.setPassword(org.intalio.tempo.security.ws.Constants.PASSWORD_MASK);
        request.addChild(elementText(TokenConstants.PASSWORD,encryptor.encrypt(password)));
        
        OMParser response = invoke(TokenConstants.AUTHENTICATE_USER.getLocalPart(), request);
        return response.getRequiredString(TokenConstants.TOKEN);
    }

    public String authenticateUser(String user, Property[] credentials) throws AuthenticationException, RBACException, RemoteException {
        OMElement request = element(TokenConstants.AUTHENTICATE_USER_WITH_CREDENTIALS);
        request.addChild(elementText(TokenConstants.USER, user));
        OMElement requestCred = element(TokenConstants.CREDENTIALS);
        for (int i = 0; i < credentials.length; i++) {
            OMElement prop = element(Constants.PROPERTY); 
            prop.addChild(elementText(Constants.NAME, credentials[i].getName()));
            prop.addChild(elementText(Constants.VALUE, credentials[i].getValue().toString()));
            requestCred.addChild(prop);
        }
        request.addChild(requestCred);
        OMParser response = invoke(TokenConstants.AUTHENTICATE_USER_WITH_CREDENTIALS.getLocalPart(), request);
        return response.getRequiredString(TokenConstants.TOKEN);
    }

    public Property[] getTokenProperties(String token) throws AuthenticationException, RemoteException {
        OMElement request = element(TokenConstants.GET_TOKEN_PROPERTIES);
        request.addChild(elementText(TokenConstants.TOKEN, token));
        OMParser response = invoke(TokenConstants.GET_TOKEN_PROPERTIES.getLocalPart(), request);
        return response.getProperties(Constants.PROPERTIES);
    }

	protected OMParser invoke(String action, OMElement request)
			throws AxisFault {
		ServiceClient serviceClient = getServiceClient();
		Options options = serviceClient.getOptions();
		EndpointReference targetEPR = new EndpointReference(_endpoint);
		options.setTo(targetEPR);
		options.setAction(action);

		// Disabling chunking as lighthttpd doesnt support it
        options.setProperty(
				org.apache.axis2.transport.http.HTTPConstants.CHUNKED,
				Boolean.FALSE);
		OMElement response = null;
		try {
			response = serviceClient.sendReceive(request);
			response.build();
		} finally {
			serviceClient.cleanupTransport();
		}
		_logger.debug("Invoked service for authentication");
		return new OMParser(response);
	}

    private static OMElement element(QName name) {
        return OM_FACTORY.createOMElement(name);
    }

    private static OMElement elementText(QName name, String text) {
        OMElement element = OM_FACTORY.createOMElement(name);
        element.setText(text);
        return element;
    }

    public String getTokenFromTicket(String ticket, String serviceURL) throws AuthenticationException, RBACException, RemoteException {
        OMElement request = element(TokenConstants.PROXY_TICKET);
        request.addChild(elementText(TokenConstants.TICKET, ticket));
        request.addChild(elementText(TokenConstants.SERVICE_URL, serviceURL));
        OMParser response = invoke(TokenConstants.GETTOKEN_FROMTICKET.getLocalPart(), request);
        return response.getRequiredString(TokenConstants.TOKEN);
    }

    public String getTokenFromOpenSSOToken(String tokenId)
    		throws AuthenticationException, RBACException, RemoteException {
        OMElement request = element(TokenConstants.OPENSSO_TICKET);
        request.addChild(elementText(TokenConstants.OPENSSO_TOKEN, tokenId));
        OMParser response = invoke(TokenConstants.GETTOKEN_FROM_OPSSSOTOKEN.getLocalPart(), request);
        return response.getRequiredString(TokenConstants.TOKEN);
    }

	protected ServiceClient getServiceClient() throws AxisFault {
		HttpClient httpClient = new HttpClient(
				MultiThreadedHttpConnectionManagerFactory.getInstance());
		Options options = new Options();
		options.setTimeOutInMilliSeconds(120 * 1000);
		ServiceClient serviceClient = new ServiceClient();
		serviceClient.setOptions(options);
		serviceClient.getOptions().setProperty(HTTPConstants.REUSE_HTTP_CLIENT,
				 org.apache.axis2.Constants.VALUE_TRUE);
		serviceClient.getOptions().setProperty(
				HTTPConstants.CACHED_HTTP_CLIENT, httpClient);
		// Disabling chunking as lighthttpd doesnt support it
		serviceClient.getOptions().setProperty(
				org.apache.axis2.transport.http.HTTPConstants.CHUNKED,
				Boolean.FALSE);
		return serviceClient;
	}
}
