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


import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.ServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.intalio.bpms.common.AxisUtil;

/**
 * RBACQueryService client.
 */
public class RBACQueryClient {
    
    /**
     * logger for RBACQueryClient.
     */
    private Logger logger = LoggerFactory.getLogger(RBACQueryClient.class);

    /**
     * endpoint url for RBACQueryService.
     */
    private String endpoint;
    /**
     * httpChunking property.
     */
    private String httpChunking = "false";

    /**
     * Create a RBACQuery service client.
     * 
     * @param endpointUrl endpoint of the RBACQuery service
     */
    public RBACQueryClient(final String endpointUrl) {
        endpoint = endpointUrl;
    }

    /**
     * get endpoint url for RBACQueryService.
     * @return endpoint String
     */
    public final String getEndpoint() {
        return endpoint;
    }

    /**
     * call operation getAssignedUsers.
     * @param role String
     * @return users String[]
     * @throws AxisFault service Exception
     */
    public final String[] getAssignedUsers(final String role) throws AxisFault {
        OMElement request = element(RBACQueryConstants.ASSIGNED_USERS_REQUEST);
        request.addChild(elementText(RBACQueryConstants.ROLE, role));
        OMParser response = invoke(
                RBACQueryConstants.ASSIGNED_USERS.getLocalPart(), request);
        return response.getRequiredStringArray(RBACQueryConstants.USER);
    }
    
    /**
     * call operation getAssignedUsers.
     * @param role String
     * @return users String[]
     * @throws AxisFault service Exception
     */
    public final String[] getAssignedRoles(final String user) throws AxisFault {
        OMElement request = element(RBACQueryConstants.ASSIGNED_ROLES_REQUEST);
        request.addChild(elementText(RBACQueryConstants.USER, user));
        OMParser response = invoke(
                RBACQueryConstants.ASSIGNED_ROLES.getLocalPart(), request);
        return response.getRequiredStringArray(RBACQueryConstants.ROLE);
    }

    /**
     * invoke operation.
     * @param action String
     * @param request OMElement
     * @return response OMParser
     * @throws AxisFault service Exception
     */
    protected final OMParser invoke(final String action,
                final OMElement request) throws AxisFault {
        ServiceClient serviceClient = null;
        OMElement response = null;
        AxisUtil util = new AxisUtil();
        try {
            serviceClient = util.getServiceClient();
            serviceClient.getOptions().setTo(new EndpointReference(endpoint));
            serviceClient.getOptions().setAction(action);
            serviceClient.getOptions().setProperty(
                        org.apache.axis2.transport.http.HTTPConstants.CHUNKED,
                        Boolean.FALSE);
            response = serviceClient.sendReceive(request);
            response.build();
        } catch (AxisFault e) {
            logger.error("Service was called with this option "
                    + serviceClient.getServiceContext());
            e.printStackTrace();
            throw e;
        } finally {
            if (serviceClient != null) {
                try {
                    util.closeClient(serviceClient);
                } catch (Exception e) {
                    logger.error("Error while cleanup");
                }
            }
        }
        logger.debug("Invoked service for authentication");
        return new OMParser(response);
    }

    /**
     * create element.
     * @param name QName
     * @return element OMElement
     */
    private static OMElement element(final QName name) {
        return OM_FACTORY.createOMElement(name);
    }

    /**
     * create elementText.
     * @param name QName
     * @param text String
     * @return element OMElement
     */
    private static OMElement elementText(final QName name,
            final String text) {
        OMElement element = OM_FACTORY.createOMElement(name);
        element.setText(text);
        return element;
    }

    /**
     * set httpChunking.
     * @param chunking String
     */
    public final void setHttpChunking(final String chunking) {
        this.httpChunking = chunking;
    }

    /**
     * get httpChunking.
     * @return httpChunking boolean
     */
    public final boolean isChunking() {
        return Boolean.parseBoolean(this.httpChunking);
    }

}
