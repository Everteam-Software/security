/**
 * Copyright (c) 2005-2006 Intalio inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * Intalio inc. - initial API and implementation
 *
 * $Id: TaskManagementServicesFacade.java 5440 2006-06-09 08:58:15Z imemruk $
 * $Log:$
 */

package org.intalio.tempo.workflow;

import org.apache.axis2.AxisFault;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.log4j.Logger;
import org.intalio.tempo.web.SysPropApplicationContextLoader;
import org.springframework.beans.factory.FactoryBean;

public class ServiceObjectSupplier implements org.apache.axis2.ServiceObjectSupplier {

	private static final Logger LOG = Logger.getLogger(ServiceObjectSupplier.class);

	public Object getServiceObject(AxisService service) throws AxisFault {
	    Parameter fac = service.getParameter("SpringBeanFactory");
        SysPropApplicationContextLoader contextLoader = SpringInit.CONTEXT_MAP.get(service.getName());
        if (null == contextLoader) {
            LOG.error("Service Context not available for service: "
                    + service.getName()
                    + ". Ensure Spring initialization of the service was successfull and service is not undeployed.");
            throw new AxisFault("Service:" + service.getName() + " is not in available state at target server.");
        }
	    if(fac!=null) {
            Thread thread = Thread.currentThread();
            ClassLoader oldClassLoader = thread.getContextClassLoader();
	        try {
                thread.setContextClassLoader(contextLoader.getClass().getClassLoader());
	            String factoryName = (String)fac.getValue();
	            LOG.info("Using factory:"+factoryName);
	            Object o = contextLoader.getBean(factoryName);
	            //LOG.info("Class:"+o.getClass().getName());
	            FactoryBean factory = (FactoryBean)o;
	            return factory.getObject();    
	        } catch (Exception e) {
	            LOG.info("Error while using factory",e);
            } finally {
                thread.setContextClassLoader(oldClassLoader);
            }
	    }
				
		String beanName = "#unspecified#";
		Parameter p = service.getParameter("SpringBeanName");
		if (p != null) {
			beanName = (String) p.getValue();
		}
		Object bean = contextLoader.getBean(beanName);
		if (bean == null) {
			LOG.error("Bean not found: "+beanName);
		}
		return bean;
	}

}
