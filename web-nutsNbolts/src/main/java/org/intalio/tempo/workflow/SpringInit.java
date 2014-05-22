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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.engine.ServiceLifeCycle;
import org.apache.log4j.Logger;
import org.intalio.tempo.web.SysPropApplicationContextLoader;

public class SpringInit implements ServiceLifeCycle {

    private static final Logger LOG = Logger.getLogger(SpringInit.class);

    public static Map<String, SysPropApplicationContextLoader> CONTEXT_MAP = new HashMap<String, SysPropApplicationContextLoader>();
    
    /**
     * Called by Axis2 during deployment
     */
    public void startUp(ConfigurationContext ignore, AxisService service) {
        String configFile = "#unspecified#";
        try {
            Parameter p = service.getParameter("SpringContextFile");
            if (p != null) configFile = (String) p.getValue();
            LOG.debug("Loading configuration: "+configFile);

            Thread thread = Thread.currentThread();
            ClassLoader oldClassLoader = thread.getContextClassLoader();
            try {
                thread.setContextClassLoader(service.getClassLoader());
                Parameter loadAllBeansOnStartup = service.getParameter("LoadAllBeansOnStartup");
                if (null != CONTEXT_MAP.get(service.getName())) {
                    LOG.warn("StartUp called again for service:"
                            + service.getName()
                            + ". Overwriting previous service context.");
                }
                if(loadAllBeansOnStartup != null && ((String) loadAllBeansOnStartup.getValue()).equalsIgnoreCase("true")){
                    //WF-1574: it will load all beans on startup, as we need to load audit configuration.
                    CONTEXT_MAP.put(service.getName(),
                            new SysPropApplicationContextLoader(configFile,
                                    true));
                } else {
                    SysPropApplicationContextLoader contextLoader = new SysPropApplicationContextLoader(
                            configFile);
                    CONTEXT_MAP.put(service.getName(), contextLoader);
                    Parameter load = service.getParameter("LoadOnStartup");
                    if (load != null && ((String) load.getValue()).equalsIgnoreCase("true")) {
                        Parameter bean = service.getParameter("SpringBeanName");
                        if (bean == null) throw new IllegalArgumentException("Missing 'SpringBeanName' parameter");
                        String beanName = (String) bean.getValue();
                        try {
                            contextLoader.getBean(beanName);
                        } catch (Exception e) {
                            throw new IllegalArgumentException("Unable to initialize bean '"+beanName+"'", e);
                        }
                    }
                }
                LOG.info("Service context created successfully for service:"
                        + service.getName());
            } catch (IOException except) {
                throw new RuntimeException(except);
            } finally {
                thread.setContextClassLoader(oldClassLoader);
            }
        } catch (Exception except) {
            LOG.error("Error while loading Spring context file: "+configFile+". Removing service context for service:"+service.getName(), except);
            CONTEXT_MAP.remove(service.getName());
        }
    }

    /**
     * Called by Axis2 during undeployment 
     */
    public void shutDown(ConfigurationContext ctxIgnore, AxisService ignore) {
        LOG.info("Shutdown was called for service:"+ignore.getName()+". Service context removed for this spring initialised service.");
        CONTEXT_MAP.remove(ignore.getName());
    }
}
