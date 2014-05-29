package org.intalio.tempo.security.database.dao;

import java.io.File;

import org.apache.log4j.Logger;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

public class SessionFactoryHelper {

    private static Logger log = Logger.getLogger(SessionFactoryHelper.class);

    private static final SessionFactory sessionFactory ;
    public static final String CONFIG_DIR_PROPERTY = "org.intalio.tempo.configDirectory";
    protected static File _configFile;
    static {
        try {
            /*
             * Build a SessionFactory object from session-factory configuration
             * defined in the hibernate.cfg.xml file. In this file we register
             * the JDBC connection information, connection pool, the hibernate
             * dialect that we used and the mapping to our hbm.xml file for each
             * POJO (Plain Old Java Object).
             */
            log.debug("Initializing configuration.");
            String configDir = System.getProperty(CONFIG_DIR_PROPERTY);
            if (configDir == null) {
                throw new RuntimeException("System property " + CONFIG_DIR_PROPERTY + " not defined.");
            }
            _configFile = new File(configDir + File.separator + "security-provider" + File.separator + "hibernate.cfg.xml");
            if(!_configFile.exists())
                throw new RuntimeException("File " + _configFile + " does not exists.");
            sessionFactory = new Configuration().configure(_configFile)
                    .buildSessionFactory();
        } catch (Exception e) {
            log.error("Error in creating SessionFactory object." + e);
            throw new ExceptionInInitializerError(e);
        }
    }

    public static SessionFactory getSessionFactory() {
        return sessionFactory;
    }
}
