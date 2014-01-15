package org.intalio.tempo.security;

import junit.framework.TestCase;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.googlecode.instinct.integrate.junit4.InstinctRunner;

public class SecurityComponentTest extends TestCase {
    private static final Logger logger = LoggerFactory
            .getLogger(SecurityComponentTest.class);

    public void test() throws Exception {
        SecurityComponent sc = new SecurityComponent();
        sc.setDefaultRealm("__realm");
        sc.setProviderClass("org.intalio.tempo.security.DummySecurityProvider");
        sc.setProperty("test", "testvalue");
        sc.init();
        sc.start();
        sc.stop();
        sc.shutDown();
    }
}
