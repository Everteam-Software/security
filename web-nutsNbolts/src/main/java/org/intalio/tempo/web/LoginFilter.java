/**
 * Copyright (c) 2008 Intalio inc.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * Intalio inc. - initial API and implementation
 */
package org.intalio.tempo.web;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpStatus;
import org.intalio.tempo.web.controller.LoginController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

public class LoginFilter implements javax.servlet.Filter {
    private static final Logger LOG = LoggerFactory
            .getLogger(LoginFilter.class);
    private static final String TRUE = "true";
    private static final String AJAX = "ajax";

    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse resp = (HttpServletResponse) response;
            String uri =req.getRequestURI();
            if ( uri.startsWith("/login") ) {
                // don't protect login page
                chain.doFilter(request, response);
                return;
            }

            boolean isAjaxCall = TRUE.equals(req.getHeader(AJAX));
            String secureSession = LoginController.getSecureRandomSession(req);
            String secureCookie = LoginController.getSecureRandomCookie(req);
            if (secureSession != null) {
                if (secureSession.equals(secureCookie)) {
                    // already authenticated
                    chain.doFilter(request, response);
                    return;
                }
            }

            WebApplicationContext context = WebApplicationContextUtils
                    .getRequiredWebApplicationContext(req.getSession()
                            .getServletContext());
            LoginController login = (LoginController) context
                    .getBean("loginController");
            if (login == null)
                throw new IllegalStateException(
                        "Missing 'loginController' object in Spring webapp context");

            User user = login.getCurrentUser(req);
            if (user == null) {
                // authentication failed or not available
                LOG.info("User not logged in, redirecting to login page: "
                        + login.getLoginPageURL());
                if (isAjaxCall) {
                    resp.setStatus(HttpStatus.SC_UNAUTHORIZED);
                } else {
                    LoginController.setRedirectAfterLoginCookie(resp,
                            req.getRequestURI());
                    resp.sendRedirect(generateUrl(login.getLoginPageURL(), req));
                }
            } else {
                // authenticated: synchronize secure random
                if (secureCookie != null) {
                    LoginController.setSecureRandomSession(req, secureCookie);
                } else {
                    LoginController.generateSecureRandom(req, resp);
                }
                ApplicationState state = login.getApplicationState(req);
                if (state != null) {
                    state.setCurrentUser(user);
                }
                chain.doFilter(request, response);
            }
        } else {
            LOG.warn("ServletRequest was not HttpServletRequest; ignoring request.");
        }
    }

    private String generateUrl(String loginUrl, HttpServletRequest req)
            throws UnsupportedEncodingException {
        if(loginUrl == null) return "";
        StringBuilder urlBuilder = new StringBuilder(loginUrl);
        try {
            urlBuilder.append("?prevAction=");
            urlBuilder.append(URLEncoder.encode(req.getRequestURI(), "UTF-8"));

            if (req.getQueryString() != null) {
                urlBuilder.append(URLEncoder.encode("?"
                        + req.getQueryString().toString(), "UTF-8"));
            }
        } catch (Exception e) {
            LOG.warn("Exception encoding the url for previous action", e);
        }
        return urlBuilder.toString();
    }

    public void init(FilterConfig config) throws ServletException {
        // nothing
    }

    public void destroy() {
        // nothing
    }

}