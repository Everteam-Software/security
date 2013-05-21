/**
 * Copyright (C) 2006, Intalio Inc.
 *
 * The program(s) herein may be used and/or copied only with
 * the written permission of Intalio Inc. or in accordance with
 * the terms and conditions stipulated in the agreement/contract
 * under which the program(s) have been supplied.
 *
 * $Id$
 * $Log$
 */
package org.intalio.tempo.web.controller;

import java.io.IOException;
import java.rmi.RemoteException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.intalio.tempo.security.Property;
import org.intalio.tempo.security.authentication.AuthenticationConstants;
import org.intalio.tempo.security.authentication.AuthenticationException;
import org.intalio.tempo.security.rbac.RBACException;
import org.intalio.tempo.security.token.TokenService;
import org.intalio.tempo.security.util.PropertyUtils;
import org.intalio.tempo.security.util.StringArrayUtils;
import org.intalio.tempo.versions.BpmsDescriptorParser;
import org.intalio.tempo.web.ApplicationState;
import org.intalio.tempo.web.Constants;
import org.intalio.tempo.web.User;
import org.springframework.validation.BindException;
import org.springframework.validation.Errors;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import com.intalio.bpms.license.IntalioSigner;

public class LoginController extends UIController {
    private static final BpmsDescriptorParser BPMS_DESCRIPTOR_PARSER = new BpmsDescriptorParser();

    public static final String AUTO_LOGIN_ID = "autoLogin";

    public static final String SINGLE_LOGIN_ID = "singleLogin";

    public static final String REDIRECT_AFTER_LOGIN = "redirectAfterLogin";

    public static final String SECURE_RANDOM = "SECURE_RANDOM";
    
    public static final String JSESSION = "JSESSIONID";
    
    public static final String UI_FW = "/ui-fw/";
    
    public static final String MONITORING = "/monitoring/";
    
    public static final String BPMS_CONSOLE = "/bpms-console/";
    
    public static final String DATE_FORMAT = "yyyy-MM-dd";

    public static final String ENT_LICENSE_EXPIRY = "enterprise";

    public static final String LICENSE_EXPIRY = "license";

    private static final Logger LOG = LogManager.getLogger(LoginController.class);

    protected final TokenService _tokenService;

    private List<String> _grantedRoles = new ArrayList<String>();

    private String _defaultRedirectAfterLogin;

    private String _loginPageURL;
    
    public static String  _displayName = "{user}";
    
    private static final Pattern DISPLAY_NAME_REGEX = Pattern.compile("\\{(.+?)\\}");

    private static SecureRandom _random;
    
    private  boolean licenseExpires = false;

    static {
        try {
            _random = SecureRandom.getInstance("SHA1PRNG");
        } catch (Exception e) {
            LOG.error("Cannot initialize secure random number generator", e);
            throw new RuntimeException(e);
        }
    }
    
    public LoginController(TokenService tokenService, String redirectSuccessfulLogin) {
        super();
        _tokenService = tokenService;
        _defaultRedirectAfterLogin = redirectSuccessfulLogin;
    }

    public String getLoginPageURL() {
        return _loginPageURL;
    } 
     
    public void setLoginPageURL(String url) {
        _loginPageURL = url;
    }
    
    public static ModelAndView redirect(String url) {
        return new ModelAndView(new RedirectView(url));
    }

    public ModelAndView redirectAfterLogin(HttpServletRequest request, HttpServletResponse response) {
        String url = _defaultRedirectAfterLogin;
        Cookie cookie = getCookie(request, REDIRECT_AFTER_LOGIN);
        if (cookie != null && cookie.getValue() != null) {
            url = cookie.getValue();
            clearCookie(REDIRECT_AFTER_LOGIN, response);
        }
        return redirect(url);
    }
    
    public static void clearAutoLogin(HttpServletResponse response) {
        clearCookie(AUTO_LOGIN_ID, response);
    }

    public static void clearSingleLogin(HttpServletResponse response) {
        clearCookie(SINGLE_LOGIN_ID, response);
    }

    public static void clearSecureRandom(HttpServletResponse response) {
        clearCookie(SECURE_RANDOM, response);
    }
    
    public static void clearRootCookie(HttpServletResponse response) {
        clearCookie(JSESSION, response);
    }
    
    public static String getSecureRandomCookie(HttpServletRequest request) {
        Cookie cookie = getCookie(request, SECURE_RANDOM);
        if (cookie == null) return null;
        return cookie.getValue();
    }

    public static String getSecureRandomSession(HttpServletRequest request) {
        return (String) request.getSession().getAttribute(SECURE_RANDOM);
    }

    public static void setSecureRandomSession(HttpServletRequest request, String secureRandom) {
        request.getSession().setAttribute(SECURE_RANDOM, secureRandom);
    }

    public static void generateSecureRandom(HttpServletRequest request, HttpServletResponse response) {
        String secureRandom = generateSecureRandom();
        request.getSession().setAttribute(SECURE_RANDOM, secureRandom);
        Cookie cookie = new Cookie(SECURE_RANDOM, secureRandom);
        cookie.setMaxAge(60*60*24*365); // one year
        cookie.setPath("/");
        response.addCookie(cookie);
    }
    
    public static String generateSecureRandom() {
        StringBuffer str = new StringBuffer();
        byte[] buf = new byte[40];
        _random.nextBytes(buf);
        return bytesToHex(buf);
    }
    
    public static String bytesToHex(byte[] bytes) {
        final char[] hex = "0123456789ABCDEF".toCharArray();
        StringBuffer buf = new StringBuffer();
        for (int i=0; i<bytes.length; i++) {
            int n = bytes[i]+128;
            buf.append(hex[n/16]);
            buf.append(hex[n%16]);
        }
        return buf.toString();
    }

    public static void clearCookie(String cookieName, HttpServletResponse response) {
        Cookie newCookie = new Cookie(cookieName, null);
        newCookie.setMaxAge(0);
        newCookie.setPath("/");
        response.addCookie(newCookie);
    }
    
    public static void clearOtherCookie(HttpServletResponse response,String cookieName,String path) {
        Cookie newCookie = new Cookie(cookieName, null);
        newCookie.setMaxAge(0);
        newCookie.setPath(path);
        response.addCookie(newCookie);
    }
    
    private static String extractProperty(String propName, Property[] props) {
        for (Property prop : props) {
            if (propName.equals(prop.getName())) {
                return (String) prop.getValue();
            }
        }
        return null;
    }

    public static String extractUser(Property[] props) {
        return extractProperty(AuthenticationConstants.PROPERTY_USER, props);
    }
    
    public static String extractUserDisplayName(Property[] props) {
    	String displayName = StringUtils.trimToNull(_displayName);
    	List<String> attributes = getAttributeValues(displayName);
    	for (String attribute : attributes) {
    		String propertyValue = extractProperty(attribute, props);
    		if(propertyValue == null)
    			propertyValue = "";
    		displayName = StringUtils.trimToNull(displayName.replace("{"+attribute+"}", propertyValue));
		}
    	if(displayName == null)
        	displayName = extractUser(props);
    	return displayName;
    }
    
    private static List<String> getAttributeValues(String str) {
	    final List<String> tagValues = new ArrayList<String>();
	    final Matcher matcher = DISPLAY_NAME_REGEX.matcher(str);
	    while (matcher.find()) {
	        tagValues.add(matcher.group(1));
	    }
	    return tagValues;
	}

    public static String[] extractRoles(Property[] props) {
        String rolesCommaList = extractProperty(AuthenticationConstants.PROPERTY_ROLES, props);
        if (rolesCommaList != null) {
            String[] roleStrings = StringArrayUtils.parseCommaDelimited(rolesCommaList);
            return roleStrings;
        }
        return null;
    }
    
    public User getCurrentUser(HttpServletRequest request) {
        try {
            User user = checkSingleLogin(request);
            if (user == null) {
                user = checkAutoLogin(request);
            }
            return user;
        } catch (Exception except) {
            return null;
        }
    }

    protected User checkAutoLogin(HttpServletRequest request) {
        return checkToken(request, AUTO_LOGIN_ID);
    }

    protected User checkSingleLogin(HttpServletRequest request) {
        return checkToken(request, SINGLE_LOGIN_ID);
    }

    protected static Cookie getCookie(HttpServletRequest request, String cookieName) {
        Cookie cookie = null;
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if (cookieName.equals(c.getName())) {
                    cookie = c;
                }
            }
        }
        return cookie;
    }
    
    protected User checkToken(HttpServletRequest request, String cookieName) {
        Cookie cookie = getCookie(request, cookieName);
        User user = null;
        if (cookie != null) {
            String token = cookie.getValue();
            if (token != null && token.trim().length() > 0) {
                try {
                    Property[] props = _tokenService.getTokenProperties(token);
                    String name = extractUser(props);
                    String displayName = extractUserDisplayName(props);
                    String[] roles = extractRoles(props);
                    Property isWorkFlowAdmin = PropertyUtils.getProperty(props, "isWorkflowAdmin");
                    user = new User(name, roles, token, Boolean.parseBoolean(isWorkFlowAdmin.getValue().toString()), displayName);
                } catch (Exception ex) {
                    LOG.error("Exception while verifying security token: "+ex);
                }
            }
        }
        return user;
    }

    public void setRedirectAfterLoginCookie(HttpServletResponse response) {
        setRedirectAfterLoginCookie(response, _defaultRedirectAfterLogin);
    }
    
    
    public static void setRedirectAfterLoginCookie(HttpServletResponse response, String url) {
        Cookie cookie = new Cookie(REDIRECT_AFTER_LOGIN, url);
        cookie.setMaxAge(60*60); // one hour
        cookie.setPath("/");
        response.addCookie(cookie);
    }


    public static void setAutoLoginCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie(AUTO_LOGIN_ID, token);
        cookie.setMaxAge(60*60*24*365); // one year
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    public static void setSingleLoginCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie(SINGLE_LOGIN_ID, token);
        cookie.setMaxAge(-1); // not persistent, kept until web browser exits
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    public List<String> getGrantedRoles() {
        return _grantedRoles;
    }

    public void setGrantedRoles(List<String> roles) {
        _grantedRoles = roles;
    }

    protected User authenticate(String username, String password, String[] grantedRoles) throws SecurityException {
        try {
        	
            String token = _tokenService.authenticateUser(username, password);
            if (token == null) {
                throw new IllegalStateException("Empty token returned from token service");
            }
            return authenticate(token, grantedRoles);
        } catch (Exception ex) {
            throw new SecurityException(ex);
        }
    }

    protected User authenticate(String token, String[] grantedRoles) throws SecurityException {
        try {
            Property[] props = _tokenService.getTokenProperties(token);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Token properties: " + PropertyUtils.toMap(props));
            }

            String name = extractUser(props);
            String displayName = extractUserDisplayName(props);
            String[] roles = extractRoles(props);
            Property isWorkFlowAdmin = PropertyUtils.getProperty(props, "isWorkflowAdmin");
            User user = new User(name, roles, token, Boolean.parseBoolean(isWorkFlowAdmin.getValue().toString()), displayName);
            if (grantedRoles.length > 0 && !user.hasOneRoleOf(grantedRoles)) {
                throw new SecurityException("User does not have one of the following role: "
                        + StringArrayUtils.toCommaDelimited(grantedRoles));
            }
            LOG.debug("User: " + user);
            return user;
        } catch (AuthenticationException ex) {
            throw new SecurityException(ex);
        } catch (RemoteException ex) {
            throw new SecurityException(ex);
        }
    }

    protected User authenticate(String username, String password, Errors errors) {
        try {
            LOG.debug("Login user=" + username);
            User currentUser = authenticate(username, password, convertRoles(_grantedRoles));

            return currentUser;
        } catch (SecurityException e) {
            LOG.error("Error during login", e);
            errors.reject("org_intalio_tempo_web_controller_login_loginError", "The user identifier or password you provided is invalid");
        }
        return null;
    }

    public String arrayToString(String[] stringArray, String delimiter) {
        StringBuilder builder = new StringBuilder();
        int arrayLength = stringArray.length;
        for (int index = 0; index < arrayLength; index++) {
            builder.append(stringArray[index]);
            if (index != (arrayLength - 1)) {
                builder.append(delimiter);
            }
        }
        return builder.toString();
    }

    public void executePost(PostMethod post) {
        HttpClient httpclient = new HttpClient();
        try {
            httpclient.executeMethod(post);
            String responseAsString = post.getResponseBodyAsString();
            LOG.debug("Response is: " + responseAsString);
        } catch (Exception e) {
            LOG.warn("Got exception " + e.getMessage() + "while posting request "
                    + post.getPath());
        } finally {
            LOG.debug("Releasing Connection");
            post.releaseConnection();
        }
    }

    // @note(alex) Called by reflection - see UIController
    @SuppressWarnings("unchecked")
    public ModelAndView logIn(HttpServletRequest request, HttpServletResponse response, LoginCommand login,
            BindException errors) throws Exception {
        // Checking whether logged in
        ApplicationState state = getApplicationState(request);
        LOG.debug("logIn() state=" + state);

        if (state.getCurrentUser() != null) {
            return redirectAfterLogin(request, response);
        }
        if (!errors.hasErrors()) {
            User user = authenticate(login.getUsername(), login.getPassword(), errors);
            if (user != null) {
                state.setCurrentUser(user);
                if (login.isAutoLogin()) {
                    // set autoLogin
                    setAutoLoginCookie(response, user.getToken());
                }
                setSingleLoginCookie(response, user.getToken());
                String prevAction = state.getPreviousAction();
                LOG.debug("logIn() prevAction=" + prevAction);
                if (prevAction == null) {
                    return redirectAfterLogin(request, response);
                } else {
                    state.setPreviousAction(null);
                    return new ModelAndView(new RedirectView(prevAction));
                }
            }
        }
        Map model = errors.getModel();
        model.put("login", login);
        BPMS_DESCRIPTOR_PARSER.addBpmsBuildVersionsPropertiesToMap(model);

        return new ModelAndView(Constants.LOGIN_VIEW, model);
    }

    // @note(alex) Called by reflection - see UIController
    public ModelAndView logOut(HttpServletRequest request, HttpServletResponse response, LoginCommand login,
            BindException errors) throws Exception {
        ApplicationState state = getApplicationState(request);
        if (state != null) {
            if (state.getCurrentUser() != null){
                String userName = state.getCurrentUser().getName();
                LOG.debug("Logout: user=" + userName);
            }
            state.setCurrentUser(null);
            state.setPreviousAction(null);
            clearAutoLogin(response);
            clearSingleLogin(response);
            clearSecureRandom(response);
            clearRootCookie(response);
            clearOtherCookie(response,JSESSION,UI_FW);
            clearOtherCookie(response,JSESSION,MONITORING);
            clearOtherCookie(response,JSESSION,BPMS_CONSOLE);
        }
        Map model = new HashMap();
        model.put("login", new LoginCommand());
        BPMS_DESCRIPTOR_PARSER.addBpmsBuildVersionsPropertiesToMap(model);
        String licenseExpiryDate = getLicenseEnterpriseDate();
        if (licenseExpires)
            model.put("license", licenseExpiryDate);
        return new ModelAndView(Constants.LOGIN_VIEW, model);
    }

    @Override
    protected ModelAndView showForm(HttpServletRequest request, HttpServletResponse response, BindException errors)
            throws Exception {
        ApplicationState state = getApplicationState(request);
        LOG.debug("showForm() state=" + state);
        String preAction = request.getParameter("prevAction");
        if(preAction != null && !preAction.equals("")) {
            state.setPreviousAction(preAction);
        }
        // Checking whether logged in
        User user = state.getCurrentUser();

        if (user == null) {
            user = checkSingleLogin(request);
            if (user != null)
                user = authenticate(user.getToken(), convertRoles(_grantedRoles));
        }
        if (user == null) {
            user = checkAutoLogin(request);
            if (user != null)
                user = authenticate(user.getToken(), convertRoles(_grantedRoles));
        }

        if (user == null) {
            // do login
            // handle login from HTTP request
            String username = request.getParameter(LoginValidator.USERNAME_PARAM);
            String password = request.getParameter(LoginValidator.PASSWORD_PARAM);

            // LOG.debug("username: " + username + " password: " + password);
            if (username != null && !"".equals(username) && password != null) {
                user = authenticate(username, password, errors);
            }
        }

        if (user != null) {
            LOG.debug("User authenticated: " + user.getName());
            state.setCurrentUser(user);
            String prevAction = state.getPreviousAction();
            if (prevAction == null) {
                LOG.debug("Redirect after succesful login");
                return redirectAfterLogin(request, response);
            } else {
                LOG.debug("Redirect after succesful login: " + prevAction);
                state.setPreviousAction(null);
                return new ModelAndView(new RedirectView(prevAction));
            }
        }
        LOG.debug("" + errors);

        Map model = errors.getModel();
        model.put("login", new LoginCommand());
        BPMS_DESCRIPTOR_PARSER.addBpmsBuildVersionsPropertiesToMap(model);
        String licenseExpiryDate = getLicenseEnterpriseDate();
        if (licenseExpires)
            model.put("license", licenseExpiryDate);
        return new ModelAndView(Constants.LOGIN_VIEW, model);
    }

    public String getLicenseEnterpriseDate() {
        String licenseExpiryDate = IntalioSigner.getKeyDate(ENT_LICENSE_EXPIRY);
        if (licenseExpiryDate != null && licenseExpiryDate != "") {
            DateFormat licenseExpiryDateFormat = new SimpleDateFormat(
                    DATE_FORMAT);
            Calendar licenseExpiryCal = Calendar.getInstance();
            try {
                licenseExpiryCal.setTime(licenseExpiryDateFormat
                        .parse(licenseExpiryDate));
            } catch (java.text.ParseException e) {
                LOG.error("Exeception occured while parsing date", e);
            }
            Calendar cur_Date = Calendar.getInstance();
            cur_Date.add(Calendar.MONTH, 1);
            if (licenseExpiryCal.getTimeInMillis() <= cur_Date
                    .getTimeInMillis()) {
                licenseExpires = true;
            }
        }
        return licenseExpiryDate;
    }
    public String getDisplayName() {
		return _displayName;
	}

	public void setDisplayName(String displayName) {
		this._displayName = displayName;
	}

    public static class LoginValidator implements org.springframework.validation.Validator {
        private static final String USERNAME_PARAM = "username";

        private static final String PASSWORD_PARAM = "password";

        /**
         * Minimal length of the component value
         */
        private static final int USERNAME_MIN_LENGTH = 0;

        /**
         * Maximum length of the component value
         */
        private static final int USERNAME_MAX_LENGTH = 100;

        /**
         * Minimum text length
         */
        private static final int PASSWORD_MIN_LENGTH = 0;

        /**
         * Maximum text length
         */
        private static final int PASSWORD_MAX_LENGTH = 20;

        public void validate(Object obj, Errors errors) {
            LOG.debug("Validate: " + obj + " " + errors);
            if (obj instanceof LoginCommand) {
                LoginCommand loginCommand = (LoginCommand) obj;
    
                // validate username
                if (StringUtils.isEmpty(loginCommand.getUsername())) {
                    errors.rejectValue(USERNAME_PARAM, "com_intalio_bpms_console_username_required");
                } else if (loginCommand.getUsername().length() < USERNAME_MIN_LENGTH) {
                    errors.rejectValue(USERNAME_PARAM, "com_intalio_bpms_console_username_less",
                            new Object[] { USERNAME_MIN_LENGTH }, null);
                } else if (loginCommand.getUsername().length() > USERNAME_MAX_LENGTH) {
                    errors.rejectValue(USERNAME_PARAM, "com_intalio_bpms_console_username_more",
                            new Object[] { USERNAME_MAX_LENGTH }, null);
                }
    
                // validate password
                if (StringUtils.isEmpty(loginCommand.getPassword())) {
                    errors.rejectValue(PASSWORD_PARAM, "com_intalio_bpms_console_password_required");
                } else if (loginCommand.getPassword().length() < PASSWORD_MIN_LENGTH) {
                    errors.rejectValue(PASSWORD_PARAM, "com_intalio_bpms_console_password_less",
                            new Object[] { PASSWORD_MIN_LENGTH }, null);
                } else if (loginCommand.getPassword().length() > PASSWORD_MAX_LENGTH) {
                    errors.rejectValue(PASSWORD_PARAM, "com_intalio_bpms_console_password_more",
                            new Object[] { PASSWORD_MAX_LENGTH }, null);
                }
            }
        }

        public boolean supports(Class clazz) {
            return LoginCommand.class.equals(clazz);
        }
    }

}