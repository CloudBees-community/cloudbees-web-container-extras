/*
 * Copyright 2010-2013, CloudBees Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloudbees.tomcat.valves;

import com.cloudbees.Strings2;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.codec.binary.Base64;

import javax.annotation.Nonnull;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * <h2>Form Authentication</h2>
 * <code><pre>
 *    <lt;Valve className="com.cloudbees.tomcat.valves.PrivateAppValve"
 *        secretKey="MY_VERY_COMPLEX_SECRET"
 *        authenticationEntryPointName="FORM_AUTH"/>
 * </pre></code>
 * <h2>Basic Authentication</h2>
 * <code><pre>
 *    <lt;Valve className="com.cloudbees.tomcat.valves.PrivateAppValve"
 *        secretKey="MY_VERY_COMPLEX_SECRET"
 *        authenticationEntryPointName="BASIC_AUTH"/>
 * </pre></code>
 * <h2>HTTP Parameter Authentication</h2>
 * <code><pre>
 *    <lt;Valve className="com.cloudbees.tomcat.valves.PrivateAppValve"
 *        secretKey="MY_VERY_COMPLEX_SECRET"
 *        authenticationEntryPointName="HTTP_PARAM_AUTH"/>
 * </pre></code>
 * <h2>HTTP Header Authentication</h2>
 * <code><pre>
 *    <lt;Valve className="com.cloudbees.tomcat.valves.PrivateAppValve"
 *        secretKey="MY_VERY_COMPLEX_SECRET"
 *        authenticationEntryPointName="HTTP_HEADER_AUTH"/>
 * </pre></code>
 *
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class PrivateAppValve extends ValveBase {
    /**
     * The descriptive information related to this implementation.
     */
    private static final String info = "com.cloudbees.tomcat.valves.PrivateAppValve/1.0";
    /**
     * Logger
     */
    private static final Log log = LogFactory.getLog(PrivateAppValve.class);
    private final AtomicInteger authenticationSuccessCount = new AtomicInteger();
    private final AtomicInteger authenticationFailureCount = new AtomicInteger();
    private String authenticationParameterName = "__cb_auth";
    private String authenticationCookieName = "__cb_auth";
    private String authenticationHeaderName = "__cb_auth";
    private String authenticationUri = "/__cb_auth";
    private boolean enabled = true;
    private String secretKey;
    private String seed = PrivateAppValve.class.getName();
    private AuthenticationEntryPoint authenticationEntryPoint = AuthenticationEntryPoint.BASIC_AUTH;
    private String realmName = "CloudBees";
    private Pattern ignoredUriRegexp = Pattern.compile("/favicon\\.ico");

    public PrivateAppValve() {
        super(true);
    }

    @Override
    public void invoke(Request tomcatRequest, Response tomcatResponse) throws IOException, ServletException {

        HttpServletRequest request = tomcatRequest.getRequest();
        HttpServletResponse response = tomcatResponse.getResponse();

        if (log.isTraceEnabled()) {
            log.trace("State: " + this);
            log.trace("Request: url=" + request.getRequestURL() + ", queryString=" + request.getQueryString());
            for (Enumeration<String> enu = request.getHeaderNames(); enu.hasMoreElements(); ) {
                String header = enu.nextElement();
                log.trace("Request header " + header + "=" + request.getHeader(header));
            }
        }

        try {
            if (!enabled) {
                if (log.isDebugEnabled())
                    log.debug("skip valve for request " + request.getRequestURI());
            } else if (isBanned(request)) {

                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User Agent is banned ");
                return;

            } else if (isIgnoredRequest(request)) {
                if (log.isDebugEnabled())
                    log.debug("skip authentication check for request " + request.getRequestURI());

            } else if (isAlreadyAuthenticated(request, response)) {
                if (log.isDebugEnabled())
                    log.debug("user-agent is already authenticated, pass through request " + request.getRequestURI());

            } else {

                AuthenticationResult authenticationResult = authenticate(request, response);

                switch (authenticationResult) {
                    case SUCCESS_INTERRUPT:
                    case FAILURE:
                        // ASSERT: Authenticator already set the appropriate
                        // HTTP status code, so we do not have to do anything
                        // special
                        return;
                    case SUCCESS_CONTINUE:
                    default:
                        // continue

                }
            }
        } catch (RuntimeException e) {
            log.error("Exception processing authentication on request " + tomcatRequest.getRequestURI(), e);
            throw e;
        }
        getNext().invoke(tomcatRequest, tomcatResponse);
    }

    protected boolean isBanned(HttpServletRequest request) {
        return false;
    }

    private void initiateAuthentication(HttpServletResponse response) throws IOException {

        switch (authenticationEntryPoint) {
            case BASIC_AUTH: {
                response.addHeader("WWW-Authenticate", "Basic realm=\"Private Application - " + realmName + "\"");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Not authenticated");
            }
            break;
            case HTTP_PARAM_AUTH: {
                response.setContentType("text/html");
                response.addHeader("WWW-Parameter-Authenticate", "realm=\"Private Application - " + realmName + "\", parameter=\"" + authenticationParameterName + "\"");
                response.addHeader("cache-control", "private,no-cache,no-store");
                String html = "<html>" +
                        "<head>" +
                        "  <title>Private Application - " + realmName + " - HTTP Parameter Authentication Required</title>" +
                        "</head>" +
                        "<body>" +
                        "<h1>Private Application - " + realmName + " - HTTP Parameter Authentication Required</h1>" +
                        "<p>Authentication with HTTP parameter \"" + authenticationParameterName + "\" is required.</p>" +
                        "<body>" +
                        "</html>";
                response.getWriter().append(html);
            }
            break;
            case FORM_AUTH: {
                response.setContentType("text/html");
                response.addHeader("WWW-Form-Authenticate", "realm=\"" + realmName + "\"");
                response.addHeader("cache-control", "private,no-cache,no-store");
                String html = "<html>" +
                        "<head>" +
                        "  <title>Private Application - " + realmName + "</title>" +
                        "</head>" +
                        "<body>" +
                        "<h1>Private Application - " + realmName + "</h1>" +
                        "<p>The URL you have requested is part of a privately deployed environment.</p>" +
                        "<p>Please enter then authentication token to sign in.</p>" +
                        "" +
                        "<form name='authentication' method='post' action='" + authenticationUri + "'>" +
                        "  <label id='lblPassword' for='password'>Secret Key</label> <input type='text' id='password' name='password' /><br/>" +
                        "  <input type='submit' id='submit' name='submit' value='Sign in'/><br/>" +
                        "</form>" +
                        "" +
                        "<body>" +
                        "</html>";
                response.getWriter().append(html);
            }
            break;
            case HTTP_HEADER_AUTH: {
                response.setContentType("text/html");
                response.addHeader("WWW-Header-Authenticate", "realm=\"Private Application - " + realmName + "\", header=\"" + authenticationHeaderName + "\"");
                response.addHeader("cache-control", "private,no-cache,no-store");
                String html = "<html>" +
                        "<head>" +
                        "  <title>Private Application - " + realmName + " - HTTP Header Authentication Required</title>" +
                        "</head>" +
                        "<body>" +
                        "<h1>Private Application - " + realmName + " - HTTP Header Authentication Required</h1>" +
                        "<p>Authentication with HTTP header \"" + authenticationHeaderName + "\" is required.</p>" +
                        "<body>" +
                        "</html>";
                response.getWriter().append(html);
            }
            break;
            default:
                throw new IllegalStateException("Unsupported authenticationEntryPoint " + authenticationEntryPoint);
        }
    }

    protected AuthenticationResult authenticate(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Validate any credentials already included with this request

        String authorization;
        switch (authenticationEntryPoint) {
            case FORM_AUTH:
                if (request.getRequestURI().equals(this.authenticationUri)) {
                    if ("post".equalsIgnoreCase(request.getMethod())) {
                        String username = request.getParameter("username");
                        String password = request.getParameter("password");
                        authorization = "basic " + new String(Base64.encodeBase64((username + ":" + password).getBytes(Strings2.ISO_8859_1)), Strings2.ISO_8859_1);
                    } else {
                        log.warn("Ignore authentication on URI '" + request.getRequestURI() + "' with non 'post' method '" + request.getMethod() + "'");
                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid  credentials submitted with non POST method");
                        return AuthenticationResult.FAILURE;
                    }
                } else {
                    authorization = null;
                    log.trace("Ignore non form-authentication request");
                }
                break;
            case BASIC_AUTH:
                authorization = request.getHeader("Authorization");
                break;
            case HTTP_PARAM_AUTH:
                authorization = request.getParameter(authenticationParameterName);
                break;
            case HTTP_HEADER_AUTH:
                authorization = request.getHeader(this.authenticationHeaderName);
                break;
            default:
                throw new IllegalStateException("Unsupported authenticationEntryPoint " + authenticationEntryPoint);
        }


        if (authorization == null || authorization.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No authentication token found, request '" + request.getRequestURI() + "' is not an authentication request");
            }
            initiateAuthentication(response);
            return AuthenticationResult.FAILURE;
        }


        String username;
        String password;
        if (Strings2.startsWithIgnoreCase(authorization, "basic ")) {

            byte[] decoded = Base64.decodeBase64(authorization.substring("basic ".length()));

            // Get username and password
            int colon = -1;
            for (int i = 0; i < decoded.length; i++) {
                if (decoded[i] == ':') {
                    colon = i;
                    break;
                }
            }

            if (colon < 0) {
                username = new String(decoded, Strings2.ISO_8859_1);
                password = null;
            } else {
                username = new String(
                        decoded, 0, colon, Strings2.ISO_8859_1);
                password = new String(
                        decoded, colon + 1, decoded.length - colon - 1,
                        Strings2.ISO_8859_1);
            }
        } else {
            username = "";
            password = authorization;
        }
        boolean authenticated = authenticate(username, password);

        AuthenticationResult authenticationResult;
        if (authenticated) {
            setAuthenticationCookie(username, password, response);
            onAuthenticationSuccess(request, username);
            if (authenticationEntryPoint.equals(AuthenticationEntryPoint.FORM_AUTH)) {
                // TODO invoke next valve with saved request
                response.sendRedirect("/");
                authenticationResult = AuthenticationResult.SUCCESS_INTERRUPT;
            } else {
                authenticationResult = AuthenticationResult.SUCCESS_CONTINUE;
            }
        } else {
            switch (authenticationEntryPoint) {
                case FORM_AUTH:
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    String html = "<html>" +
                            "<head>" +
                            "  <title>Private Application - " + realmName + " - Invalid Secret Key</title>" +
                            "</head>" +
                            "<body>" +
                            "<h1>Private Application - " + realmName + " - Invalid Secret Key</h1>" +
                            "<p>The secret key is invalid.</p>" +
                            "<body>" +
                            "</html>";
                    response.getWriter().println(html);
                    break;
                default:
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Private Application - " + realmName + " - Invalid  credentials");
            }
            onAuthenticationFailure(request, username);
            authenticationResult = AuthenticationResult.FAILURE;
        }
        return authenticationResult;
    }

    private void onAuthenticationFailure(HttpServletRequest request, String username) {
        log.warn("Failed authentication from ip address " + request.getRemoteAddr() + " on entry point:" + authenticationEntryPoint);
        this.authenticationFailureCount.incrementAndGet();
    }

    private void onAuthenticationSuccess(HttpServletRequest request, String username) {
        log.info("Successful authentication from ip address " + request.getRemoteAddr() + " on entry point " + authenticationEntryPoint);

        this.authenticationSuccessCount.incrementAndGet();
    }

    protected void setAuthenticationCookie(String username, String password, HttpServletResponse response) {
        Cookie cookie = new Cookie(getAuthenticationCookieName(), getSecretKeyHash());
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    protected void removeAuthenticationCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(getAuthenticationCookieName(), "");
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    /**
     * username is currently ignored
     *
     * @param username
     * @param password
     * @return <code>true</code> if the credentials are valid
     */
    protected boolean authenticate(@Nonnull String username, @Nonnull String password) {
        if (secretKey.equals(password)) {
            return true;
        } else {
            return false;
        }
    }

    protected boolean isAlreadyAuthenticated(HttpServletRequest request, HttpServletResponse response) {

        Cookie[] cookies = request.getCookies() == null ? new Cookie[0] : request.getCookies();
        for (Cookie cookie : cookies) {
            if (this.authenticationCookieName.equals(cookie.getName())) {

                if (getSecretKeyHash().equals(cookie.getValue())) {
                    if (log.isDebugEnabled())
                        log.debug("Valid authentication cookie '" + cookie.getName() + "'");
                    return true;
                } else {
                    if (log.isInfoEnabled())
                        log.info("Invalid authentication cookie '" + cookie.getName() + "', remove it and continue");
                    removeAuthenticationCookie(response);
                }
            } else {
                if (log.isTraceEnabled())
                    log.trace("Skip non-authenticating cookie " + cookie.getName());

            }
        }
        return false;
    }

    protected String getSecretKeyHash() {
        return String.valueOf((seed + ":" + secretKey).hashCode());
    }

    /**
     * request like 'favicon.ico' could skip authentication
     */
    protected boolean isIgnoredRequest(HttpServletRequest request) {
        boolean matches = ignoredUriRegexp.matcher(request.getRequestURI()).matches();

        return matches;
    }

    public String getAuthenticationCookieName() {
        return authenticationCookieName;
    }

    public void setAuthenticationCookieName(String authenticationCookieName) {
        this.authenticationCookieName = authenticationCookieName;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getSeed() {
        return seed;
    }

    public void setSeed(String seed) {
        this.seed = seed;
    }

    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public String getAuthenticationEntryPointName() {
        return authenticationEntryPoint == null ? null : authenticationEntryPoint.toString();
    }

    public void setAuthenticationEntryPointName(String authenticationEntryPoint) {
        this.authenticationEntryPoint = AuthenticationEntryPoint.valueOf(authenticationEntryPoint);
    }

    public String getAuthenticationHeaderName() {
        return authenticationHeaderName;
    }

    public void setAuthenticationHeaderName(String authenticationHeaderName) {
        this.authenticationHeaderName = authenticationHeaderName;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getRealmName() {
        return realmName;
    }

    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }

    public String getAuthenticationParameterName() {
        return authenticationParameterName;
    }

    public void setAuthenticationParameterName(String authenticationParameterName) {
        this.authenticationParameterName = authenticationParameterName;
    }

    public int getAuthenticationSuccessCount() {
        return authenticationSuccessCount.get();
    }

    public int getAuthenticationFailureCount() {
        return authenticationFailureCount.get();
    }

    public String getAuthenticationUri() {
        return authenticationUri;
    }

    public void setAuthenticationUri(String authenticationUri) {
        this.authenticationUri = authenticationUri;
    }

    public String getIgnoredUriRegexp() {
        return ignoredUriRegexp.pattern();
    }

    public void setIgnoredUriRegexp(String ignoredUriRegexp) {
        this.ignoredUriRegexp = Pattern.compile(ignoredUriRegexp);
    }

    /**
     * Return descriptive information about this Valve implementation.
     */
    @Override
    public String getInfo() {
        return (info);

    }

    @Override
    public String toString() {
        return "PrivateAppValve{" +
                "authenticationEntryPoint=" + authenticationEntryPoint +
                ", authenticationCookieName='" + authenticationCookieName + '\'' +
                ", authenticationHeaderName='" + authenticationHeaderName + '\'' +
                ", authenticationParameterName='" + authenticationParameterName + '\'' +
                ", realmName='" + realmName + '\'' +
                ", enabled=" + enabled +
                ", secretKey='" + secretKey + '\'' +
                ", seed='" + seed + '\'' +
                '}';
    }

    enum AuthenticationEntryPoint {FORM_AUTH, BASIC_AUTH, HTTP_HEADER_AUTH, HTTP_PARAM_AUTH}

    enum AuthenticationResult {SUCCESS_CONTINUE, SUCCESS_INTERRUPT, FAILURE}
}
