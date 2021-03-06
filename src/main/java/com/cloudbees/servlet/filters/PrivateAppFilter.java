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
package com.cloudbees.servlet.filters;

import com.cloudbees.Strings2;

import javax.annotation.Nonnull;
import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Private Application Filter. Requires to know a scret to access to the application.
 * <p/>
 * <h2>Filter Init Parameters</h2>
 * <p/>
 * <table>
 * <tr><th>Init Parameter</th><th>Description</th></tr>
 * <tr><td><code>secretKey</code></td><td>the secret key used to authenticate users. **WARNING**: this secret key must be strong to not be guessed! **Mandatory**</td></tr>
 * <tr><td><code>authenticationEntryPointName</code></td><td>type of authentication (`FORM_AUTH`, `BASIC_AUTH`, `HTTP_PARAM_AUTH` or `HTTP_HEADER_AUTH`)</td></tr>
 * <tr><td><code>authenticationParameterName</code></td><td>name of the HTTP parameter used to pass the secret key when using `HTTP_PARAM_AUTH`. Optional, default `__cb_auth`.</td></tr>
 * <tr><td><code>authenticationHeaderName</code></td><td>name of the HTTP header to pass the secret key when using `HTTP_HEADER_AUTH`. Optional, default `x-cb-auth`.</td></tr>
 * <tr><td><code>authenticationUri</code></td><td>URI used to submit the authentication form when using `FORM_AUTH`. Optional, default `/__cb_auth`.</td></tr>
 * <tr><td><code>authenticationCookieName</code></td><td>name of the HTTP cookie in which is persisted the successful authentication. Optional, default `__cb_auth`.</td></tr>
 * <tr><td><code>enabled</code></td><td>enable/disable flag. Optional, default `true`</td></tr>
 * <tr><td><code>realmName</code></td><td>name of the realm used in authentication messages. Optional, default `CloudBees`</td></tr>
 * <tr><td><code>ignoredUriRegexp</code></td><td>regexp of URIs to ignore when checking for authentication. Optional, default `/favicon\.ico`</td></tr>
 * </table>
 * <p/>
 * <h2>Form Authentication</h2>
 * <p/>
 * <p>Default form submission URI: {@value #FORM_AUTH_DEFAULT_URI}.</p>
 * <p/>
 * <code><pre>
 * &lt;filter&gt;
 *   &lt;filter-name&gt;PrivateAppFilter&lt;/filter-name&gt;
 *   &lt;filter-class&gt;com.cloudbees.servlet.filters.PrivateAppFilter&lt;/filter-class&gt;
 *   &lt;init-param&gt;
 *     &lt;param-name&gt;secretKey&lt;/param-name&gt;
 *     &lt;param-value&gt;12345&lt;/param-value&gt;
 *   &lt;/init-param&gt;
 *   &lt;init-param&gt;
 *     &lt;param-name&gt;authenticationEntryPointName&lt;/param-name&gt;
 *     &lt;param-value&gt;FORM_AUTH&lt;/param-value&gt;
 *   &lt;/init-param&gt;
 * &lt;/filter&gt;
 * &lt;filter-mapping&gt;
 *   &lt;filter-name&gt;PrivateAppFilter&lt;/filter-name&gt;
 *   &lt;url-pattern&gt;*&lt;/url-pattern&gt;
 * &lt;/filter-mapping&gt;
 * </pre></code>
 * <p/>
 * <h2>Basic Authentication</h2>
 * <p/>
 * <code><pre>
 *   &lt;init-param&gt;
 *     &lt;param-name&gt;authenticationEntryPointName&lt;/param-name&gt;
 *     &lt;param-value&gt;BASIC_AUTH&lt;/param-value&gt;
 *   &lt;/init-param&gt;
 * &lt;/pre&gt;&lt;/code&gt;
 * &lt;h2&gt;HTTP Parameter Authentication&lt;/h2&gt;
 * &lt;p&gt;Default param name: {@value #HTTP_PARAM_AUTH_DEFAULT_NAME}.&lt;/p&gt;
 * &lt;code&gt;&lt;pre&gt;
 *   &lt;init-param&gt;
 *     &lt;param-name&gt;authenticationEntryPointName&lt;/param-name&gt;
 *     &lt;param-value&gt;HTTP_PARAM_AUTH&lt;/param-value&gt;
 *   &lt;/init-param&gt;
 * </pre></code>
 * <p/>
 * <h2>HTTP Header Authentication</h2>
 * <p/>
 * <p>Default header name: {@value #HTTP_HEADER_AUTH_DEFAULT_NAME}.</p>
 * <p/>
 * <code><pre>
 *   &lt;init-param&gt;
 *     &lt;param-name&gt;authenticationEntryPointName&lt;/param-name&gt;
 *     &lt;param-value&gt;HTTP_HEADER_AUTH&lt;/param-value&gt;
 *   &lt;/init-param&gt;
 * </pre></code>
 *
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class PrivateAppFilter implements Filter {
    public static final String SYSTEM_PROPERTY_NAME_PREFIX = "privateApp.";
    public static final String PARAM_NAME_SECRET_KEY = "secretKey";
    public static final String PARAM_NAME_AUTHENTICATION_ENTRY_POINT_NAME = "authenticationEntryPointName";
    public static final String PARAM_NAME_AUTHENTICATION_PARAMETER_NAME = "authenticationParameterName";
    public static final String PARAM_NAME_AUTHENTICATION_COOKIE_NAME = "authenticationCookieName";
    public static final String PARAM_NAME_AUTHENTICATION_HEADER_NAME = "authenticationHeaderName";
    public static final String PARAM_NAME_AUTHENTICATION_AUTHENTICATION_URI = "authenticationUri";
    public static final String PARAM_NAME_ENABLED = "enabled";
    public static final String PARAM_NAME_REALM_NAME = "realmName";
    public static final String PARAM_NAME_IGNORED_URI_REGEXP = "ignoredUriRegexp";
    public static final String PARAM_NAME_SEED = "seed";

    public static final String HTTP_PARAM_AUTH_DEFAULT_NAME = "__cb_auth";
    public static final String HTTP_HEADER_AUTH_DEFAULT_NAME = "x-cb-auth";
    public static final String FORM_AUTH_DEFAULT_URI = "/__cb_auth";
    public static final String AUTH_REALM_DEFAULT_NAME = "CloudBees";
    /**
     * Logger
     */
    private static final Logger log = Logger.getLogger(PrivateAppFilter.class.getName());
    public static final String AUTH_COOKIE_DEFAULT_NAME = "__cb_auth";

    private String authenticationParameterName = HTTP_PARAM_AUTH_DEFAULT_NAME;
    private String authenticationCookieName = AUTH_COOKIE_DEFAULT_NAME;
    private String authenticationHeaderName = HTTP_HEADER_AUTH_DEFAULT_NAME;
    private String authenticationUri = FORM_AUTH_DEFAULT_URI;
    private boolean enabled = true;
    private String secretKey;
    private String seed = PrivateAppFilter.class.getName();
    private AuthenticationEntryPoint authenticationEntryPoint = AuthenticationEntryPoint.FORM_AUTH;
    private String realmName = AUTH_REALM_DEFAULT_NAME;
    private Pattern ignoredUriRegexp = Pattern.compile("/favicon\\.ico");

    private final AtomicInteger authenticationSuccessCount = new AtomicInteger();
    private final AtomicInteger authenticationFailureCount = new AtomicInteger();

    public PrivateAppFilter() {
        authenticationParameterName = System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_AUTHENTICATION_PARAMETER_NAME, HTTP_PARAM_AUTH_DEFAULT_NAME);
        authenticationCookieName = System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_AUTHENTICATION_COOKIE_NAME, AUTH_COOKIE_DEFAULT_NAME);
        authenticationHeaderName = System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_AUTHENTICATION_HEADER_NAME, HTTP_HEADER_AUTH_DEFAULT_NAME);
        authenticationUri = System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_AUTHENTICATION_AUTHENTICATION_URI, FORM_AUTH_DEFAULT_URI);
        enabled = Boolean.valueOf(System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_ENABLED, "true"));
        secretKey = System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_SECRET_KEY, null);
        seed = System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_SEED, PrivateAppFilter.class.getName());
        authenticationEntryPoint = AuthenticationEntryPoint.valueOf(System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_AUTHENTICATION_ENTRY_POINT_NAME, AuthenticationEntryPoint.FORM_AUTH.name()));
        realmName = System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_REALM_NAME, AUTH_REALM_DEFAULT_NAME);
        ignoredUriRegexp = Pattern.compile(System.getProperty(
                SYSTEM_PROPERTY_NAME_PREFIX + PARAM_NAME_IGNORED_URI_REGEXP, "/favicon\\.ico"));

        if (this.secretKey == null) {
            this.enabled = false;
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

        Map<String, String> config = new HashMap<String, String>();
        for (String name : Collections.list(filterConfig.getInitParameterNames())) {
            config.put(name, filterConfig.getInitParameter(name));
        }

        if (config.containsKey(PARAM_NAME_AUTHENTICATION_PARAMETER_NAME))
            authenticationParameterName = config.get(PARAM_NAME_AUTHENTICATION_PARAMETER_NAME);

        if (config.containsKey(PARAM_NAME_AUTHENTICATION_COOKIE_NAME))
            authenticationCookieName = config.get(PARAM_NAME_AUTHENTICATION_COOKIE_NAME);

        if (config.containsKey(PARAM_NAME_AUTHENTICATION_HEADER_NAME))
            authenticationHeaderName = config.get(PARAM_NAME_AUTHENTICATION_HEADER_NAME);

        if (config.containsKey(PARAM_NAME_AUTHENTICATION_AUTHENTICATION_URI))
            authenticationUri = config.get(PARAM_NAME_AUTHENTICATION_AUTHENTICATION_URI);

        if (config.containsKey(PARAM_NAME_ENABLED))
            enabled = Boolean.valueOf(config.get(PARAM_NAME_ENABLED));

        if (config.containsKey(PARAM_NAME_SECRET_KEY)) {
            secretKey = config.get(PARAM_NAME_SECRET_KEY);
            enabled = true;
        }

        if (config.containsKey(PARAM_NAME_SEED))
            seed = config.get(PARAM_NAME_SEED);

        if (config.containsKey(PARAM_NAME_AUTHENTICATION_ENTRY_POINT_NAME))
            authenticationEntryPoint = AuthenticationEntryPoint.valueOf(config.get(PARAM_NAME_AUTHENTICATION_ENTRY_POINT_NAME));

        if (config.containsKey(PARAM_NAME_REALM_NAME))
            realmName = config.get(PARAM_NAME_REALM_NAME);

        if (config.containsKey(PARAM_NAME_IGNORED_URI_REGEXP))
            ignoredUriRegexp = Pattern.compile(config.get(PARAM_NAME_IGNORED_URI_REGEXP));

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    @Override
    public void destroy() {

    }

    public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (log.isLoggable(Level.FINER)) {
            log.finer("State: " + this);
            log.finer("Request: url=" + request.getRequestURL() + ", queryString=" + request.getQueryString());
            for (Enumeration<String> enu = request.getHeaderNames(); enu.hasMoreElements(); ) {
                String header = enu.nextElement();
                log.finer("Request header " + header + "=" + request.getHeader(header));
            }
        }

        try {
            if (!enabled) {
                if (log.isLoggable(Level.FINE))
                    log.fine("skip valve for request " + request.getRequestURI());
            } else if (isBanned(request)) {

                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User Agent is banned ");
                return;

            } else if (isIgnoredRequest(request)) {
                if (log.isLoggable(Level.FINE))
                    log.fine("skip authentication check for request " + request.getRequestURI());

            } else if (isAlreadyAuthenticated(request, response)) {
                if (log.isLoggable(Level.FINE))
                    log.fine("user-agent is already authenticated, pass through request " + request.getRequestURI());

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
            log.log(Level.WARNING, "Exception processing authentication on request " + request.getRequestURI(), e);
            throw e;
        }
        chain.doFilter(request, response);
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
                        authorization = "basic " + DatatypeConverter.printBase64Binary((username + ":" + password).getBytes(Strings2.ISO_8859_1));
                    } else {
                        log.warning("Ignore authentication on URI '" + request.getRequestURI() + "' with non 'post' method '" + request.getMethod() + "'");
                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid  credentials submitted with non POST method");
                        return AuthenticationResult.FAILURE;
                    }
                } else {
                    authorization = null;
                    log.finer("Ignore non form-authentication request");
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
            if (log.isLoggable(Level.FINE)) {
                log.fine("No authentication token found, request '" + request.getRequestURI() + "' is not an authentication request");
            }
            initiateAuthentication(response);
            return AuthenticationResult.FAILURE;
        }


        String username;
        String password;
        if (Strings2.startsWithIgnoreCase(authorization, "basic ")) {

            byte[] decoded = javax.xml.bind.DatatypeConverter.parseBase64Binary(authorization.substring("basic ".length()));

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
        log.warning("Failed authentication from ip address " + request.getRemoteAddr() + " on entry point:" + authenticationEntryPoint);
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
                    if (log.isLoggable(Level.FINE))
                        log.fine("Valid authentication cookie '" + cookie.getName() + "'");
                    return true;
                } else {
                    log.info("Invalid authentication cookie '" + cookie.getName() + "', remove it and continue");
                    removeAuthenticationCookie(response);
                }
            } else {
                if (log.isLoggable(Level.FINER))
                    log.finer("Skip non-authenticating cookie " + cookie.getName());
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
        try {
            this.authenticationEntryPoint = AuthenticationEntryPoint.valueOf(authenticationEntryPoint);
        } catch (RuntimeException e) {
            new IllegalArgumentException("Unsupported authenticationEntryPoint '" + authenticationEntryPoint + "', not one of " + Arrays.asList(AuthenticationEntryPoint.values()), e);
        }
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
