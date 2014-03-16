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

import com.cloudbees.tomcat.valves.IoUtils2;
import com.cloudbees.tomcat.valves.TomcatBaseTest;
import org.apache.catalina.deploy.FilterDef;
import org.apache.catalina.deploy.FilterMap;
import org.apache.catalina.startup.Tomcat;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.*;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

/**
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class PrivateAppFilterIntegratedTest extends TomcatBaseTest {
    String accessKey = "";
    String secretKey = "ze-secret";
    HttpHost httpHost;
    DefaultHttpClient httpClient = new DefaultHttpClient();

    PrivateAppFilter privateAppFilter = new PrivateAppFilter();

    @After
    @Override
    public void tearDown() throws Exception {
        httpClient.getConnectionManager().shutdown();
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        Tomcat tomcat = getTomcatInstance();

        // Must have a real docBase - just use temp
        org.apache.catalina.Context context = tomcat.addContext("", System.getProperty("java.io.tmpdir"));

        privateAppFilter = new PrivateAppFilter();
        privateAppFilter.setSecretKey(secretKey);
        privateAppFilter.setEnabled(true);

        FilterDef filterDef = new FilterDef();
        filterDef.setFilter(privateAppFilter);
        filterDef.setFilterName(PrivateAppFilter.class.getName());
        context.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName(PrivateAppFilter.class.getName());
        filterMap.addURLPattern("*");
        context.addFilterMap(filterMap);

        context.addFilterDef(filterDef);


        Tomcat.addServlet(context, "hello-servlet", new HttpServlet() {
            @Override
            protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
                System.out.println(req.getRequestURL());
                IoUtils2.flush(req.getInputStream(), System.out);
                Enumeration<String> headers = req.getHeaderNames();
                while (headers.hasMoreElements()) {
                    String header = headers.nextElement();
                    System.out.println("   " + header + ": " + req.getHeader(header));
                }
                resp.addHeader("x-response", "hello");
                resp.getWriter().println("Hello world!");
            }
        });
        context.addServletMapping("/*", "hello-servlet");



        tomcat.start();

        httpClient = new DefaultHttpClient();
        httpHost = new HttpHost("localhost", getPort());
    }

    @Test
    public void unauthenticated_request_is_redirected_to_login_page() throws Exception {
        System.out.println("unauthenticated_request_is_redirected_to_login_page");

        privateAppFilter.setAuthenticationEntryPoint(PrivateAppFilter.AuthenticationEntryPoint.BASIC_AUTH);

        HttpResponse response = httpClient.execute(httpHost, new HttpGet("/"));

        assertThat(response.getStatusLine().getStatusCode(), equalTo(HttpServletResponse.SC_UNAUTHORIZED));
        assertThat(response.containsHeader("WWW-Authenticate"), is(true));


        dumpHttpResponse(response);

        EntityUtils.consumeQuietly(response.getEntity());

    }

    @Test
    public void basic_authentication_scenario() throws Exception {
        System.out.println("basic_authentication_scenario");

        authentication_scenario(PrivateAppFilter.AuthenticationEntryPoint.BASIC_AUTH);
    }

    @Test
    public void http_header_authentication_scenario() throws Exception {
        System.out.println("http_header_authentication_scenario");
        authentication_scenario(PrivateAppFilter.AuthenticationEntryPoint.HTTP_HEADER_AUTH);
    }

    @Test
    public void http_parameter_authentication_scenario() throws Exception {
        System.out.println("http_parameter_authentication_scenario");
        authentication_scenario(PrivateAppFilter.AuthenticationEntryPoint.HTTP_PARAM_AUTH);
    }

    @Test
    public void form_authentication_scenario() throws Exception {
        System.out.println("form_authentication_scenario");

        privateAppFilter.setAuthenticationEntryPoint(PrivateAppFilter.AuthenticationEntryPoint.FORM_AUTH);

        {
            // ANONYMOUS REQUEST RENDERS LOGIN FORM
            HttpGet request = new HttpGet("/");
            HttpResponse response = httpClient.execute(httpHost, request);

            assertThat(response.getStatusLine().getStatusCode(), equalTo(HttpServletResponse.SC_OK));
            assertThat(response.containsHeader("WWW-Form-Authenticate"), is(true));

            dumpHttpResponse(response);

            EntityUtils.consumeQuietly(response.getEntity());
        }
        {
            // AUTHENTICATION REQUEST
            HttpPost request = new HttpPost(privateAppFilter.getAuthenticationUri());
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair("username", accessKey));
            nvps.add(new BasicNameValuePair("password", secretKey));
            request.setEntity(new UrlEncodedFormEntity(nvps, Consts.UTF_8));

            HttpResponse response = httpClient.execute(httpHost, request);

            assertThat(response.getStatusLine().getStatusCode(), equalTo(HttpServletResponse.SC_MOVED_TEMPORARILY));

            dumpHttpResponse(response);

            EntityUtils.consumeQuietly(response.getEntity());
        }
        {
            // ALREADY AUTHENTICATED REQUEST

            HttpGet request = new HttpGet("/");
            HttpResponse response = httpClient.execute(httpHost, request);

            assertThat(response.getStatusLine().getStatusCode(), equalTo(HttpServletResponse.SC_OK));
            assertThat(response.containsHeader("x-response"), is(true));

            dumpHttpResponse(response);

            EntityUtils.consumeQuietly(response.getEntity());
        }
    }

    private void authentication_scenario(PrivateAppFilter.AuthenticationEntryPoint authenticationEntryPoint) throws Exception {
        privateAppFilter.setAuthenticationEntryPoint(authenticationEntryPoint);

        {
            // AUTHENTICATION REQUEST
            HttpRequest request;
            switch (authenticationEntryPoint) {
                case BASIC_AUTH:
                    request = new HttpGet("/");
                    request.addHeader("Authorization", buildBasicAuthHeader());
                    break;
                case HTTP_PARAM_AUTH:
                    URI uri = new URIBuilder("/").addParameter(privateAppFilter.getAuthenticationParameterName(), secretKey).build();
                    request = new HttpGet(uri);
                    break;
                case HTTP_HEADER_AUTH:
                    request = new HttpGet("/");
                    request.addHeader(privateAppFilter.getAuthenticationHeaderName(), secretKey);
                    break;
                default:
                    throw new IllegalStateException();
            }
            HttpResponse response = httpClient.execute(httpHost, request);

            assertThat(response.getStatusLine().getStatusCode(), equalTo(HttpServletResponse.SC_OK));
            assertThat(response.containsHeader("x-response"), is(true));

            dumpHttpResponse(response);

            EntityUtils.consumeQuietly(response.getEntity());
        }

        {
            // ALREADY AUTHENTICATED REQUEST
            HttpGet request = new HttpGet("/");
            HttpResponse response = httpClient.execute(httpHost, request);

            assertThat(response.getStatusLine().getStatusCode(), equalTo(HttpServletResponse.SC_OK));
            assertThat(response.containsHeader("x-response"), is(true));

            dumpHttpResponse(response);

            EntityUtils.consumeQuietly(response.getEntity());
        }
    }

    @Test
    public void pre_emptive_basic_authentication_scenario() throws IOException {
        System.out.println("pre_emptive_basic_authentication_scenario");

        privateAppFilter.setAuthenticationEntryPoint(PrivateAppFilter.AuthenticationEntryPoint.BASIC_AUTH);

        httpClient.getCredentialsProvider().setCredentials(
                new AuthScope(httpHost.getHostName(), httpHost.getPort()),
                new UsernamePasswordCredentials(accessKey, secretKey));

        // Create AuthCache instance
        AuthCache authCache = new BasicAuthCache();
        // Generate BASIC scheme object and add it to the local auth cache
        BasicScheme basicAuth = new BasicScheme();
        authCache.put(httpHost, basicAuth);

        // Add AuthCache to the execution context
        BasicHttpContext localcontext = new BasicHttpContext();
        localcontext.setAttribute(ClientContext.AUTH_CACHE, authCache);

        HttpGet httpget = new HttpGet("/");


        for (int i = 0; i < 3; i++) {
            HttpResponse response = httpClient.execute(httpHost, httpget, localcontext);
            assertThat(response.getStatusLine().getStatusCode(), equalTo(HttpServletResponse.SC_OK));
            assertThat(response.containsHeader("x-response"), is(true));

            dumpHttpResponse(response);

            EntityUtils.consumeQuietly(response.getEntity());
        }

    }

    private String buildBasicAuthHeader() {
        return "Basic " + Base64.encodeBase64String((accessKey + ":" + secretKey).getBytes());
    }

    private void dumpHttpResponse(HttpResponse anonymousRequest) {
        System.out.println("------");
        System.out.println(anonymousRequest.getStatusLine());
        for (Header header : anonymousRequest.getAllHeaders()) {
            System.out.println(header);
        }
    }

    /*
    http://www.hostettler.net/blog/2012/04/09/embedded-jee-web-application-integration-testing-using-tomcat-7/
     */
}
