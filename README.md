# CloudBees Web Container Extras

CloudBees add-ons for web containers.


## PrivateAppValve

### Valve Configuration

 * `secretKey`: the secret key used to authenticate users. **WARNING**: this secret key must be complex to not be guessed! **Mandatory**
 * `authenticationEntryPoint`: type of authentication (`FORM_AUTH`, `BASIC_AUTH`, `HTTP_PARAM_AUTH` or `HTTP_HEADER_AUTH`)
 * `authenticationParameterName`: named of the HTTP parameter used to pass the secret key when using `HTTP_PARAM_AUTH`. Optional, default `__cb_auth`.
 * `authenticationHeaderName`: named of the HTTP header to pass the secret key when using `HTTP_HEADER_AUTH`. Optional, default `__cb_auth`.
 * `authenticationUri`: URI used to submit the authentication form when using `FORM_AUTH`. Optional, default `/__cb_auth`.
 * `authenticationCookieName`: named of the HTTP cookie in which is persisted the successful authentication. Optional, default `__cb_auth`.
 * `enabled`: enable/disable flag. Optional, default `true`
 * `realmName`: name of the realm used in authentication messages. Optional, default `CloudBees`
 * `ignoredUriRegexp`: regexp of URIs to ignore when checking for authentication. Optional, default `/favicon\.ico`

### Form Based Authentication

#### Basic Configuration

```xml
   <Valve className="com.cloudbees.tomcat.valves.PrivateAppValve"
      secretKey="cloudbees-super-secret-key"
      authenticationEntryPointName="FORM_AUTH" />
```

### HTTP Header Based Authentication

#### Basic Configuration

```xml
   <Valve className="com.cloudbees.tomcat.valves.PrivateAppValve"
      secretKey="cloudbees-super-secret-key"
      authenticationEntryPointName="HTTP_HEADER_AUTH" />
```

#### Sample

```
curl -v --header __cb_auth:cloudbees-super-secret-key http://localhost:8080/
* About to connect() to localhost port 8080 (#0)
*   Trying ::1...
* connected
* Connected to localhost (::1) port 8080 (#0)
> GET / HTTP/1.1
> User-Agent: curl/7.24.0 (x86_64-apple-darwin12.0) libcurl/7.24.0 OpenSSL/0.9.8x zlib/1.2.5
> Host: localhost:8080
> Accept: */*
> __cb_auth:cloudbees-super-secret-key
>
< HTTP/1.1 200 OK
< Server: Apache-Coyote/1.1
< Set-Cookie: __cb_auth=-1758681927; Path=/; HttpOnly
< Content-Type: text/html;charset=ISO-8859-1
< Transfer-Encoding: chunked
< Date: Sat, 27 Jul 2013 12:46:20 GMT
<
```


### HTTP Parameter Based Authentication

#### Basic Configuration

```xml
   <Valve className="com.cloudbees.tomcat.valves.PrivateAppValve"
      secretKey="cloudbees-super-secret-key"
      authenticationEntryPointName="HTTP_PARAM_AUTH" />
```

#### Sample

```
curl -v http://localhost:8080/?__cb_auth=cloudbees-super-secret-key
* About to connect() to localhost port 8080 (#0)
*   Trying ::1...
* connected
* Connected to localhost (::1) port 8080 (#0)
> GET /?__cb_auth=cloudbees-super-secret-key HTTP/1.1
> User-Agent: curl/7.24.0 (x86_64-apple-darwin12.0) libcurl/7.24.0 OpenSSL/0.9.8x zlib/1.2.5
> Host: localhost:8080
> Accept: */*
>
< HTTP/1.1 200 OK
< Server: Apache-Coyote/1.1
< Set-Cookie: __cb_auth=-1758681927; Path=/; HttpOnly
< Content-Type: text/html;charset=ISO-8859-1
< Transfer-Encoding: chunked
< Date: Sat, 27 Jul 2013 12:42:05 GMT
<
```

### Management and Monitoring

The PrivateAppValve is exposed as a JMX MBean with ObjectName `Catalina:type=Valve,host=localhost,name=PrivateAppValve`
where `host` is the name of the Tomcat host under which the valve is deployed.

In addition to read/write access to configuration parameters, the MBean given access to stats:

* `authenticationSuccessCount`: Counter of successful authentications
* `authenticationFailureCount`: Counter of failed authentications

### Audit & Security

* Authentication failures are logged with the a warning message indicating the source IP address. Sample:

   ```
Jul 27, 2013 3:44:05 PM com.cloudbees.tomcat.valves.PrivateAppValve onAuthenticationFailure
WARNING: Failed authentication from ip address 127.0.0.1 on entry point:FORM_AUTH
```

* Authentication success are logged with an info message indicating the source IP address. Sample:

   ```
Jul 27, 2013 3:44:10 PM com.cloudbees.tomcat.valves.PrivateAppValve onAuthenticationSuccess
INFO: Successful authentication from ip address 127.0.0.1 on entry point FORM_AUTH
```

### Troubleshooting

In `$CATALINA_BASE/conf/logging.properties`, enable logger `com.cloudbees.tomcat.valves.PrivateAppValve`:

```
com.cloudbees.tomcat.valves.PrivateAppValve.level=FINEST
```

### FAQ

#### Where should I declare the PrivateAppValve

The PrivateAppValve should be declared just after the RemoteIpValve if used and after the AccesLogValve.

#### Why so many authentication entry points

It may convenient to use form authentication for many human facing applications (`FORM_AUTH`).

Other types of applications involving API / web services apps will probably prefer authentication mechanisms
which allow no interactive-authentication such as `HTTP_PARAM_AUTH`, `HTTP_HEADER_AUTH` or `HTTP_BASIC_AUTH`.

`HTTP_BASIC_AUTH` will cause interferences if the protected application also uses Basic Authentication.
