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
package com.cloudbees.tomcat.listener;

import org.apache.catalina.*;
import org.apache.catalina.deploy.ContextResource;
import org.apache.catalina.deploy.ContextResourceLink;
import org.apache.catalina.deploy.NamingResources;
import org.apache.catalina.deploy.ResourceBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Dump the JNDI context of the server/context in the logs.
 * <p/>
 * <strong>WARNING: this valve does NOT work with Tomcat 8</strong>
 *
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class JndiContextDumperListener implements LifecycleListener {

    private static final Log log = LogFactory.getLog(JndiContextDumperListener.class);
    private Object source;
    private Map<String, String> resourceTypeDisplayName = new HashMap<String, String>() {
        {
            put("javax.sql.DataSource", "data source");
            put("javax.mail.Session", "mail session");
        }
    };

    protected String getResourceTypeDisplayName(ResourceBase resource) {
        String name = resourceTypeDisplayName.get(resource.getType());
        if (name == null) {
            name = resource.getType();
        }
        return name;
    }

    @Override
    public void lifecycleEvent(LifecycleEvent event) {
        if (!Lifecycle.BEFORE_START_EVENT.equals(event.getType())) {
            return;
        }

        source = event.getSource();

        if (source instanceof Context) {
            Context context = (Context) source;
            NamingResources namingResources = context.getNamingResources();

            String contextName = context.getName();
            if (!contextName.startsWith("/"))
                contextName = "/" + contextName;
            Host host = (Host) context.getParent();

            for (ContextResource resource : namingResources.findResources()) {
                log.info("Created " + getResourceTypeDisplayName(resource) + " with JNDI binding java:comp/env/" + resource.getName() + " on host=" + host.getName() + ", path=" + contextName);
            }
            for (ContextResourceLink resource : namingResources.findResourceLinks()) {
                log.info("Created " + getResourceTypeDisplayName(resource) + " with JNDI binding java:comp/env/" + resource.getName() + " on host=" + host.getName() + ", path=" + contextName);
            }
        } else if (source instanceof Server) {
            Server server = (Server) source;
            NamingResources namingResources = server.getGlobalNamingResources();

            for (ContextResource resource : namingResources.findResources()) {
                log.info("Created " + getResourceTypeDisplayName(resource) + " with JNDI binding java:comp/env/" + resource.getName() + " on server");
            }
            for (ContextResourceLink resource : namingResources.findResourceLinks()) {
                log.info("Created " + getResourceTypeDisplayName(resource) + " with JNDI binding java:comp/env/" + resource.getName() + " on server");
            }
        } else {
            return;
        }
    }


}
