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
package com.cloudbees.syslog;

import org.junit.Ignore;
import org.junit.Test;

import java.sql.Timestamp;

/**
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class SyslogMessageUdpSenderTest {

    @Ignore
    @Test
    public void send() throws Exception {
        SyslogMessageUdpSender messageSender = new SyslogMessageUdpSender();
        messageSender.setDefaultAppName("myapp");
        messageSender.setDefaultFacility(SyslogFacility.USER);
        messageSender.setDefaultSeverity(SyslogSeverity.INFORMATIONAL);
        messageSender.setHostname("localhost");
        messageSender.setPort(37486);
        messageSender.sendMessage("unit test message éèà " + getClass() + " - " + new Timestamp(System.currentTimeMillis()));
    }
}
