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

import com.cloudbees.syslog.SyslogFacility;
import com.cloudbees.syslog.SyslogMessage;
import com.cloudbees.syslog.SyslogMessageUdpSender;
import com.cloudbees.syslog.SyslogSeverity;
import org.apache.catalina.AccessLog;
import org.apache.catalina.LifecycleException;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Access Log Valve that sends the access logs to a Syslog server.
 *
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class SyslogAccessLogValve extends AccessLogValveBase implements AccessLog {

    private static final Log log = LogFactory.getLog(SyslogAccessLogValve.class);

    private SyslogMessageUdpSender messageSender = new SyslogMessageUdpSender();

    @Override
    protected synchronized void startInternal() throws LifecycleException {
        super.startInternal();
        log.info("SyslogAccessLogValve configured to send access logs to the syslog server " + messageSender.getHostname() + ":" + messageSender.getPort());
    }

    @Override
    public void log(String message) {
        try {
            messageSender.sendMessage(message);
        } catch (IOException e) {
            log.error("Exception sending Syslog message", e);
        }
    }

    public void sendMessage(SyslogMessage message) throws IOException {
        messageSender.sendMessage(message);
    }

    public int getSendErrorCount() {
        return messageSender.getSendErrorCount();
    }

    public int getSendCount() {
        return messageSender.getSendCount();
    }

    public long getSendDurationInNanos() {
        return messageSender.getSendDurationInNanos();
    }

    public long getSendDurationInMillis() {
        return TimeUnit.MILLISECONDS.convert(getSendDurationInNanos(), TimeUnit.NANOSECONDS);
    }

    public String getAppName() {
        return messageSender.getDefaultAppName();
    }

    public void setAppName(String appName) {
        messageSender.setDefaultAppName(appName);
    }

    public String getSeverity() {
        return messageSender.getDefaultSeverity() == null ? null : messageSender.getDefaultSeverity().label();
    }

    public void setSeverity(String severity) {
        messageSender.setDefaultSeverity(SyslogSeverity.fromLabel(severity));
    }

    public String getHostName() {
        return messageSender.getDefaultHostName();
    }

    public int getSyslogServerPort() {
        return messageSender.getPort();
    }

    public void setSyslogServerPort(int syslogServerPort) {
        messageSender.setPort(syslogServerPort);
    }

    public String getFacility() {
        return messageSender.getDefaultFacility() == null ? null : messageSender.getDefaultFacility().label();
    }

    public void setFacility(String facility) {
        messageSender.setDefaultFacility(SyslogFacility.fromLabel(facility));
    }

    public String getSyslogServerHostname() {
        return messageSender.getHostname();
    }

    public void setSyslogServerHostname(String syslogServerHostname) {
        messageSender.setHostname(syslogServerHostname);
    }

    public void setSyslogMessageHostname(String messageHostname) {
        messageSender.setDefaultMessageHostName(messageHostname);
    }
}
