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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Syslog message as defined in <a href="https://tools.ietf.org/html/rfc5424">RFC 5424 - The Syslog Protocol</a>.
 *
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class SyslogMessage {
    public final static String SP = " ";
    public final static String NILVALUE = "-";
    protected final static SimpleDateFormat rfc3339DateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US) {
        {
            setTimeZone(TimeZone.getTimeZone("GMT"));
        }
    };
    private final static Lock lock = new ReentrantLock();
    private static long lastFormattedTimestampTimeInMillis;
    private static String lastFormattedTimestampValue;
    private SyslogFacility facility;
    private SyslogSeverity severity;
    private Long timestamp;
    private String hostname;
    private String appName;
    private String procId;
    private String msgId;
    private String msg;

    protected static String format(long time) {
        lock.lock();
        try {
            if (time != lastFormattedTimestampTimeInMillis) {
                lastFormattedTimestampTimeInMillis = time;
                lastFormattedTimestampValue = rfc3339DateFormat.format(new Date(lastFormattedTimestampTimeInMillis));
            }
            return lastFormattedTimestampValue;
        } finally {
            lock.unlock();
        }
    }

    public SyslogFacility getFacility() {
        return facility;
    }

    public void setFacility(SyslogFacility facility) {
        this.facility = facility;
    }

    public SyslogMessage withFacility(SyslogFacility facility) {
        this.facility = facility;
        return this;
    }

    public SyslogSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(SyslogSeverity severity) {
        this.severity = severity;
    }

    public SyslogMessage withSeverity(SyslogSeverity severity) {
        this.severity = severity;
        return this;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public SyslogMessage withTimestamp(long timestamp) {
        this.timestamp = timestamp;
        return this;
    }

    public SyslogMessage withTimestamp(Date timestamp) {
        this.timestamp = (timestamp == null) ? null : timestamp.getTime();
        return this;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public SyslogMessage withHostname(String hostname) {
        this.hostname = hostname;
        return this;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public SyslogMessage withAppName(String appName) {
        this.appName = appName;
        return this;
    }

    public String getProcId() {
        return procId;
    }

    public void setProcId(String procId) {
        this.procId = procId;
    }

    public SyslogMessage withProcId(String procId) {
        this.procId = procId;
        return this;
    }

    public String getMsgId() {
        return msgId;
    }

    public void setMsgId(String msgId) {
        this.msgId = msgId;
    }

    public SyslogMessage withMsgId(String msgId) {
        this.msgId = msgId;
        return this;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public SyslogMessage withMsg(String msg) {
        this.msg = msg;
        return this;
    }

    public String toSyslogMessage() {

        int pri = facility.value() + severity.value();


        String structuredData = NILVALUE;


        String formattedMessage = "<" + pri + ">" +
                "1" + SP + // version
                format(timestamp == null ? System.currentTimeMillis() : timestamp) + SP +
                (hostname == null ? getLocalhostName() : hostname) + SP +
                (appName == null ? NILVALUE : appName) + SP +
                (procId == null ? NILVALUE : String.valueOf(procId)) + SP +
                (msgId == null ? NILVALUE : String.valueOf(msgId)) + SP +
                structuredData;
        if (msg != null) {
            formattedMessage += SP + msg;
        }
        return formattedMessage;
    }

    private String getLocalhostName() {
        String hostname;
        try {
            hostname = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            hostname = SyslogMessage.NILVALUE;
        }
        return hostname;
    }
}
