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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Syslog message sender over UDP.
 *
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class SyslogMessageUdpSender {
    private final static Charset UTF_8 = Charset.forName("UTF-8");
    public static final int DEFAULT_SYSLOG_PORT = 514;
    public static final String DEFAULT_SYSLOG_HOST = "localhost";
    protected final Logger logger = Logger.getLogger(getClass().getName());
    private final AtomicInteger sendErrorCounter = new AtomicInteger();
    private final AtomicInteger sendCounter = new AtomicInteger();
    private final AtomicLong sendDurationInNanosCounter = new AtomicLong();
    private int port = DEFAULT_SYSLOG_PORT;
    private String hostname = DEFAULT_SYSLOG_HOST;
    private DatagramSocket datagramSocket;
    private SyslogFacility defaultFacility = SyslogFacility.USER;
    private String defaultHostName;
    private String defaultAppName;
    private SyslogSeverity defaultSeverity = SyslogSeverity.INFORMATIONAL;

    public void sendMessage(SyslogMessage message) throws IOException {
        sendCounter.incrementAndGet();
        long nanosBefore = System.nanoTime();

        try {
            if (datagramSocket == null) {
                datagramSocket = new DatagramSocket();
            }

            InetSocketAddress address = new InetSocketAddress(hostname, port);

            String syslogMessageStr = message.toSyslogMessage();

            if (logger.isLoggable(Level.FINER)) {
                logger.finer("Send syslog message " + syslogMessageStr);
            }
            byte[] bytes = syslogMessageStr.getBytes(UTF_8);

            DatagramPacket packet = new DatagramPacket(bytes, bytes.length, address);
            datagramSocket.send(packet);
        } catch (IOException | RuntimeException e) {
            sendErrorCounter.incrementAndGet();
        } finally {
            sendDurationInNanosCounter.addAndGet(System.nanoTime() - nanosBefore);
        }

    }

    public void sendMessage(String message) throws IOException {

        SyslogMessage syslogMessage = new SyslogMessage()
                .withAppName(defaultAppName)
                .withFacility(defaultFacility)
                .withHostname(defaultHostName)
                .withSeverity(defaultSeverity)
                .withMsg(message);

        sendMessage(syslogMessage);
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public SyslogFacility getDefaultFacility() {
        return defaultFacility;
    }

    public void setDefaultFacility(SyslogFacility defaultFacility) {
        this.defaultFacility = defaultFacility;
    }

    public String getDefaultHostName() {
        return defaultHostName;
    }

    public void setDefaultMessageHostName(String defaultHostName) {
        this.defaultHostName = defaultHostName;
    }

    public String getDefaultAppName() {
        return defaultAppName;
    }

    public void setDefaultAppName(String defaultAppName) {
        this.defaultAppName = defaultAppName;
    }

    public SyslogSeverity getDefaultSeverity() {
        return defaultSeverity;
    }

    public void setDefaultSeverity(SyslogSeverity defaultSeverity) {
        this.defaultSeverity = defaultSeverity;
    }

    public int getSendErrorCount() {
        return sendErrorCounter.get();
    }

    public int getSendCount() {
        return sendCounter.get();
    }

    public long getSendDurationInNanos() {
        return sendDurationInNanosCounter.get();
    }
}
