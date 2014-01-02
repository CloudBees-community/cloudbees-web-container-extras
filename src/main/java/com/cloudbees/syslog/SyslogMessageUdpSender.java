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
import java.net.*;
import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Syslog message sender over UDP.
 *
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class SyslogMessageUdpSender {
    public static final int DEFAULT_SYSLOG_PORT = 514;
    public static final String DEFAULT_SYSLOG_HOST = "localhost";
    public static final long INET_ADDRESS_TTL = TimeUnit.MILLISECONDS.convert(30, TimeUnit.SECONDS);
    public static final SyslogMessageFormat DEFAULT_SYSLOG_MESSAGE_FORMAT = SyslogMessageFormat.RFC_3164;
    private final static Charset UTF_8 = Charset.forName("UTF-8");
    protected final Logger logger = Logger.getLogger(getClass().getName());
    private final AtomicInteger sendErrorCounter = new AtomicInteger();
    private final AtomicInteger sendCounter = new AtomicInteger();
    private final AtomicLong sendDurationInNanosCounter = new AtomicLong();
    private int syslogServerPort = DEFAULT_SYSLOG_PORT;
    private AtomicReference<DatagramSocket> datagramSocket;
    private SyslogFacility defaultFacility = SyslogFacility.USER;
    private String defaultMessageHostname;
    private String defaultAppName;
    private SyslogSeverity defaultSeverity = SyslogSeverity.INFORMATIONAL;
    private AtomicReference<InetAddress> syslogServerHostname;
    private long inetAddressTtlInMillis = INET_ADDRESS_TTL;
    private long lastHostnameAddressResolutionTime;
    private SyslogMessageFormat syslogMessageFormat = DEFAULT_SYSLOG_MESSAGE_FORMAT;

    public SyslogMessageUdpSender() {
        try {
            syslogServerHostname = new AtomicReference<InetAddress>(InetAddress.getByName(DEFAULT_SYSLOG_HOST));
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Exception loading default syslogServerHostname '" + DEFAULT_SYSLOG_HOST + "'", e);
        }
        try {
            datagramSocket = new AtomicReference<DatagramSocket>(new DatagramSocket());
        } catch (SocketException e) {
            throw new IllegalStateException("Exception initializing datagramSocket", e);
        }
        lastHostnameAddressResolutionTime = System.currentTimeMillis();
    }

    public void sendMessage(SyslogMessage message) throws IOException {
        sendCounter.incrementAndGet();
        long nanosBefore = System.nanoTime();

        try {
            String syslogMessageStr = message.toSyslogMessage(syslogMessageFormat);

            if (logger.isLoggable(Level.FINEST)) {
                logger.finest("Send syslog message " + syslogMessageStr);
            }
            byte[] bytes = syslogMessageStr.getBytes(UTF_8);

            DatagramPacket packet = new DatagramPacket(bytes, bytes.length, syslogServerHostname.get(), syslogServerPort);
            datagramSocket.get().send(packet);
        } catch (IOException e) {
            sendErrorCounter.incrementAndGet();
            throw e;
        } catch (RuntimeException e) {
            sendErrorCounter.incrementAndGet();
            throw e;
        } finally {
            sendDurationInNanosCounter.addAndGet(System.nanoTime() - nanosBefore);
        }
    }

    public void sendMessage(String message) throws IOException {

        SyslogMessage syslogMessage = new SyslogMessage()
                .withAppName(defaultAppName)
                .withFacility(defaultFacility)
                .withHostname(defaultMessageHostname)
                .withSeverity(defaultSeverity)
                .withMsg(message);

        sendMessage(syslogMessage);
    }

    public void backgroundProcess() {
        if (System.currentTimeMillis() > (lastHostnameAddressResolutionTime + inetAddressTtlInMillis)) {
            renewNetworkResources();
            lastHostnameAddressResolutionTime = System.currentTimeMillis();
        }
    }

    protected void renewNetworkResources() {
        try {
            syslogServerHostname.set(InetAddress.getByName(syslogServerHostname.get().getHostName()));
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Exception resolving '" + syslogServerHostname.get().getHostName() + "'");
        }
        try {
            DatagramSocket previousDatagramSocket = datagramSocket.getAndSet(new DatagramSocket());
            if (previousDatagramSocket != null) {
                previousDatagramSocket.close();
            }
        } catch (SocketException e) {
            throw new IllegalStateException("Exception re-initializing datagramSocket", e);
        }
    }

    public int getSyslogServerPort() {
        return syslogServerPort;
    }

    public void setSyslogServerPort(int syslogServerPort) {
        this.syslogServerPort = syslogServerPort;
    }

    public String getSyslogServerHostname() {
        return syslogServerHostname.get().getHostName();
    }

    public void setSyslogServerHostname(String syslogServerHostname) throws UnknownHostException {
        this.syslogServerHostname.set(InetAddress.getByName(syslogServerHostname));
    }

    public SyslogFacility getDefaultFacility() {
        return defaultFacility;
    }

    public void setDefaultFacility(SyslogFacility defaultFacility) {
        this.defaultFacility = defaultFacility;
    }

    public String getDefaultMessageHostname() {
        return defaultMessageHostname;
    }

    public void setDefaultMessageHostName(String defaultHostName) {
        this.defaultMessageHostname = defaultHostName;
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

    public SyslogMessageFormat getSyslogMessageFormat() {
        return syslogMessageFormat;
    }

    public void setSyslogMessageFormat(SyslogMessageFormat syslogMessageFormat) {
        this.syslogMessageFormat = syslogMessageFormat;
    }

    public void setSyslogMessageFormat(String syslogMessageFormat) {
        this.syslogMessageFormat = SyslogMessageFormat.valueOf(syslogMessageFormat);
    }
}
