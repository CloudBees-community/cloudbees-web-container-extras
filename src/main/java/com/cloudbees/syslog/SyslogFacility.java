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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;

/**
 * Syslog facility as defined in <a href="https://tools.ietf.org/html/rfc5424">RFC 5424 - The Syslog Protocol</a>.
 * <p/>
 * See <a href="http://tools.ietf.org/html/rfc5427">RFC 5427 - Textual Conventions for Syslog Management</a> for the {@link #label}.
 *
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public enum SyslogFacility {

    /**
     * kernel messages, numerical code 0.
     */
    KERN(0, "KERN"),
    /**
     * user-level messages, numerical code 1.
     */
    USER(1 << 3, "USER"),
    /**
     * mail system, numerical code 2.
     */
    MAIL(2 << 3, "MAIL"),
    /**
     * system daemons, numerical code 3.
     */
    DAEMON(3 << 3, "DAEMON"),
    /**
     * security/authorization messages, numerical code 4.
     */
    AUTH(4 << 3, "AUTH"),
    /**
     * messages generated internally by syslogd, numerical code 5.
     */
    SYSLOG(5 << 3, "SYSLOG"),
    /**
     * line printer subsystem, numerical code 6.
     */
    LPR(6 << 3, "LPR"),
    /**
     * network news subsystem, numerical code 7.
     */
    NEWS(7 << 3, "NEWS"),
    /**
     * UUCP subsystem, numerical code 8
     */
    UUCP(8 << 3, "UUCP"),
    /**
     * clock daemon, numerical code 9.
     */
    CRON(9 << 3, "CRON"),
    /**
     * security/authorization  messages, numerical code 10.
     */
    AUTHPRIV(10 << 3, "AUTHPRIV"),
    /**
     * ftp daemon, numerical code 11.
     */
    FTP(11 << 3, "FTP"),
    /**
     * NTP subsystem, numerical code 12.
     */
    NTP(12 << 3, "NTP"),
    /**
     * log audit, numerical code 13.
     */
    AUDIT(13 << 3, "AUDIT"),
    /**
     * log alert, numerical code 14.
     */
    ALERT(14 << 3, "ALERT"),
    /**
     * clock daemon, numerical code 15.
     */
    CLOCK(15 << 3, "CLOCK"),
    /**
     * reserved for local use, numerical code 16.
     */
    LOCAL0(16 << 3, "LOCAL0"),
    /**
     * reserved for local use, numerical code 17.
     */
    LOCAL1(17 << 3, "LOCAL1"),
    /**
     * reserved for local use, numerical code 18.
     */
    LOCAL2(18 << 3, "LOCAL2"),
    /**
     * reserved for local use, numerical code 19.
     */
    LOCAL3(19 << 3, "LOCAL3"),
    /**
     * reserved for local use, numerical code 20.
     */
    LOCAL4(20 << 3, "LOCAL4"),
    /**
     * reserved for local use, numerical code 21.
     */
    LOCAL5(21 << 3, "LOCAL5"),
    /**
     * reserved for local use, numerical code 22.
     */
    LOCAL6(22 << 3, "LOCAL6"),
    /**
     * reserved for local use, numerical code 23.
     */
    LOCAL7(23 << 3, "LOCAL7");
    private final static Map<String, SyslogFacility> syslogFacilityFromLabel = new HashMap<String, SyslogFacility>();
    private final static Map<Integer, SyslogFacility> syslogFacilityFromValue = new HashMap<Integer, SyslogFacility>();

    static {
        for (SyslogFacility syslogFacility : SyslogFacility.values()) {
            syslogFacilityFromLabel.put(syslogFacility.label, syslogFacility);
            syslogFacilityFromValue.put(syslogFacility.value, syslogFacility);
        }
    }

    private final int value;
    private final String label;

    private SyslogFacility(int value, String label) {
        this.value = value;
        this.label = label;
    }

    @Nonnull
    public static SyslogFacility fromValue(int value) throws IllegalArgumentException {
        SyslogFacility syslogFacility = syslogFacilityFromValue.get(value);
        if (syslogFacility == null) {
            throw new IllegalArgumentException("Invalid severity '" + value + "'");
        }
        return syslogFacility;
    }

    @Nullable
    public static SyslogFacility fromLabel(@Nullable String label) throws IllegalArgumentException {
        if (label == null)
            return null;

        SyslogFacility syslogFacility = syslogFacilityFromLabel.get(label);
        if (syslogFacility == null) {
            throw new IllegalArgumentException("Invalid severity '" + label + "'");
        }
        return syslogFacility;
    }

    public int value() {
        return value;
    }

    @Nonnull
    public String label() {
        return label;
    }
}
