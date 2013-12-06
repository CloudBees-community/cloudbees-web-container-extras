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
 * Syslog severity as defined in <a href="https://tools.ietf.org/html/rfc5424">RFC 5424 - The Syslog Protocol</a>.
 *
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public enum SyslogSeverity {
    /**
     * Emergency: system is unusable, numerical code 0.
     */
    EMERGENCY(0, "EMERGENCY"),
    /**
     * Alert: action must be taken immediately, numerical code 1.
     */
    ALERT(1, "ALERT"),
    /**
     * Critical: critical conditions, numerical code 2.
     */
    CRITICAL(2, "CRITICAL"),
    /**
     * Error: error conditions, numerical code 3.
     */
    ERROR(3, "ERROR"),
    /**
     * Warning: warning conditions, numerical code 4.
     */
    WARNING(4, "WARNING"),
    /**
     * Notice: normal but significant condition, numerical code 5.
     */
    NOTICE(5, "NOTICE"),
    /**
     * Informational: informational messages, numerical code 6.
     */
    INFORMATIONAL(6, "INFORMATIONAL"),
    /**
     * Debug: debug-level messages, numerical code 7.
     */
    DEBUG(7, "DEBUG");
    private final static Map<String, SyslogSeverity> syslogSeverityFromLabel = new HashMap<>();
    private final static Map<Integer, SyslogSeverity> syslogSeverityFromValue = new HashMap<>();

    static {
        for (SyslogSeverity syslogSeverity : SyslogSeverity.values()) {
            syslogSeverityFromLabel.put(syslogSeverity.label, syslogSeverity);
            syslogSeverityFromValue.put(syslogSeverity.value, syslogSeverity);
        }
    }

    private final int value;
    @Nonnull
    private final String label;

    private SyslogSeverity(int value, @Nonnull String label) {
        this.value = value;
        this.label = label;
    }

    @Nonnull
    public static SyslogSeverity fromValue(int value) throws IllegalArgumentException {
        SyslogSeverity syslogSeverity = syslogSeverityFromValue.get(value);
        if (syslogSeverity == null) {
            throw new IllegalArgumentException("Invalid severity '" + value + "'");
        }
        return syslogSeverity;
    }

    @Nullable
    public static SyslogSeverity fromLabel(@Nullable String label) throws IllegalArgumentException {
        if (label == null)
            return null;

        SyslogSeverity syslogSeverity = syslogSeverityFromLabel.get(label);
        if (syslogSeverity == null) {
            throw new IllegalArgumentException("Invalid severity '" + label + "'");
        }
        return syslogSeverity;
    }

    public int value() {
        return value;
    }

    @Nonnull
    public String label() {
        return label;
    }
}
