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
import java.text.DateFormat;
import java.util.Date;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class ThreadSafeDateFormat {

    private final DateFormat simpleDateFormat;
    private final Lock lock = new ReentrantLock();
    private long lastFormattedTimestampTimeInMillis;
    private String lastFormattedTimestampValue;

    public ThreadSafeDateFormat(@Nonnull DateFormat simpleDateFormat) {
        this.simpleDateFormat = simpleDateFormat;
    }

    protected String format(long time) {
        lock.lock();
        try {
            if (time != lastFormattedTimestampTimeInMillis) {
                lastFormattedTimestampTimeInMillis = time;
                lastFormattedTimestampValue = simpleDateFormat.format(new Date(lastFormattedTimestampTimeInMillis));
            }
            return lastFormattedTimestampValue;
        } finally {
            lock.unlock();
        }
    }
}
