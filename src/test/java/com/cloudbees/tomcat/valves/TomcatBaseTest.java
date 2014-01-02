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

import org.junit.Before;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public abstract class TomcatBaseTest extends org.apache.catalina.startup.TomcatBaseTest {
    @Before
    @Override
    public void setUp() throws Exception {
        File tempDir = File.createTempFile("tomcat", "test");
        boolean deleted = tempDir.delete();
        if (!deleted) {
            throw new IllegalStateException("TMP file " + tempDir + " could not be deleted");
        }
        boolean created = tempDir.mkdirs();
        if (!created) {
            throw new IllegalStateException("TMP dir " + tempDir + " could not be created");
        }
        System.setProperty("tomcat.test.temp", new File(tempDir, "tmp").getAbsolutePath());
        System.setProperty("tomcat.test.tomcatbuild", new File(tempDir, "build").getAbsolutePath());
        super.setUp();
    }
}
