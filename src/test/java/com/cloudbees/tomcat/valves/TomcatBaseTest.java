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

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public abstract class TomcatBaseTest extends org.apache.catalina.startup.TomcatBaseTest {
    @Before
    @Override
    public void setUp() throws Exception {
        Path tomcatTempDir = Files.createTempDirectory("tomcat");
        System.setProperty("tomcat.test.temp", tomcatTempDir.resolve("tmp").toFile().getAbsolutePath());
        System.setProperty("tomcat.test.tomcatbuild", tomcatTempDir.resolve("build").toFile().getAbsolutePath());
        super.setUp();
    }
}
