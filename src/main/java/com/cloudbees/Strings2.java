/*
 * Copyright 2010-2013, the original author or authors
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
package com.cloudbees;

import javax.annotation.Nullable;
import java.nio.charset.Charset;

/**
 * {@linkplain String} util class
 * @author <a href="mailto:cleclerc@cloudbees.com">Cyrille Le Clerc</a>
 */
public class Strings2 {

    public final static Charset ISO_8859_1 = Charset.forName("ISO_8859_1");

    public static boolean startsWithIgnoreCase(@Nullable String str, @Nullable String token) {
        if (token == null) {
            return true;
        }
        if (str == null || str.length() < token.length()) {
            return false;
        }
        return str.substring(0, token.length()).equalsIgnoreCase(token);

    }
}
