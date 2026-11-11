/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.parosproxy.paros.core.scanner;

import java.io.IOException;

/**
 * Indicates that a request could not be sent (or its response could not be used) because the
 * authenticated session was invalidated and could not be transparently recovered.
 *
 * <p>Thrown while active scanning with an authenticated user, when the authentication session is
 * lost and either the re-authentication failed or the request is not safe to replay. Messages that
 * fail with this exception (for example, login pages, authentication error pages) must not be
 * analysed for vulnerabilities nor produce results.
 *
 * @since 2.18.0
 * @see AuthGenerationManager
 */
public class AuthSessionException extends IOException {

    private static final long serialVersionUID = 1L;

    public AuthSessionException(String message) {
        super(message);
    }

    public AuthSessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
