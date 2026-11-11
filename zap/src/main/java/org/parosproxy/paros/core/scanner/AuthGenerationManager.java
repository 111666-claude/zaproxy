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

import java.util.Locale;
import java.util.function.BooleanSupplier;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

/**
 * Coordinates the recovery of the authenticated session while active scanning with a user.
 *
 * <p>The scan threads send their requests with the current authentication <em>generation</em>. When
 * a response indicates that the session is no longer authenticated (for example, {@code 401} or
 * {@code 403} status codes, a redirection to the login page, or a logged out indicator) the session
 * is refreshed: a single thread performs the re-authentication while the remaining threads wait,
 * and once done the generation is incremented so all threads switch to the new authentication
 * state.
 *
 * <p>Only requests that are safe to replay (that is, requests with safe HTTP methods, such as
 * {@code GET}) are retried after a refresh, requests with non-safe methods are stopped and the
 * reason recorded. Responses obtained while the session was invalidated (for example, login or
 * authentication error pages) must not be analysed for vulnerabilities nor produce results.
 *
 * <p>If the authentication can not be recovered (for example, invalid credentials or the
 * authentication service failing) the manager stops allowing requests to be sent, by throwing
 * {@link AuthSessionException}.
 *
 * @since 2.18.0
 */
public class AuthGenerationManager {

    private static final Logger LOGGER = LogManager.getLogger(AuthGenerationManager.class);

    /**
     * The maximum number of consecutive authentication refreshes, without a valid response in
     * between, before the authentication is considered unrecoverable.
     */
    private static final int MAX_CONSECUTIVE_REFRESHES = 3;

    /** The verdict of checking a response obtained with a given authentication generation. */
    public enum ResponseVerdict {
        /** The response corresponds to an authenticated session, it can be analysed. */
        VALID,
        /** The session was refreshed and the request is safe to replay, it should be retried. */
        RETRY,
        /** The session was refreshed but the request is not safe to replay, it must be stopped. */
        NOT_REPLAYABLE,
        /** The session could not be refreshed, the request must be stopped. */
        REFRESH_FAILED,
    }

    private final Object lock = new Object();

    private final User user;
    private final BooleanSupplier authenticator;

    private long generation;
    private boolean sessionInvalidated;
    private boolean authFailed;
    private int consecutiveRefreshes;
    private HttpMessage invalidatingMessage;

    /**
     * Constructs an {@code AuthGenerationManager} for the given user.
     *
     * @param user the user being scanned as, might be {@code null} if the scan is not
     *     authenticated.
     */
    public AuthGenerationManager(User user) {
        this(user, null);
    }

    /**
     * Constructs an {@code AuthGenerationManager} with the given authenticator.
     *
     * @param user the user being scanned as, might be {@code null}.
     * @param authenticator the action that refreshes the authentication, returning {@code true} if
     *     successful. If {@code null} the user is re-authenticated with its authentication method.
     */
    AuthGenerationManager(User user, BooleanSupplier authenticator) {
        this.user = user;
        this.authenticator = authenticator;
    }

    /**
     * Tells whether or not the manager is enabled, that is, if the scan is being done with a user
     * that has a configured authentication method.
     *
     * @return {@code true} if enabled, {@code false} otherwise.
     */
    public boolean isEnabled() {
        if (user == null) {
            return false;
        }
        try {
            Context context = user.getContext();
            return context != null
                    && context.getAuthenticationMethod() != null
                    && context.getAuthenticationMethod().isConfigured();
        } catch (Exception e) {
            LOGGER.debug("Failed to check if authentication is configured:", e);
            return false;
        }
    }

    /**
     * Gets the current authentication generation.
     *
     * @return the current generation.
     */
    public long getGeneration() {
        synchronized (lock) {
            return generation;
        }
    }

    /**
     * Called before sending a request, to obtain the authentication generation the request is being
     * sent with.
     *
     * <p>If the session was invalidated by another thread this call blocks while the authentication
     * is being refreshed, resuming once the new generation is available. No requests are dispatched
     * with the old credentials while a refresh is in progress.
     *
     * @return the generation the request is being sent with.
     * @throws AuthSessionException if the authentication could not be recovered.
     */
    public long beforeRequest() throws AuthSessionException {
        synchronized (lock) {
            if (user == null) {
                return generation;
            }
            if (sessionInvalidated && !refreshLocked()) {
                throw new AuthSessionException(
                        "Unable to send request, the authentication session could not be"
                                + " recovered.");
            }
            return generation;
        }
    }

    /**
     * Called after a response was received for a request sent with the given generation, to check
     * whether the response can be used or the request needs to be handled otherwise.
     *
     * @param msg the message sent and received.
     * @param requestGeneration the generation the request was sent with.
     * @return the verdict for the response.
     */
    public ResponseVerdict afterResponse(HttpMessage msg, long requestGeneration) {
        if (user == null) {
            return ResponseVerdict.VALID;
        }
        if (!isSessionInvalid(msg)) {
            synchronized (lock) {
                consecutiveRefreshes = 0;
            }
            return ResponseVerdict.VALID;
        }

        synchronized (lock) {
            if (authFailed) {
                return ResponseVerdict.REFRESH_FAILED;
            }
            if (generation == requestGeneration) {
                sessionInvalidated = true;
                invalidatingMessage = msg;
            }
            if (sessionInvalidated && !refreshLocked()) {
                return ResponseVerdict.REFRESH_FAILED;
            }
            if (!isSafeToReplay(msg)) {
                LOGGER.info(
                        "Not replaying request with method {} to {}, it is not safe to replay"
                                + " after the authentication session was refreshed.",
                        msg.getRequestHeader().getMethod(),
                        msg.getRequestHeader().getURI());
                return ResponseVerdict.NOT_REPLAYABLE;
            }
            return ResponseVerdict.RETRY;
        }
    }

    /**
     * Tells whether or not the given message is safe to replay, that is, if it uses a safe HTTP
     * method (for example, {@code GET}, {@code HEAD}).
     *
     * @param msg the message to check.
     * @return {@code true} if safe to replay, {@code false} otherwise.
     */
    public static boolean isSafeToReplay(HttpMessage msg) {
        String method = msg.getRequestHeader().getMethod().toUpperCase(Locale.ROOT);
        switch (method) {
            case HttpRequestHeader.GET:
            case HttpRequestHeader.HEAD:
            case HttpRequestHeader.OPTIONS:
            case HttpRequestHeader.TRACE:
                return true;
            default:
                return false;
        }
    }

    /**
     * Refreshes the authentication session.
     *
     * <p>Called with the {@link #lock} held, ensuring a single thread performs the refresh while
     * the others wait.
     *
     * @return {@code true} if the session was refreshed, {@code false} otherwise.
     */
    private boolean refreshLocked() {
        if (consecutiveRefreshes >= MAX_CONSECUTIVE_REFRESHES) {
            authFailed = true;
            LOGGER.warn(
                    "Giving up re-authenticating user {}, the session keeps being invalidated"
                            + " (for example, invalid credentials).",
                    user.getName());
            return false;
        }

        boolean success;
        try {
            success =
                    authenticator != null
                            ? authenticator.getAsBoolean()
                            : reauthenticate(user, invalidatingMessage);
        } catch (Exception e) {
            LOGGER.warn("Failed to re-authenticate the user {}:", user.getName(), e);
            success = false;
        }
        consecutiveRefreshes++;

        if (!success) {
            LOGGER.warn("Failed to refresh the authentication session of user {}.", user.getName());
            return false;
        }

        sessionInvalidated = false;
        generation++;
        LOGGER.debug(
                "Authentication session of user {} refreshed, new generation: {}",
                user.getName(),
                generation);
        return true;
    }

    private static boolean reauthenticate(User user, HttpMessage unauthenticatedMessage) {
        if (unauthenticatedMessage != null) {
            user.queueAuthentication(unauthenticatedMessage);
        }
        user.authenticate();
        return !user.requiresAuthentication();
    }

    private boolean isSessionInvalid(HttpMessage msg) {
        int statusCode = msg.getResponseHeader().getStatusCode();
        if (statusCode == HttpStatusCode.UNAUTHORIZED || statusCode == HttpStatusCode.FORBIDDEN) {
            LOGGER.debug(
                    "Session of user {} invalidated, received status code {} for {}",
                    user.getName(),
                    statusCode,
                    msg.getRequestHeader().getURI());
            return true;
        }

        if (isRedirectToLoginPage(msg)) {
            LOGGER.debug(
                    "Session of user {} invalidated, redirected to the login page from {}",
                    user.getName(),
                    msg.getRequestHeader().getURI());
            return true;
        }

        try {
            return !user.isAuthenticated(msg);
        } catch (Exception e) {
            LOGGER.debug("Failed to check if response is authenticated:", e);
            return false;
        }
    }

    private boolean isRedirectToLoginPage(HttpMessage msg) {
        if (!HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode())) {
            return false;
        }
        String location = msg.getResponseHeader().getHeader(HttpHeader.LOCATION);
        if (location == null || location.isEmpty()) {
            return false;
        }
        String loginPageUrl = getLoginPageUrl();
        if (loginPageUrl == null || loginPageUrl.isEmpty()) {
            return false;
        }
        try {
            URI target = resolveLocation(msg.getRequestHeader().getURI(), location);
            URI loginPage = new URI(loginPageUrl, true);
            return isSamePage(target, loginPage);
        } catch (Exception e) {
            LOGGER.debug("Failed to compare redirection with login page:", e);
            return false;
        }
    }

    private static URI resolveLocation(URI base, String location) throws Exception {
        try {
            return new URI(base, location, true);
        } catch (Exception e) {
            // Handle redirect URLs that are unencoded
            return new URI(base, location, false);
        }
    }

    private static boolean isSamePage(URI uri, URI other) throws Exception {
        return equalsIgnoreCase(uri.getScheme(), other.getScheme())
                && equalsIgnoreCase(uri.getHost(), other.getHost())
                && uri.getPort() == other.getPort()
                && equalsIgnoreCase(uri.getPath(), other.getPath());
    }

    private static boolean equalsIgnoreCase(String str, String other) {
        if (str == null) {
            return other == null;
        }
        return other != null && str.equalsIgnoreCase(other);
    }

    private String getLoginPageUrl() {
        try {
            Context context = user.getContext();
            if (context == null) {
                return null;
            }
            AuthenticationMethod method = context.getAuthenticationMethod();
            return method != null ? method.getLoginPageUrl() : null;
        } catch (Exception e) {
            LOGGER.debug("Failed to obtain the login page URL:", e);
            return null;
        }
    }
}
