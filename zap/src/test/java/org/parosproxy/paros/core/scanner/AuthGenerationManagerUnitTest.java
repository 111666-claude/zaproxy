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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

/** Unit test for {@link AuthGenerationManager}. */
class AuthGenerationManagerUnitTest {

    private static final String LOGIN_PAGE_URL = "http://example.com/login";

    private User user;
    private AuthenticationMethod authenticationMethod;
    private AtomicInteger refreshCount;
    private BooleanSupplier authenticator;

    private AuthGenerationManager manager;

    @BeforeEach
    void setup() {
        user = mock(User.class);
        Context context = mock(Context.class);
        authenticationMethod = mock(AuthenticationMethod.class);
        given(user.getContext()).willReturn(context);
        given(context.getAuthenticationMethod()).willReturn(authenticationMethod);
        given(authenticationMethod.isConfigured()).willReturn(true);
        given(authenticationMethod.getLoginPageUrl()).willReturn(LOGIN_PAGE_URL);
        given(user.isAuthenticated(any())).willReturn(true);

        refreshCount = new AtomicInteger();
        authenticator =
                () -> {
                    refreshCount.incrementAndGet();
                    return true;
                };
        manager = new AuthGenerationManager(user, authenticator);
    }

    @Test
    void shouldBeDisabledWhenNoUser() {
        // Given
        AuthGenerationManager manager = new AuthGenerationManager(null);
        // When / Then
        assertThat(manager.isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldBeDisabledWhenAuthenticationNotConfigured() {
        // Given
        given(authenticationMethod.isConfigured()).willReturn(false);
        // When / Then
        assertThat(manager.isEnabled(), is(equalTo(false)));
    }

    @Test
    void shouldBeEnabledWhenAuthenticationConfigured() {
        // When / Then
        assertThat(manager.isEnabled(), is(equalTo(true)));
    }

    @Test
    void shouldIgnoreResponsesWhenNoUser() throws Exception {
        // Given
        AuthGenerationManager manager = new AuthGenerationManager(null);
        HttpMessage msg = createMessage("GET", "http://example.com/", 401);
        // When / Then
        assertThat(manager.beforeRequest(), is(equalTo(0L)));
        assertThat(
                manager.afterResponse(msg, 0),
                is(equalTo(AuthGenerationManager.ResponseVerdict.VALID)));
    }

    @Test
    void shouldReturnValidForAuthenticatedResponse() throws Exception {
        // Given
        HttpMessage msg = createMessage("GET", "http://example.com/", 200);
        long generation = manager.beforeRequest();
        // When
        AuthGenerationManager.ResponseVerdict verdict = manager.afterResponse(msg, generation);
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.VALID)));
        assertThat(manager.getGeneration(), is(equalTo(0L)));
        assertThat(refreshCount.get(), is(equalTo(0)));
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403})
    void shouldRefreshAndRetryOnAuthErrorStatusCodes(int statusCode) throws Exception {
        // Given
        HttpMessage msg = createMessage("GET", "http://example.com/", statusCode);
        long generation = manager.beforeRequest();
        // When
        AuthGenerationManager.ResponseVerdict verdict = manager.afterResponse(msg, generation);
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.RETRY)));
        assertThat(manager.getGeneration(), is(equalTo(1L)));
        assertThat(refreshCount.get(), is(equalTo(1)));
    }

    @Test
    void shouldNotReplayNonSafeMethod() throws Exception {
        // Given
        HttpMessage msg = createMessage("POST", "http://example.com/form", 401);
        long generation = manager.beforeRequest();
        // When
        AuthGenerationManager.ResponseVerdict verdict = manager.afterResponse(msg, generation);
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.NOT_REPLAYABLE)));
        // Session still refreshed for following requests
        assertThat(manager.getGeneration(), is(equalTo(1L)));
        assertThat(refreshCount.get(), is(equalTo(1)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "HEAD", "OPTIONS", "TRACE"})
    void shouldReplaySafeMethods(String method) throws Exception {
        // Given
        HttpMessage msg = createMessage(method, "http://example.com/", 401);
        // When
        AuthGenerationManager.ResponseVerdict verdict =
                manager.afterResponse(msg, manager.beforeRequest());
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.RETRY)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://example.com/login", "/login"})
    void shouldDetectRedirectToLoginPage(String location) throws Exception {
        // Given
        HttpMessage msg = createMessage("GET", "http://example.com/", 302);
        msg.getResponseHeader().setHeader("Location", location);
        // When
        AuthGenerationManager.ResponseVerdict verdict =
                manager.afterResponse(msg, manager.beforeRequest());
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.RETRY)));
        assertThat(refreshCount.get(), is(equalTo(1)));
    }

    @Test
    void shouldNotDetectRedirectToOtherPage() throws Exception {
        // Given
        HttpMessage msg = createMessage("GET", "http://example.com/", 302);
        msg.getResponseHeader().setHeader("Location", "http://example.com/other");
        // When
        AuthGenerationManager.ResponseVerdict verdict =
                manager.afterResponse(msg, manager.beforeRequest());
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.VALID)));
        assertThat(refreshCount.get(), is(equalTo(0)));
    }

    @Test
    void shouldDetectLoggedOutResponse() throws Exception {
        // Given
        HttpMessage msg = createMessage("GET", "http://example.com/", 200);
        given(user.isAuthenticated(msg)).willReturn(false);
        // When
        AuthGenerationManager.ResponseVerdict verdict =
                manager.afterResponse(msg, manager.beforeRequest());
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.RETRY)));
        assertThat(refreshCount.get(), is(equalTo(1)));
    }

    @Test
    void shouldAllowOnlyOneRefreshForConcurrentInvalidations() throws Exception {
        // Given
        int threads = 8;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<FutureTask<AuthGenerationManager.ResponseVerdict>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            FutureTask<AuthGenerationManager.ResponseVerdict> task =
                    new FutureTask<>(
                            () -> {
                                // All threads obtain the generation before any invalidation is
                                // detected.
                                long generation = manager.beforeRequest();
                                ready.countDown();
                                start.await();
                                HttpMessage msg = createMessage("GET", "http://example.com/", 401);
                                return manager.afterResponse(msg, generation);
                            });
            tasks.add(task);
            new Thread(task).start();
        }
        // When
        ready.await();
        start.countDown();
        // Then
        for (FutureTask<AuthGenerationManager.ResponseVerdict> task : tasks) {
            assertThat(task.get(), is(equalTo(AuthGenerationManager.ResponseVerdict.RETRY)));
        }
        assertThat(refreshCount.get(), is(equalTo(1)));
        assertThat(manager.getGeneration(), is(equalTo(1L)));
    }

    @Test
    void shouldSwitchToNewGenerationWithoutRefreshingAgain() throws Exception {
        // Given two requests sent with the same generation
        long generationA = manager.beforeRequest();
        long generationB = manager.beforeRequest();
        HttpMessage msgA = createMessage("GET", "http://example.com/a", 401);
        HttpMessage msgB = createMessage("GET", "http://example.com/b", 401);
        // When both detect the invalidation
        AuthGenerationManager.ResponseVerdict verdictA = manager.afterResponse(msgA, generationA);
        AuthGenerationManager.ResponseVerdict verdictB = manager.afterResponse(msgB, generationB);
        // Then only one refresh happened
        assertThat(verdictA, is(equalTo(AuthGenerationManager.ResponseVerdict.RETRY)));
        assertThat(verdictB, is(equalTo(AuthGenerationManager.ResponseVerdict.RETRY)));
        assertThat(refreshCount.get(), is(equalTo(1)));
        assertThat(manager.getGeneration(), is(equalTo(1L)));
    }

    @Test
    void shouldRefreshAgainOnRepeatedInvalidation() throws Exception {
        // Given a first invalidation and recovery
        manager.afterResponse(
                createMessage("GET", "http://example.com/", 401), manager.beforeRequest());
        manager.afterResponse(
                createMessage("GET", "http://example.com/", 200), manager.beforeRequest());
        assertThat(manager.getGeneration(), is(equalTo(1L)));
        assertThat(refreshCount.get(), is(equalTo(1)));
        // When the session is invalidated again
        AuthGenerationManager.ResponseVerdict verdict =
                manager.afterResponse(
                        createMessage("GET", "http://example.com/", 401), manager.beforeRequest());
        // Then a new refresh is done
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.RETRY)));
        assertThat(manager.getGeneration(), is(equalTo(2L)));
        assertThat(refreshCount.get(), is(equalTo(2)));
    }

    @Test
    void shouldFailWhenSessionKeepsBeingInvalidated() throws Exception {
        // Given an authenticator that succeeds but responses that are always invalid (for
        // example, invalid credentials)
        AuthGenerationManager.ResponseVerdict verdict = null;
        // When
        for (int i = 0; i < 4; i++) {
            verdict =
                    manager.afterResponse(
                            createMessage("GET", "http://example.com/", 401),
                            manager.beforeRequest());
        }
        // Then the manager gives up and stops dispatching requests
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.REFRESH_FAILED)));
        assertThrows(AuthSessionException.class, () -> manager.beforeRequest());
        assertThat(refreshCount.get(), is(equalTo(3)));
    }

    @Test
    void shouldFailWhenRefreshNotSuccessful() throws Exception {
        // Given an authenticator that fails to refresh the session
        manager = new AuthGenerationManager(user, () -> false);
        // When
        AuthGenerationManager.ResponseVerdict verdict =
                manager.afterResponse(
                        createMessage("GET", "http://example.com/", 401), manager.beforeRequest());
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.REFRESH_FAILED)));
        assertThrows(AuthSessionException.class, () -> manager.beforeRequest());
    }

    @Test
    void shouldFailWhenAuthenticationServiceThrows() throws Exception {
        // Given an authenticator that fails with an exception (for example, the authentication
        // service is not reachable)
        manager =
                new AuthGenerationManager(
                        user,
                        () -> {
                            throw new RuntimeException("Auth service not reachable");
                        });
        // When
        AuthGenerationManager.ResponseVerdict verdict =
                manager.afterResponse(
                        createMessage("GET", "http://example.com/", 401), manager.beforeRequest());
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.REFRESH_FAILED)));
        assertThrows(AuthSessionException.class, () -> manager.beforeRequest());
    }

    @Test
    void shouldReauthenticateUserByDefault() throws Exception {
        // Given a manager that uses the user to refresh the session
        AuthGenerationManager manager = new AuthGenerationManager(user);
        given(user.requiresAuthentication()).willReturn(false);
        HttpMessage msg = createMessage("GET", "http://example.com/", 401);
        // When
        AuthGenerationManager.ResponseVerdict verdict =
                manager.afterResponse(msg, manager.beforeRequest());
        // Then
        assertThat(verdict, is(equalTo(AuthGenerationManager.ResponseVerdict.RETRY)));
        verify(user).queueAuthentication(msg);
        verify(user).authenticate();
    }

    private static HttpMessage createMessage(String method, String url, int statusCode)
            throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                new HttpRequestHeader(
                        method + " " + url + " HTTP/1.1\r\nHost: example.com\r\n\r\n"));
        msg.setResponseHeader(
                new HttpResponseHeader(
                        "HTTP/1.1 " + statusCode + " Reason\r\nContent-Length: 0\r\n\r\n"));
        return msg;
    }
}
