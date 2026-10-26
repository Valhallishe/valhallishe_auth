package net.rafalohaki.veloauth.remember;

import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RememberedSessionsTest {
    @TempDir Path directory;
    private final UUID uuid = UUID.randomUUID();
    private final String ip = "192.0.2.10";
    private final MutableClock clock = new MutableClock();

    private static RememberPolicy defaults() {
        return new RememberPolicy(true, Duration.ofHours(48), true, true, true, 10_000, Set.of());
    }

    private RememberedSessions open(RememberPolicy policy) throws Exception {
        return new RememberedSessions(directory.resolve("sessions.properties"), policy,
                LoggerFactory.getLogger(getClass()), clock);
    }

    private RegisteredPlayer account() {
        RegisteredPlayer account = mock(RegisteredPlayer.class);
        when(account.getUuidAsUUID()).thenReturn(uuid);
        when(account.getNickname()).thenReturn("maxmer12");
        when(account.getHash()).thenReturn("bcrypt-salted-credential-A");
        when(account.getRegDate()).thenReturn(123L);
        return account;
    }

    @Test void defaultsAre48HoursAndSliding() throws Exception {
        Path config = directory.resolve("config.yml");
        Files.writeString(config, "language: en\n");
        RememberPolicy policy = RememberPolicy.load(config);
        assertEquals(Duration.ofHours(48), policy.duration());
        assertTrue(policy.enabled());
        assertTrue(policy.slidingExpiration());
        assertTrue(policy.persist());
        assertTrue(policy.revokeOnLogout());
    }

    @Test void configSupportsAllPoliciesAndRejectsInvalidValues() throws Exception {
        Path config = directory.resolve("config.yml");
        Files.writeString(config, """
                remembered-sessions:
                  enabled: false
                  duration-hours: 24
                  sliding-expiration: false
                  persist: false
                  revoke-on-logout: false
                  max-entries: 3
                  excluded-players: [MAXMER12]
                """);
        RememberPolicy policy = RememberPolicy.load(config);
        assertFalse(policy.enabled());
        assertEquals(Duration.ofHours(24), policy.duration());
        assertFalse(policy.slidingExpiration());
        assertFalse(policy.persist());
        assertFalse(policy.revokeOnLogout());
        assertEquals(3, policy.maxEntries());
        assertTrue(policy.excludedPlayers().contains("maxmer12"));
        Files.writeString(config, "remembered-sessions:\n  duration-hours: 0\n");
        assertThrows(IllegalArgumentException.class, () -> RememberPolicy.load(config));
        Files.writeString(config, "remembered-sessions:\n  enabled: not-a-boolean\n");
        assertThrows(java.io.IOException.class, () -> RememberPolicy.load(config));
    }

    @Test void requiresExactIpAndUuidAndCurrentCredential() throws Exception {
        try (var sessions = open(defaults())) {
            RegisteredPlayer account = account();
            sessions.remember(uuid, ip, account);
            assertNull(sessions.candidate(uuid, "192.0.2.11"));
            assertNull(sessions.candidate(UUID.randomUUID(), ip));
            var grant = sessions.candidate(uuid, ip);
            AtomicBoolean authorized = new AtomicBoolean();
            assertTrue(sessions.use(grant, account, () -> authorized.set(true)));
            assertTrue(authorized.get());
            when(account.getHash()).thenReturn("bcrypt-salted-credential-B");
            assertFalse(sessions.use(grant, account, () -> fail("Changed password authorized")));
        }
    }

    @Test void mereChecksDoNotExtendExpiryAndBoundaryExpires() throws Exception {
        try (var sessions = open(defaults())) {
            sessions.remember(uuid, ip, account());
            long expires = sessions.candidate(uuid, ip).expiresAt();
            clock.advance(Duration.ofHours(47));
            var grant = sessions.candidate(uuid, ip);
            assertTrue(sessions.use(grant, account(), () -> { }));
            assertEquals(expires, sessions.candidate(uuid, ip).expiresAt());
            clock.advance(Duration.ofHours(1));
            assertNull(sessions.candidate(uuid, ip));
            assertFalse(sessions.renew(grant));
        }
    }

    @Test void successfulResumedLoginRenewsForAnother48Hours() throws Exception {
        try (var sessions = open(defaults())) {
            sessions.remember(uuid, ip, account());
            var first = sessions.candidate(uuid, ip);
            clock.advance(Duration.ofHours(47));
            assertTrue(sessions.renew(first));
            var renewed = sessions.candidate(uuid, ip);
            assertEquals(clock.millis() + Duration.ofHours(48).toMillis(), renewed.expiresAt());
            assertFalse(sessions.renew(first), "Old connection cannot renew a replaced grant");
            clock.advance(Duration.ofHours(2));
            assertNotNull(sessions.candidate(uuid, ip));
        }
    }

    @Test void fixedExpirationPolicyDoesNotSlide() throws Exception {
        var fixed = new RememberPolicy(true, Duration.ofHours(48), false, true, true, 10, Set.of());
        try (var sessions = open(fixed)) {
            sessions.remember(uuid, ip, account());
            var grant = sessions.candidate(uuid, ip);
            clock.advance(Duration.ofHours(47));
            assertTrue(sessions.renew(grant));
            assertEquals(grant.expiresAt(), sessions.candidate(uuid, ip).expiresAt());
            clock.advance(Duration.ofHours(1));
            assertNull(sessions.candidate(uuid, ip));
        }
    }

    @Test void survivesRestartWithoutLeakingPasswordHash() throws Exception {
        try (var sessions = open(defaults())) {
            sessions.remember(uuid, ip, account());
        }
        String content = Files.readString(directory.resolve("sessions.properties"));
        assertFalse(content.contains("bcrypt-salted-credential"));
        clock.advance(Duration.ofHours(24));
        try (var sessions = open(defaults())) {
            assertTrue(sessions.use(sessions.candidate(uuid, ip), account(), () -> { }));
            clock.advance(Duration.ofHours(24));
            assertNull(sessions.candidate(uuid, ip));
        }
    }

    @Test void revocationCannotBeUndoneByLateRenewalOrRestore() throws Exception {
        try (var sessions = open(defaults())) {
            sessions.remember(uuid, ip, account());
            var grant = sessions.candidate(uuid, ip);
            sessions.revoke(uuid);
            assertFalse(sessions.renew(grant));
            assertFalse(sessions.use(grant, account(), () -> fail("Revoked grant restored")));
        }
        try (var sessions = open(defaults())) {
            assertNull(sessions.candidate(uuid, ip));
        }
    }

    @Test void excludesPremiumTotpConflictAndUnregisteredAccounts() throws Exception {
        try (var sessions = open(defaults())) {
            RegisteredPlayer account = account();
            when(account.getTotpToken()).thenReturn("totp-secret");
            sessions.remember(uuid, ip, account);
            assertNull(sessions.candidate(uuid, ip));
            when(account.getTotpToken()).thenReturn(null);
            when(account.getPremiumUuid()).thenReturn(UUID.randomUUID().toString());
            sessions.remember(uuid, ip, account);
            assertNull(sessions.candidate(uuid, ip));
            when(account.getPremiumUuid()).thenReturn(null);
            when(account.getConflictMode()).thenReturn(true);
            sessions.remember(uuid, ip, account);
            assertNull(sessions.candidate(uuid, ip));
            when(account.getConflictMode()).thenReturn(false);
            when(account.getHash()).thenReturn("");
            sessions.remember(uuid, ip, account);
            assertNull(sessions.candidate(uuid, ip));
            sessions.remember(uuid, ip, null);
            assertNull(sessions.candidate(uuid, ip));
        }
    }

    @Test void newTotpOrDeletedAccountRejectsOldGrant() throws Exception {
        try (var sessions = open(defaults())) {
            RegisteredPlayer account = account();
            sessions.remember(uuid, ip, account);
            var grant = sessions.candidate(uuid, ip);
            when(account.getTotpToken()).thenReturn("new-totp-secret");
            assertFalse(sessions.use(grant, account, () -> fail("TOTP bypassed")));
            assertFalse(sessions.use(grant, null, () -> fail("Deleted account authorized")));
        }
    }

    @Test void policiesApplyToExistingGrants() throws Exception {
        try (var sessions = open(defaults())) {
            sessions.remember(uuid, ip, account());
            clock.advance(Duration.ofHours(2));
            sessions.applyPolicy(new RememberPolicy(true, Duration.ofHours(1), true,
                    true, true, 10, Set.of()));
            assertNull(sessions.candidate(uuid, ip));
            sessions.applyPolicy(new RememberPolicy(true, Duration.ofHours(48), true,
                    true, true, 10, Set.of("MAXMER12")));
            sessions.remember(uuid, ip, account());
            assertNull(sessions.candidate(uuid, ip));
            sessions.applyPolicy(new RememberPolicy(false, Duration.ofHours(48), true,
                    true, true, 10, Set.of()));
            sessions.remember(uuid, ip, account());
            assertNull(sessions.candidate(uuid, ip));
        }
    }

    @Test void disabledPersistenceRemovesDiskGrants() throws Exception {
        try (var sessions = open(defaults())) {
            sessions.remember(uuid, ip, account());
            sessions.flush();
            assertTrue(Files.exists(directory.resolve("sessions.properties")));
            sessions.applyPolicy(new RememberPolicy(true, Duration.ofHours(48), true,
                    false, true, 10, Set.of()));
            sessions.flush();
            assertFalse(Files.exists(directory.resolve("sessions.properties")));
        }
    }

    @Test void capacityEvictsOldestLoginAndPoliciesValidate() throws Exception {
        try (var sessions = open(new RememberPolicy(true, Duration.ofHours(48), true,
                true, true, 1, Set.of()))) {
            sessions.remember(uuid, ip, account());
            clock.advance(Duration.ofSeconds(1));
            sessions.remember(uuid, "192.0.2.11", account());
            assertNull(sessions.candidate(uuid, ip));
            assertNotNull(sessions.candidate(uuid, "192.0.2.11"));
        }
        assertThrows(IllegalArgumentException.class, () -> new RememberPolicy(true,
                Duration.ZERO, true, true, true, 10, Set.of()));
        assertThrows(IllegalArgumentException.class, () -> new RememberPolicy(true,
                Duration.ofHours(48), true, true, true, 0, Set.of()));
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-10-26T00:00:00Z");
        void advance(Duration duration) { now = now.plus(duration); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
