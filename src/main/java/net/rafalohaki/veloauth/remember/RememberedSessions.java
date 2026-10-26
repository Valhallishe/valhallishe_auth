package net.rafalohaki.veloauth.remember;

import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Reconnect grants are distinct from upstream's connection-bound authorization.
 * Matching never extends a grant; renewal happens only after a successful backend connection.
 * Password hashes are never written here: a digest binds each grant to the current credentials.
 */
public final class RememberedSessions implements AutoCloseable {
    public record Grant(UUID uuid, String ip, String nickname, String credentialDigest,
                        long lastLogin, long expiresAt, UUID generation) { }

    private final Map<String, Grant> grants = new HashMap<>();
    private final Path file;
    private final Logger logger;
    private final Clock clock;
    private final ScheduledExecutorService writer;
    private RememberPolicy policy;
    private final Object diskLock = new Object();
    private long revision = 1;
    private long persistedRevision;
    private boolean closed;

    public RememberedSessions(Path directory, Logger logger) throws IOException {
        this(directory.resolve("remembered-sessions.properties"),
                RememberPolicy.load(directory.resolve("config.yml")), logger, Clock.systemUTC());
    }

    RememberedSessions(Path file, RememberPolicy policy, Logger logger, Clock clock) throws IOException {
        this.file = file;
        this.policy = policy;
        this.logger = logger;
        this.clock = clock;
        load();
        writer = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "ValhallisheAuth-SessionWriter");
            thread.setDaemon(true);
            return thread;
        });
        flushSafely();
        writer.scheduleWithFixedDelay(this::flushSafely, 1, 1, TimeUnit.SECONDS);
    }

    public synchronized RememberPolicy policy() {
        return policy;
    }

    public void applyPolicy(RememberPolicy replacement) {
        synchronized (this) {
            policy = replacement;
            grants.values().removeIf(grant -> !valid(grant));
            trim();
            revision++;
        }
        flushSafely();
    }

    public synchronized Grant candidate(UUID uuid, String ip) {
        if (closed || uuid == null || ip == null) {
            return null;
        }
        String key = key(uuid, ip);
        Grant grant = grants.get(key);
        if (grant != null && !valid(grant)) {
            grants.remove(key);
            revision++;
            return null;
        }
        return grant;
    }

    /** Runs authorization while holding the revocation lock; late grants cannot undo a logout. */
    public synchronized boolean use(Grant grant, RegisteredPlayer account, Runnable authorize) {
        if (!current(grant) || !eligible(account) || !grant.uuid().equals(account.getUuidAsUUID())
                || !grant.nickname().equalsIgnoreCase(account.getNickname())
                || !grant.credentialDigest().equals(fingerprint(account))) {
            return false;
        }
        authorize.run();
        return true;
    }

    /** Called only by the successful password/registration flow, after backend transfer acceptance. */
    public synchronized void remember(UUID uuid, String ip, RegisteredPlayer account) {
        if (closed || uuid == null || ip == null || ip.equals("unknown") || !eligible(account)
                || !uuid.equals(account.getUuidAsUUID()) || !policy.allows(account.getNickname())) {
            return;
        }
        long now = clock.millis();
        grants.put(key(uuid, ip), new Grant(uuid, ip, account.getNickname(), fingerprint(account),
                now, now + policy.duration().toMillis(), UUID.randomUUID()));
        revision++;
        trim();
    }

    public synchronized boolean renew(Grant grant) {
        if (!current(grant)) {
            return false;
        }
        if (policy.slidingExpiration()) {
            long now = clock.millis();
            grants.put(key(grant.uuid(), grant.ip()), new Grant(grant.uuid(), grant.ip(),
                    grant.nickname(), grant.credentialDigest(), now,
                    now + policy.duration().toMillis(), UUID.randomUUID()));
            revision++;
        }
        return true;
    }

    public void revoke(UUID uuid) {
        synchronized (this) {
            if (grants.values().removeIf(grant -> grant.uuid().equals(uuid))) {
                revision++;
            }
        }
        // Revocations are durable before /logout or password-change completion.
        flushSafely();
    }

    private boolean current(Grant grant) {
        return grant != null && !closed && grant.equals(grants.get(key(grant.uuid(), grant.ip())))
                && valid(grant);
    }

    private boolean valid(Grant grant) {
        long now = clock.millis();
        return policy.allows(grant.nickname()) && grant.lastLogin() <= now
                && now < grant.expiresAt()
                && now - grant.lastLogin() < policy.duration().toMillis();
    }

    private static boolean eligible(RegisteredPlayer account) {
        // Remembering offline passwords never bypasses Mojang verification or TOTP.
        return account != null && account.getHash() != null && !account.getHash().isBlank()
                && (account.getPremiumUuid() == null || account.getPremiumUuid().isBlank())
                && (account.getTotpToken() == null || account.getTotpToken().isBlank())
                && !account.getConflictMode();
    }

    private static String key(UUID uuid, String ip) {
        return uuid + "@" + ip;
    }

    private static String fingerprint(RegisteredPlayer account) {
        String value = account.getHash() + '\0' + java.util.Objects.toString(account.getTotpToken(), "") + '\0'
                + java.util.Objects.toString(account.getPremiumUuid(), "") + '\0' + account.getRegDate();
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is required by Java", impossible);
        }
    }

    private void trim() {
        while (grants.size() > policy.maxEntries()) {
            grants.entrySet().stream().min(Comparator.comparingLong(e -> e.getValue().lastLogin()))
                    .ifPresent(entry -> grants.remove(entry.getKey()));
        }
    }

    private void load() throws IOException {
        if (!policy.enabled() || !policy.persist() || !Files.exists(file)) {
            return;
        }
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            properties.load(reader);
        } catch (IllegalArgumentException malformed) {
            logger.warn("Ignoring malformed remembered-session file; password login remains required");
            return;
        }
        for (String key : properties.stringPropertyNames()) {
            try {
                String[] identity = key.split("@", 2);
                String[] fields = properties.getProperty(key).split("\\|", -1);
                if (identity.length != 2 || fields.length != 6) {
                    continue;
                }
                Grant grant = new Grant(UUID.fromString(identity[0]), identity[1], fields[0], fields[1],
                        Long.parseLong(fields[2]), Long.parseLong(fields[3]), UUID.fromString(fields[4]));
                if (fields[5].equals("1") && valid(grant)) {
                    grants.put(key, grant);
                }
            } catch (IllegalArgumentException malformed) {
                logger.warn("Ignoring invalid remembered-session entry; password login remains required");
            }
        }
        trim();
    }

    /** A single disk writer keeps filesystem I/O off Velocity event threads. */
    void flush() throws IOException {
        synchronized (diskLock) {
            Properties properties = new Properties();
            long snapshotRevision;
            boolean persist;
            synchronized (this) {
                if (revision == persistedRevision) {
                    return;
                }
                snapshotRevision = revision;
                persist = policy.persist() && policy.enabled();
                grants.values().stream().filter(this::valid).forEach(grant -> properties.setProperty(
                        key(grant.uuid(), grant.ip()), grant.nickname() + '|' + grant.credentialDigest()
                                + '|' + grant.lastLogin() + '|' + grant.expiresAt() + '|'
                                + grant.generation() + "|1"));
            }
            // Never hold the authentication/revocation lock during filesystem operations.
            if (!persist) {
                Files.deleteIfExists(file);
            } else {
                Files.createDirectories(file.getParent());
                Path temporary = Files.createTempFile(file.getParent(), "remembered-sessions-", ".tmp");
                try {
                    try {
                        Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rw-------"));
                    } catch (UnsupportedOperationException ignored) {
                        // Non-POSIX filesystems retain the platform's permissions.
                    }
                    try (Writer output = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)) {
                        properties.store(output, "ValhallisheAuth remembered sessions v1");
                    }
                    try {
                        Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE,
                                StandardCopyOption.REPLACE_EXISTING);
                    } catch (AtomicMoveNotSupportedException ignored) {
                        Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
                    }
                } finally {
                    Files.deleteIfExists(temporary);
                }
            }
            synchronized (this) {
                persistedRevision = snapshotRevision;
            }
        }
    }

    private void flushSafely() {
        try {
            flush();
        } catch (IOException failure) {
            logger.error("Could not persist remembered sessions; will retry", failure);
        }
    }

    @Override
    public void close() {
        synchronized (this) {
            closed = true;
        }
        writer.shutdown();
        try {
            if (!writer.awaitTermination(5, TimeUnit.SECONDS)) {
                writer.shutdownNow();
            }
        } catch (InterruptedException interrupted) {
            writer.shutdownNow();
            Thread.currentThread().interrupt();
        }
        flushSafely();
    }
}
