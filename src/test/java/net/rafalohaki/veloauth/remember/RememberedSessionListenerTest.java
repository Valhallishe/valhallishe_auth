package net.rafalohaki.veloauth.remember;

import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static net.rafalohaki.veloauth.testsupport.EventTaskTestSupport.await;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RememberedSessionListenerTest {
    @TempDir Path directory;
    private final UUID uuid = UUID.randomUUID();
    private final String ip = "192.0.2.10";
    private final VeloAuth plugin = mock(VeloAuth.class);
    private final AuthCache cache = mock(AuthCache.class);
    private final DatabaseManager database = mock(DatabaseManager.class);
    private final ConnectionManager connections = mock(ConnectionManager.class);
    private final RegisteredPlayer account = mock(RegisteredPlayer.class);
    private final RegisteredServer backend = mock(RegisteredServer.class);
    private final ConnectionLifecycleRegistry lifecycle = new ConnectionLifecycleRegistry();
    private RememberedSessions sessions;
    private RememberedSessionListener listener;
    private Player player;

    @BeforeEach void setup() throws Exception {
        sessions = new RememberedSessions(directory.resolve("sessions.properties"),
                new RememberPolicy(true, Duration.ofHours(48), true, true, true, 100, Set.of()),
                LoggerFactory.getLogger(getClass()), Clock.systemUTC());
        when(account.getUuidAsUUID()).thenReturn(uuid);
        when(account.getNickname()).thenReturn("maxmer12");
        when(account.getHash()).thenReturn("salted-credential");
        when(plugin.getAuthCache()).thenReturn(cache);
        when(plugin.getDatabaseManager()).thenReturn(database);
        when(plugin.getConnectionLifecycleRegistry()).thenReturn(lifecycle);
        when(plugin.getConnectionManager()).thenReturn(connections);
        when(plugin.getLogger()).thenReturn(LoggerFactory.getLogger(getClass()));
        when(cache.isPlayerAuthorized(uuid, ip)).thenReturn(true);
        when(cache.hasActiveSession(uuid, "maxmer12", ip)).thenReturn(true);
        when(database.findPlayerByNickname("maxmer12"))
                .thenReturn(CompletableFuture.completedFuture(DbResult.success(account)));
        player = player();
        lifecycle.activate(player, previous -> { });
        sessions.remember(uuid, ip, account);
        listener = new RememberedSessionListener(plugin, sessions);
    }

    private Player player() {
        Player value = mock(Player.class);
        when(value.getUniqueId()).thenReturn(uuid);
        when(value.getUsername()).thenReturn("maxmer12");
        when(value.isActive()).thenReturn(true);
        when(value.getRemoteAddress()).thenReturn(new InetSocketAddress(ip, 25565));
        return value;
    }

    @AfterEach void cleanup() { sessions.close(); }

    @Test void restoresAuthorizationButRenewsOnlyAfterBackendConnection() {
        var original = sessions.candidate(uuid, ip);
        await(listener.onPostLogin(new PostLoginEvent(player)));
        verify(cache).authorize(eq(uuid), any(CachedAuthUser.class), eq("maxmer12"), eq(ip));
        assertEquals(original, sessions.candidate(uuid, ip));
        RegisteredServer limbo = mock(RegisteredServer.class);
        when(connections.isAuthServer(limbo)).thenReturn(true);
        listener.onBackendConnected(new ServerConnectedEvent(player, limbo, null));
        assertEquals(original, sessions.candidate(uuid, ip));
        listener.onBackendConnected(new ServerConnectedEvent(player, backend, limbo));
        assertNotEquals(original.generation(), sessions.candidate(uuid, ip).generation());
        var renewed = sessions.candidate(uuid, ip);
        listener.onBackendConnected(new ServerConnectedEvent(player, backend, null));
        assertEquals(renewed, sessions.candidate(uuid, ip), "Backend switches do not extend reconnect grants");
    }

    @Test void databaseFailureRequiresPassword() {
        when(database.findPlayerByNickname("maxmer12")).thenReturn(
                CompletableFuture.completedFuture(DbResult.databaseError("unavailable")));
        await(listener.onPostLogin(new PostLoginEvent(player)));
        verify(cache, never()).authorize(any(), any(), any(), any());
    }

    @Test void changedCredentialOrWrongDatabaseUuidRequiresPassword() {
        when(account.getUuidAsUUID()).thenReturn(UUID.randomUUID());
        await(listener.onPostLogin(new PostLoginEvent(player)));
        verify(cache, never()).authorize(any(), any(), any(), any());
        when(account.getUuidAsUUID()).thenReturn(uuid);
        when(account.getHash()).thenReturn("changed-credential");
        await(listener.onPostLogin(new PostLoginEvent(player)));
        verify(cache, never()).authorize(any(), any(), any(), any());
    }

    @Test void lateDatabaseResponseCannotAuthorizeRetiredConnection() {
        CompletableFuture<DbResult<RegisteredPlayer>> lookup = new CompletableFuture<>();
        when(database.findPlayerByNickname("maxmer12")).thenReturn(lookup);
        var task = listener.onPostLogin(new PostLoginEvent(player));
        lifecycle.retire(player, false, () -> { });
        lookup.complete(DbResult.success(account));
        await(task);
        verify(cache, never()).authorize(any(), any(), any(), any());
    }

    @Test void logoutRevocationDuringLookupCannotBeUndone() {
        CompletableFuture<DbResult<RegisteredPlayer>> lookup = new CompletableFuture<>();
        when(database.findPlayerByNickname("maxmer12")).thenReturn(lookup);
        var task = listener.onPostLogin(new PostLoginEvent(player));
        sessions.revoke(uuid);
        lookup.complete(DbResult.success(account));
        await(task);
        verify(cache, never()).authorize(any(), any(), any(), any());
    }

    @Test void staleDisconnectDoesNotRemoveReplacementAttempt() {
        await(listener.onPostLogin(new PostLoginEvent(player)));
        Player replacement = player();
        lifecycle.activate(replacement, previous -> { });
        await(listener.onPostLogin(new PostLoginEvent(replacement)));
        var original = sessions.candidate(uuid, ip);
        listener.onDisconnect(new DisconnectEvent(player, DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN));
        listener.onBackendConnected(new ServerConnectedEvent(replacement, backend, null));
        assertNotEquals(original.generation(), sessions.candidate(uuid, ip).generation());
    }

    @Test void premiumAndUnknownIpNeverUseRememberedPassword() {
        when(player.isOnlineMode()).thenReturn(true);
        assertNull(listener.onPostLogin(new PostLoginEvent(player)));
        when(player.isOnlineMode()).thenReturn(false);
        when(player.getRemoteAddress()).thenReturn(new InetSocketAddress("192.0.2.11", 25565));
        assertNull(listener.onPostLogin(new PostLoginEvent(player)));
        verifyNoInteractions(database);
    }
}
