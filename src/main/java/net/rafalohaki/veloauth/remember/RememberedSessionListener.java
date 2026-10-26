package net.rafalohaki.veloauth.remember;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry.Operation;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Additional listener keeps the upstream authentication lifecycle unchanged. */
public final class RememberedSessionListener {
    private record Attempt(Player player, Operation operation, RememberedSessions.Grant grant) { }

    private final VeloAuth plugin;
    private final RememberedSessions sessions;
    private final Map<UUID, Attempt> resumed = new ConcurrentHashMap<>();

    public RememberedSessionListener(VeloAuth plugin, RememberedSessions sessions) {
        this.plugin = plugin;
        this.sessions = sessions;
    }

    // Run after AuthListener has activated the concrete connection, before initial server selection.
    @Subscribe(priority = -1000)
    public EventTask onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        if (player.isOnlineMode()) {
            return null;
        }
        UUID uuid = player.getUniqueId();
        String ip = PlayerAddressUtils.getPlayerIp(player);
        RememberedSessions.Grant grant = sessions.candidate(uuid, ip);
        Operation operation = plugin.getConnectionLifecycleRegistry().capture(player);
        if (grant == null || operation == null) {
            return null;
        }
        String username = player.getUsername();
        return EventTask.resumeWhenComplete(plugin.getDatabaseManager().findPlayerByNickname(username)
                .thenAccept(result -> {
                    if (result == null || result.isDatabaseError() || result.getValue() == null) {
                        return; // Database errors never grant offline authorization.
                    }
                    plugin.getConnectionLifecycleRegistry().runIfCurrent(operation, () -> {
                        if (!grant.nickname().equalsIgnoreCase(username)) {
                            return;
                        }
                        sessions.use(grant, result.getValue(), () -> {
                            CachedAuthUser user = new CachedAuthUser(uuid, username, ip,
                                    System.currentTimeMillis(), false, null);
                            plugin.getAuthCache().authorize(uuid, user, username, ip);
                            resumed.put(uuid, new Attempt(player, operation, grant));
                            plugin.getLogger().info("Remembered session accepted for {}", username);
                        });
                    });
                }).exceptionally(failure -> {
                    plugin.getLogger().warn("Remembered-session lookup failed for {}; password required",
                            username, failure);
                    return null;
                }));
    }

    @Subscribe(priority = -1000)
    public void onBackendConnected(ServerConnectedEvent event) {
        if (plugin.getConnectionManager().isAuthServer(event.getServer())) {
            return;
        }
        Player player = event.getPlayer();
        Attempt attempt = resumed.get(player.getUniqueId());
        if (attempt == null || attempt.player() != player) {
            return;
        }
        resumed.remove(player.getUniqueId(), attempt);
        plugin.getConnectionLifecycleRegistry().runIfCurrent(attempt.operation(), () -> {
            String ip = PlayerAddressUtils.getPlayerIp(player);
            if (plugin.getAuthCache().isPlayerAuthorized(player.getUniqueId(), ip)
                    && plugin.getAuthCache().hasActiveSession(player.getUniqueId(), player.getUsername(), ip)
                    && sessions.renew(attempt.grant())) {
                plugin.getLogger().info("Remembered session login completed for {}", player.getUsername());
            }
        });
    }

    @Subscribe(priority = -1000)
    public void onDisconnect(DisconnectEvent event) {
        Player player = event.getPlayer();
        resumed.computeIfPresent(player.getUniqueId(),
                (uuid, attempt) -> attempt.player() == player ? null : attempt);
        // Upstream still clears connection authorization; only the reconnect grant survives.
    }
}
