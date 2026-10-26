package net.rafalohaki.veloauth.remember;

import org.spongepowered.configurate.ConfigurationNode;
import org.spongepowered.configurate.yaml.YamlConfigurationLoader;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/** Fork-specific policy, deliberately separate from upstream's connection-session settings. */
public record RememberPolicy(boolean enabled, Duration duration, boolean slidingExpiration,
                             boolean persist, boolean revokeOnLogout, int maxEntries,
                             Set<String> excludedPlayers) {
    public RememberPolicy {
        if (duration == null || duration.isNegative() || duration.isZero()
                || duration.compareTo(Duration.ofDays(365)) > 0) {
            throw new IllegalArgumentException("remembered-sessions.duration-hours must be 1..8760");
        }
        if (maxEntries < 1 || maxEntries > 1_000_000) {
            throw new IllegalArgumentException("remembered-sessions.max-entries must be 1..1000000");
        }
        excludedPlayers = excludedPlayers.stream().map(n -> n.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    public static RememberPolicy load(Path config) throws IOException {
        ConfigurationNode node = YamlConfigurationLoader.builder().path(config).build()
                .load().node("remembered-sessions");
        long hours = node.node("duration-hours").get(Long.class, 48L);
        if (hours < 1 || hours > 8760) {
            throw new IllegalArgumentException("remembered-sessions.duration-hours must be 1..8760");
        }
        return new RememberPolicy(node.node("enabled").get(Boolean.class, true),
                Duration.ofHours(hours),
                node.node("sliding-expiration").get(Boolean.class, true),
                node.node("persist").get(Boolean.class, true),
                node.node("revoke-on-logout").get(Boolean.class, true),
                node.node("max-entries").get(Integer.class, 10_000),
                Set.copyOf(node.node("excluded-players").getList(String.class, List.of())));
    }

    public boolean allows(String nickname) {
        return enabled && !excludedPlayers.contains(nickname.toLowerCase(Locale.ROOT));
    }
}
