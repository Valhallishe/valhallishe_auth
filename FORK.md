# ValhallisheAuth

Fork of VeloAuth. Upstream history and MIT attribution are preserved. Java packages,
the Velocity plugin ID (`veloauth`), commands, database schema and the data directory
(`plugins/veloauth/`) intentionally remain compatible with upstream.

The display name is **ValhallisheAuth**. Install its JAR **instead of** VeloAuth,
never alongside it. Back up the database and `plugins/veloauth/` before replacing
the JAR. Existing password hashes do not need to be reset or converted.

## Reconnect sessions

Add this block to `plugins/veloauth/config.yml` (also present in the bundled default):

```yaml
remembered-sessions:
  enabled: true
  duration-hours: 48
  sliding-expiration: true
  persist: true
  revoke-on-logout: true
  max-entries: 10000
  excluded-players: []
```

All settings support `/vauth reload`. Duration must be 1–8760 hours. Exclusions
are case-insensitive usernames; excluded accounts always use normal authentication.

- A successful password login or registration creates a grant for the exact UUID
  and public IP seen by Velocity. Different UUIDs on the same IP do not match.
- Ordinary disconnect removes upstream's connection authorization but retains the
  reconnect grant. A fresh connection also checks the account in the database and
  verifies its UUID, nickname and credential fingerprint.
- With sliding expiration, the 48-hour window restarts when a resumed connection
  reaches a non-auth backend. Probes, failed authentication and failed transfers
  do not renew it. Further backend switches on the same connection do not renew it.
- With sliding expiration disabled, a resumed login retains the original expiry;
  a new successful password login creates a new window.
- Changing IP requires a password for that IP. Existing grants for other IPs remain
  valid until expiry or revocation.
- `/logout` revokes all remembered IPs for that UUID by default. Password changes
  and account deletion revoke grants. A changed credential fingerprint also makes
  an old grant unusable. Premium, TOTP and conflict-mode accounts are not eligible.
- `persist` retains grants across proxy restarts in
  `plugins/veloauth/remembered-sessions.properties`. Atomic snapshots contain IPs,
  UUIDs, timestamps and SHA-256 credential fingerprints, never plaintext passwords
  or password hashes. Normal updates are flushed once per second and on shutdown; revocations and
  policy changes are flushed before the operation completes.
- Disabling the feature removes grants; reducing the duration immediately limits
  existing grants as well. Upstream's `cache.session-timeout-minutes` remains the
  lifetime of connection-bound authentication, not the reconnect window.

An offline UUID is derived from a nickname. Someone able to use the same nickname
and public IP can inherit an active grant. This is the configured trust policy,
not device authentication. The proxy must receive the real client IP; do not use
a shared TCP relay IP as every player's address.

## Updating from upstream

```sh
git remote add upstream https://github.com/rafalohaki/VeloAuth.git # once
git fetch upstream --tags
git switch main
git merge --no-ff upstream/main
./mvnw test
./mvnw package -DskipTests
git push origin main
```

Do not reinitialize the repository or squash upstream history. Use merge commits
for upstream updates so local feature commits remain identifiable. Keep new
functionality in `net.rafalohaki.veloauth.remember` and the corresponding test
package. Avoid formatting or renaming upstream files.

The integration points to check after each merge are:

1. `VeloAuth`: initialize/register/close the module and reload its policy.
2. `PostAuthFlow`: create grants only after successful password authentication.
3. `LogoutCommand`, `ChangePasswordCommand`, `UnregisterCommand`: revoke grants.
4. `RememberedSessionListener`: run after upstream connection activation and
   before initial backend selection; renew only after an authorized backend join.

Upstream's real-client smoke scenarios expect reauthentication on reconnect.
The external journey supports both policies without duplicating the upstream harness:

```sh
VELOAUTH_PLUGIN_JAR="$PWD/target/veloauth-1.6.2-valhallishe.1.jar" \
  ./scripts/test-velocity-external.sh
VELOAUTH_PLUGIN_JAR="$PWD/target/veloauth-1.6.2-valhallishe.1.jar" \
  VELOAUTH_REMEMBERED_SESSIONS=true ./scripts/test-velocity-external.sh
```

Run the other upstream baseline scenarios with `remembered-sessions.enabled: false`.
Mandatory checks for the enabled path are:
password login → disconnect → reconnect from the same IP+UUID → automatic backend
entry; different IP/UUID and expiry require a password; `/logout` revokes the grant.

The upstream README and release workflow are retained. Each upstream release job
checks that it runs in `rafalohaki/VeloAuth`, so it cannot publish a misleading
VeloAuth release from this fork. Fork builds use `.github/workflows/valhallishe.yml`.
