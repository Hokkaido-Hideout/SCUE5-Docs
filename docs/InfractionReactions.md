---
layout: default
title: SCUE5 Infraction Reactions
---

# SCUE5 Infraction Reactions: configuration, collection and retention

Documented implementation: SCUE5 Indie UE5.6 development source, reviewed October 2, 2026. Check your installed version and edition before integration; this guide does not certify feature availability in every shipped package.

[Back to the SCUE5 documentation](../README.md)

## What is built in?

| Question | Current implementation |
| --- | --- |
| Does the server save local files? | Yes, the GameSecurity logger can write security text files, and the BehaviorCore subsystem exports behavioral JSON audits on its executing machine. These are separate exporters, not a complete infraction journal. |
| Does every reaction event get a durable record? | No. The reaction hub uses Unreal diagnostic logging and delegates. It does not automatically serialize every event into an infraction file or database. |
| Are LAN and online responses different? | Yes. Each infraction has separate Online, LAN and Standalone actions. |
| Are authoritative servers and clients different? | Yes, authority controls which events and actions are permitted. Authority is separate from the session policy selection. |
| Are dedicated servers and listen servers separate profiles? | No. Both use the selected LAN/Online policy. There is no dedicated-server versus listen-server profile. |
| Can Blueprint developers collect infractions? | Yes. Bind the game-instance reaction delegates and copy their event payloads into your own records. |
| Does the plugin retain watch lists or bans across restarts? | No. Watch lists are in memory; ban persistence belongs to the game's moderation integration. |
| Does enabling network reporting upload logs? | No. The legacy security-service sender is a placeholder. No automatic backend uploader is implemented. |

Installing the plugin or choosing a reaction does not enable every possible detector. Gameplay-specific detectors need the game's telemetry and validation integration.

## Where local files go

Paths below are relative to the **executing process's** Unreal project directories. On a dedicated server, that is the server machine. On a listen server, it is the host machine. Client files remain on the client unless the game explicitly transfers data.

Use `FPaths::ProjectSavedDir()` and `FPaths::ProjectLogDir()` to resolve deployed paths; do not assume the development project's absolute directory is the packaged server's directory.

| Output | Default location | Contents and trigger |
| --- | --- | --- |
| GameSecurity security log | `Saved/Logs/AntiCheat/SecurityLog_<local-date-time>_<guid>.ace` | UTF-8 text appended when a caller invokes `FSecurityLogger::LogSecurityEvent` at or above its verbosity threshold. |
| BehaviorCore audit | `Saved/BehaviorAudit/<sanitized-player-name>_Audit_<guid>.json` | A new JSON file for each `ExportPlayerAudit` call with nonempty telemetry history. |
| Reaction diagnostic messages | The process's ordinary Unreal log output, when enabled | Accepted authoritative reactions except Ignore; accepted client-local detections also emit a diagnostic. This is not structured event persistence. |

### GameSecurity text log

On Windows, the GameSecurity module initializes the logger when `WITH_ANTI_CHEAT == 1`. File logging defaults to enabled, and the minimum severity defaults to Warning. The filename is selected at logger initialization; the directory/file is created when a write actually occurs. Initialization's Info message is below the default threshold, so module startup alone need not create an `.ace` file.

Each line includes a UTC timestamp, category, severity, message, player field and session field. The `.ace` extension does **not** mean the file is encrypted: the writer saves plain UTF-8 text. The current text serializer does not persist the entry's binary snapshot.

The legacy logger's field named `PlayerID` actually contains the player's display name when player context is available. Do not use it as an authenticated account identifier. This differs from the reaction event's `PlayerID`, described below.

C++ controls are `FSecurityLogger::SetVerbosity`, `EnableFileLogging` and `EnableNetworkReporting`. These controls are process-wide and are not exposed as per-session logging settings in the Infraction Reactions panel. `SendToSecurityService` has no implementation; enabling it does not upload anything.

Only calls to this logger produce these files. The reaction hub does not forward all of its events into this logger.

### BehaviorCore JSON audit

In builds containing server code, the BehaviorCore game-instance subsystem schedules a scan every 10 seconds. The scan skips network clients and player controllers without pawns. Each sampled player is fed into the behavior core, which retains up to 60 telemetry samples and exports a new audit file on every feed, including Normal risk profiles.

Audit fields:

- `Player`: display name.
- `Confidence`, `RiskScore`, `RiskLevel` and `Flags`.
- `Telemetry`: entries containing Time, Jump, Fire, Latency, Speed, RotationYaw and LastFireDelta.

These files contain behavioral snapshots, not the full `FSCUE5InfractionEvent`. They do not include the reaction EventID, authenticated account mapping, selected reaction or confirmed action result.

The default scan currently supplies placeholder shooting, jump and latency values. Integrate real game telemetry before treating those fields as evidence of actual player input. The C++ audit object has an editable `AuditDirectory`; this is not an exposed directory control in the reactions settings panel.

### File export reliability and retention

The two exporters use a shared asynchronous writer. Disk I/O runs on its worker thread using copied text payloads, without holding UObjects or queue locks during the write.

Current queue limits are 256 pending requests, 8 MiB of queued text/path storage and 1 MiB per request. The byte limits count in-memory TCHAR storage, not final UTF-8 file size. Enqueue requests can be rejected when these limits are reached or the writer is unavailable. Failed filesystem writes are counted and are not automatically retried. The exporters currently do not surface enqueue/write completion to Blueprint.

At module shutdown, queued jobs are discarded before joining the writer. Process crashes can also lose queued data. Accepted enqueue is therefore not proof that a record reached disk.

There is no built-in file rotation, age-based cleanup, disk quota, durable retry queue or retention duration. Audit exports create new files repeatedly. The server operator must archive and expire files using their own operational tooling. For durable moderation evidence, use a persistence system with explicit write/upload acknowledgments and retry handling.

C++ integrations can inspect `FSCUE5AsyncFileWriter` counters: completed, failed, dropped and pending. These process-wide counters are not exposed as Blueprint nodes.

Ordinary `UE_LOG` output depends on the target's logging configuration, particularly Shipping builds. The current development Game target does not explicitly enable Shipping diagnostic logging. The custom text/JSON file writers are separate from `UE_LOG`; do not rely on ordinary diagnostic logs as your Shipping infraction archive.

## Session policies and authority

Open **Project Settings > HKH > SCUE5 Infraction Reactions**.

Settings are backed by `Config/DefaultGame.ini`, under the class section `[/Script/SCUE5BehaviorCore.SCUE5ReactionSettings]`. Deployed instances load their Unreal Game configuration; settings are not automatically synchronized from server to clients.

Each of the 31 infraction rules has:

| Setting | Scope |
| --- | --- |
| Standalone action | Used when the world has Standalone net mode. Default: Log. |
| LAN action | Used for network play whose server context is LAN. Default: Log. |
| Online action | Used for network play whose server context is Online. Default: WatchList. |
| Enabled, minimum confidence, cooldown, custom action key, kick message | Shared across all three session contexts for that infraction. |
| Enable infraction reactions | Global pipeline switch, shared across contexts. |
| Default network context | Fallback for network play. Default: Online. |

Threat groups are Low, Moderate, High and Critical. Grouping selects a classification; each infraction still has its own rule.

The panel's **Configure for** dropdown changes which action you edit. It does not select the running session mode or change the default network context. There is no separate Editor/PIE reaction profile.

At LAN session creation, obtain **Get SCUE5 Reactions** on the server, call **Set Session Context** with LAN, and check its boolean result. For an online session, set Online. The override belongs to that game-instance hub and is not replicated. Set it again when switching session types in a surviving game instance. Standalone dispatch always uses the Standalone action.

| Execution context | Reaction behavior |
| --- | --- |
| Dedicated server / listen server, Online | Authoritative hub uses Online rules. |
| Dedicated server / listen server, LAN | Authoritative hub uses LAN rules after explicit context selection. |
| Standalone | Authoritative local hub uses Standalone rules; there is no remote connection to kick. |
| Network client | Local detections use diagnostic Log and On Local Infraction; they cannot execute the configured server penalty. |
| Server receiving a client hint | Broadcasts On Client Report with confidence zero and authority false; does not run the configured reaction. |

LAN does not mean non-authoritative: its server still owns authority. Different actions let your game choose a relaxed LAN policy.

Choosing Ignore, disabling a rule or disabling the reaction pipeline does not disable unrelated detector exporters. It also cannot override Unreal's disconnect when a native RPC `_Validate` returns false.

## Collecting data from Blueprint

Use one persistent listener per server game instance to avoid duplicate records. A server-side manager actor can bind during BeginPlay once the game world exists. For map travel, manage rebinding deliberately and unbind the departing listener during EndPlay.

1. Call **Get SCUE5 Reactions** using an object in the game world. Check the returned hub is valid.
2. On the server, set the session context for the created session.
3. Bind **On Infraction** to collect accepted authoritative incidents.
4. Bind **On Reaction Applied** to record the built-in action result.
5. If needed, separately bind **On Client Report** for untrusted hints.
6. Bind **On Custom Reaction** and **On Ban Requested** for your game's action/backend integration.
7. Copy the event's data immediately into a durable-record structure. Do not retain the live Subject actor as the identity of an archived incident.

| Delegate | Meaning |
| --- | --- |
| On Infraction | Accepted authoritative event, broadcast before its selected built-in action runs. Includes Ignore events that pass the rule gates. |
| On Reaction Applied | The event and a boolean indicating built-in execution success. Log/Ignore succeed without proving disk persistence. WatchList/Kick can fail. |
| On Custom Reaction | Selected Custom action; interpret CustomAction in your game handler. |
| On Ban Requested | Selected BanRequest action; your backend decides and persists the ban. |
| On Local Infraction | Accepted client-local diagnostic event. Not server evidence. |
| On Client Report | Untrusted client hint received by the server. Subject identifies the reporting connection, not an alleged offender. |

For Custom and BanRequest, On Reaction Applied reports false because the hub cannot confirm your external handler's outcome. Persist backend completion separately; do not automatically label these as failed backend operations.

### Event payload

All delegates carry `FSCUE5InfractionEvent`, which exposes Blueprint-readable fields:

| Field | Storage meaning |
| --- | --- |
| EventID | GUID for this dispatched event. Use it to correlate On Infraction, On Reaction Applied and backend outcomes. |
| Infraction / ThreatLevel | Stable code and current policy classification. Store enum names as well as a schema version for long-lived archives. |
| Reaction / Session | Selected reaction and session context. Client hints use Ignore; local client events use Log. |
| Subject | Live actor reference; may be absent for host/process incidents. Not a durable player identifier. |
| PlayerID | Online-subsystem identifier obtained from server player state. May be empty or session-only. |
| PlayerName | Display name only. |
| Details | Descriptive evidence/check name, truncated to 2,048 TCHAR characters. |
| CustomAction | Project-defined custom/backend action key. |
| Confidence | Clamped to 0–1 for accepted detections. Client hints have zero confidence. |
| Timestamp | UTC event creation time. |
| bServerAuthority | Whether the detection was accepted as authoritative. Client hints remain false even when delivered to a server listener. |

Add your authenticated account ID, match/session ID, server instance ID, build version and evidence source to the saved record. Distinguish server-authenticated identity from the online/display fields. Anonymous host integrity incidents should remain unattributed rather than being assigned to an arbitrary remote player.

### What the delegates do not collect

On Infraction and On Local Infraction are **post-filter** events. Disabled pipeline/rules, insufficient confidence, cooldown suppression, invalid input and recursive dispatch do not produce these accepted-event delegates. Cooldown is per Subject/Infraction, shared across contexts, with at most 4,096 entries.

They are not a feed of every raw detector sample or every attempted call. If your evidence requirements include suppressed samples, instrument the detector or telemetry source separately.

Events are transient broadcasts. There is no hub history array, replay API, query-by-account API or automatic persistence for late subscribers.

On Client Report has its own transport limits: valid infraction code, PlayerController ownership, a maximum 2,048-character payload and at most 32 accepted hints per second per validation component. It is gated by the global pipeline switch but does not execute per-rule confidence/cooldown/action handling. Server listeners must bound storage for this untrusted stream.

## Retaining incidents beyond a session

### Blueprint-only local retention

The plugin provides collection delegates, not a Blueprint infraction file-export node. A developer can implement local persistence using Unreal SaveGame:

1. Create a project record struct containing copied scalar/text/enum fields from the event and your account/session metadata. Exclude Subject.
2. Create a SaveGame Blueprint containing an array of these records and a schema version.
3. Load the chosen slot at server startup, or create a new object if it does not exist.
4. On Infraction, append a record keyed by EventID. On Reaction Applied, update that record or append a linked outcome record using the same EventID.
5. Save bounded batches with **Async Save Game to Slot**. Check completion success before treating the batch as persisted.
6. Serialize saves to each slot: allow one operation in flight, take a stable batch snapshot, and queue later changes until completion. Implement retry/error reporting.
7. Rotate/archive records by match or bounded batch; apply your own retention limit.

This is a suggested project implementation, not a built-in SCUE5 journal or a supplied SaveGame asset. Slot storage is platform dependent and is not a Markdown/JSON export. Writes occur wherever the listener executes: bind and save on the server for server-local retention.

For database or JSON export from Blueprint, use your project's existing persistence integration. SCUE5 currently supplies neither a generic Blueprint filesystem API nor a completed HTTP moderation client.

### Server/backend retention

For a central archive, connect the authoritative listener to your game's persistence service. A useful record separates:

- Detection: EventID, code, confidence, copied details, source and UTC timestamp.
- Identity/context: authenticated account, session, server instance, policy mode and build.
- Policy decision: selected action and configured custom key.
- Execution outcome: built-in result, backend acknowledgment, moderator decision and completion time.

Use EventID for idempotent ingestion, keep client hints marked untrusted, and record server corroboration separately. A corroborated **Report Server Infraction** creates a new authoritative EventID; preserve the original hint ID in your own record if you need that relationship.

Batch writes/uploads off the game thread using copied records. Monitor failures, retry with bounds, and persist acknowledgments. Never block the game thread on filesystem or network operations inside a reaction delegate.

### Watch lists and bans

The built-in watch list stores weak PlayerController references, capped at 4,096. Query it with **Is Player Watch Listed** and clear it with **Clear Watch List** on authority. It stores membership, not a durable collection of the event payloads.

It is scoped to the game instance, cleared on subsystem teardown, and may lose entries when controllers are destroyed. It does not survive process restart or act as an account ban database.

BanRequest broadcasts an event; it does not itself ban, schedule a temporary ban, persist a ban or enforce bans at login. Your authenticated account/backend integration must implement those behaviors.

## Validation integration

Add **SCUE5 Validation Component** to the PlayerController Blueprint to transport local detections through its owned server RPC. It replicates by default and does not tick. Accepted local detections automatically use it when it exists on the local PlayerController. **Report Local Detection** also supports custom client detector hints.

For replicated data, call **SCUE5 Check Validation Result** from your OnRep graph with the predicate, Subject, descriptive CheckName and Stage=OnRep; branch on the returned boolean. Alternatively use **Validate Replicated State** on the validation component. A failure on a client remains a local diagnostic/hint.

For Blueprint server events, validate against server data at the beginning of the event, call the helper with Stage=RPC, and skip the gameplay operation when it returns false. Blueprint Server Custom Events do not provide native C++ `_Validate` functions.

For native RPC validation, include `SCUE5_ReactionLibrary.h` and report before returning the validation result:

```cpp
bool AMyActor::ServerDoAction_Validate(int32 RequestedValue)
{
    const bool bValid = IsRequestAllowedByServer(RequestedValue);
    return USCUE5ReactionLibrary::CheckValidationResult(
        this, this, bValid, TEXT("ServerDoAction_Validate"),
        ESCUE5ValidationStage::RPC);
}
```

The plugin's own transport RPC is integrated. Arbitrary project OnRep predicates and native RPC validators must call the helper; the plugin does not install a global engine hook for them.

Unreal still disconnects a peer when its native RPC validation returns false, even if the SCUE5 action is Ignore or Log. Kick uses the authoritative GameSession and can fail for a local host, absent connection or unattributable process incident.

All reaction dispatch and UObject access run on the game thread. Recursive reaction dispatch from a delegate is rejected.

## Verify your game integration

Before deployment, check your own integration:

1. Trigger an authoritative test incident with an attributable subject. Confirm On Infraction and On Reaction Applied share an EventID.
2. Switch Online/LAN context on the server and verify the intended action changes; confirm shared confidence/cooldown settings remain shared.
3. Submit a valid client hint. Confirm it reaches On Client Report with confidence zero and authority false, without an automatic penalty.
4. Persist an incident and its outcome, restart the server, and verify your archive reloads or backend query returns both records.
5. Exercise write/upload failures and queue limits. Confirm your retention integration reports failures and retries appropriately.
6. Check deployed Shipping file paths and logging behavior on the actual server machine.

These implementation details were source-reviewed. They do not certify a dedicated-server deployment or your game's retention backend; validate both in your deployment environment.

## Implementation references

In plugin source, the relevant files are:

- Runtime: `SCUE5_Reactions.cpp`, `SCUE5.h`, `ISCUE5.cpp`, `SCUE5_ValidationComponent.cpp`.
- BehaviorCore: `SCUE5_Infractions.h`, `SCUE5_ReactionSettings.h/.cpp`, `SCUE5_BehaviorCoreSubsystem.cpp`, `SCUE5_BehaviorCoreComponent.cpp`, `SCUE5_BehaviorAuditLogger.h/.cpp`, `SCUE5_AsyncFileWriter.h/.cpp`.
- GameSecurity: `SCUE5_SecurityLogger.cpp`, `ISCUE5_GameSecurity.cpp`.

These are source references, not files bundled with this documentation repository.

Retention tooling must implement applicable license requirements, including the [EULA's data protection terms](../README.md#scue5-eula). The implementation has no automatic expiry.
