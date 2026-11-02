# Validation

## Background-session Keychain access — November 2, 2026

T3 and other SSH-launched agents run in their own macOS security session, where the login keychain stays locked even while the desktop session has it unlocked. A locked read or write (`security` exit 36) is now repeated once through a one-shot `gui/UID` launchd job and a private owner-only socket, limited to this plugin's own find/add records. It never unlocks or bypasses the Keychain; with no logged-in desktop session it reports that clearly. All 175 tests passed, and the read-only doctor verified all four Gmail accounts from a locked T3 session without reading mail.

## Beginner setup guidance — September 17, 2026

Added a plain-language walkthrough, resumable agent setup mode, and a setup discovery trigger. Checked local guide links and plugin/skill schema validation. The setup reference is loaded only for onboarding; routine service commands retain separate references. Runtime behavior is unchanged.

## GitHub auto-updater — September 16, 2026

- Added an opt-in native macOS LaunchAgent for hourly/login checks, direct GitHub main downloads, bounded staged releases, release tests, source/cache verification, and compact status receipts.
- Real temporary Git repositories exercise checkout and managed-release upgrades, already-current checks, dirty/divergent source protection, version reuse, failed tests, failed installation recovery/retry, disabled plugins, and cache tampering. Additional boundary tests cover repository/path restrictions, inherited environment isolation, and concurrent updater locking.
- All 164 tests passed on the local and remote Macs. Both native hourly/login LaunchAgents were enabled and completed a live GitHub check with `current` status and matching installed source/cache. The initial deployment also refreshed all four existing Gmail accounts without copying credentials.
- Auto-updates do not call Google, transfer credentials, or synchronize account notes. The compact per-Mac receipt records later verified upgrades with the previous/new revision and installed version.


## Optional Workspace expansion — September 16, 2026

The Gmail history below remains a record of its earlier live verification. Workspace code and tests are additional; installing these modules does not grant Google permissions or constitute a live API test.

- Added Calendar, Meet, Drive, Docs, Sheets, and Contacts modules under an explicit account/service command router.
- Synthetic tests cover account/client/type-bound refs, query-bound pagination, request replay/conflicts, conservative uncertain outcomes, private no-overwrite downloads, wrong/empty Drive destinations, bounded Sheets ranges and RAW writes, document tabs/chunks/index revisions, explicit calendars/timezones/guest notifications, standalone Meet semantics, contact etags, OAuth identity/scope/refresh checks, isolated client/token namespaces, narrow remote transfer, staged remote CLI installation, and transport retry/redaction boundaries.
- An independent read-only review reproduced and prompted fixes for document continuation, matrix truncation, empty Drive move destinations, append width, stale formatting indexes, and client-name collision. A fictional multi-company scenario correctly required clarification before selecting a work identity.
- The current synthetic token benchmark is in `benchmarks/results.json`: 37 discovery tokens, 698 router tokens, no MCP schemas. Service references load individually; these counts are not measured billing savings.
- Live Workspace verification requires separate Google consent for each intended account. Until consent is completed, do not describe any Workspace account or API as connected/verified. Existing Gmail grants remain separate.

The independent client uses Python standard library and macOS Keychain. No gogcli runtime remains.

## Completed

- 60 Python tests cover routing, wrong-account blocking, identity-bound references, bounded Unicode reads, HTML conversion, header injection, attachment changes, request reuse/conflict, concurrent sends, and uncertain outcomes. Recipient tests cover addressed aliases versus authenticated mailboxes, repeated delivery headers, forwarding/group context, metadata-only search, visible versus absent Bcc, and bounded routing output.
- OAuth tests cover exact Gmail-only scopes, PKCE/offline authorization, state validation, wrong-mailbox rejection before storage, refresh verification, cached access, excess-scope rejection on refresh, and foreign client endpoints.
- Transport tests verify three bounded attempts for transient GET failures, redacted provider errors, and no automatic retry of a send POST.
- Native MIME tests cover Unicode, To/Bcc/From, reply headers/thread IDs, and attachments. Alias tests cover local allowlists, account-specific selection, live accepted/pending/missing approval, shared-purpose metadata, invalid shared flags, display-name injection, read-only settings access, selected From/Reply-To, actual stored sender verification, and replay protection across aliases.
- A real macOS Keychain write/read/delete round trip passed using a temporary random test record. No secret values were printed; the test record was removed.
- Codex plugin and skill validation passed; the standalone plugin was installed from the personal marketplace.
- The three requested account-purpose entries were saved in owner-only local configuration outside Git.
- Synthetic benchmark with recipient/delivery context: 23 discovery tokens, 451 full-skill tokens, zero MCP schemas; ten headers 1,033 to 827 tokens; a long-message first chunk 21,955 to 776 tokens. The chunk returns 4,000 of 21,400 characters and preserves continuation. These are fixture measurements, not live mail or billing savings.

## Live connection verification

The dedicated Google Cloud project has Gmail API enabled, a Desktop OAuth client named Email Agent Desktop, and an External audience. The publishing status was verified as **In production** before any mailbox was connected. Google's unverified-app notice remains for this personal-use application; production status does not imply Google verification.

The first three configured accounts, `personal`, `dittodub` (previously `work`), and `maker`, were authenticated and verified as follows:

- The initial token exchange returned exactly `gmail.readonly` and `gmail.send`.
- The Gmail profile matched the configured email address before the refresh token was stored.
- Credentials were saved in macOS Keychain, and a real refresh exchange succeeded.
- Google did not return a fixed refresh-token expiration interval. This does not guarantee perpetual access; Google revocation and policy rules still apply.
- A fresh process successfully searched for one inbox message and read it through the normal client. The initial personal result contained 1,214 body characters; work contained 1,000; maker contained 2,831. All stayed within the 4,000-character default, and search/read results were marked untrusted. Private message content was not included in the verification report or repository.

The client secret was captured from Google's one-time display directly into Keychain without printing it or placing it in source, command arguments, or a secret file. Account notes remain in owner-only local configuration. The generic public privacy notice required for app branding contains no mailbox data or credentials.

## Live send and recipient-context verification

At the user's request, one clearly labeled delivery-test email was sent from the `work` account to the `personal` account using the installed plugin and a stable request ID. The plugin recorded a successful send. A recipient-side search returned exactly one matching message. The sent and received copies matched in sender, recipient, subject, and body after normalizing transport whitespace, including a Unicode check mark. The received message's Delivered-To header matched the authenticated personal mailbox.

The updated client also searched and read existing messages addressed to the user's team and contact addresses but delivered to the work mailbox. Both live examples preserved the original To address and the separate Delivered-To/mailbox identity. Account addresses, message references, and private message content remain outside this repository. Reading recipient/forwarding context required no additional Google scopes.


## Shared sender setup and verification

The company mailbox now uses a company-specific account ID instead of the generic work ID. Its primary address remains the default. Local Team and Contact notes explicitly mark them shared: mail and replies reach other people. The installed skill uses shared senders only when requested or clearly implied by shared company correspondence, never solely because incoming mail addressed the group. Personal matters use the personal mailbox, and individual company correspondence uses the primary company address.

Team was added and verified through Gmail's normal Send mail as UI. The installed plugin sent one clearly labeled Team test to the user's personal mailbox with a stable request ID. Exactly one copy arrived; its From was the verified Team identity, Reply-To was Team, To and Delivered-To matched the personal mailbox, and the body matched the sent copy after transport whitespace normalization. No reply was sent to the shared group.

Contact's setup was completed after the user sent the verification email. Google's confirmation page was completed, and the Gmail API now reports both Team and Contact accepted. The installed plugin sent one clearly labeled Contact test to the personal mailbox with its own stable request ID. Exactly one copy arrived with the correct Contact From and Reply-To, personal To/Delivered-To, and matching body. No test reply was sent to either shared group. Neither alias required additional OAuth scopes, settings-write permission, or a new token grant.


## Fourth company mailbox

The `runs-the-place` account was connected through its dedicated Runs-The-Place Chrome profile. The profile's signed-in email matched the requested mailbox. Local purpose notes reserve this identity for that company's management, setup, operations, and business correspondence, separately from DittoDub, other companies, personal mail, and unrelated personal development.

The initial exchange granted exactly Gmail read and send scopes. The exact Gmail profile identity was verified before storage in macOS Keychain, and an immediate refresh exchange passed. A fresh process using the installed plugin then verified identity, searched an inbox message, and read a 1,243-character body within the default 4,000-character limit. No message content or new mailbox credentials were included in this report or repository. Account metadata remains outside Git with file mode 600.

All four configured mailboxes are now authenticated. Team and Contact remain shared sending aliases of the DittoDub mailbox, with separate purpose notes and accepted Gmail verification.


## Remote deployment checks

Eight deployment tests cover source path traversal, exact credential record selection, mismatched credential identities and excess scopes, derived-key-only export, conservative ledger merging/conflicts, redacted failure output, rejection of a wrong remote computer before credential access, and atomic owner-only account files. These tests use synthetic credentials. Live deployment to the owner's remote Mac succeeded. The SSH host key and exact computer/user identity were checked before credential access. Direct SSH Keychain writes were unavailable; a synthetic write/read/delete probe verified the logged-in desktop session, and the final transfer used a one-time process in that session with a private Unix socket. No credential values were placed in source, temporary files, command arguments, or logs.

The existing Gmail client and four configured refresh grants were copied directly into remote Keychain. All four exact mailbox identities refreshed successfully. Fresh processes using the installed plugin then searched and read a message from each mailbox, and live sender checks reported both shared aliases accepted. The remote personal marketplace reports Email Agent installed and enabled at the same version as the local Mac; installed file contents match the deployed source.

All 60 tests also passed on the remote Mac's Python 3.9.6. A second deployment without credential copying succeeded and reused remote Keychain records, proving the ordinary update path. The three existing send-ledger records were merged conservatively. All four local accounts were reverified afterward. No new email was sent as part of remote deployment.


## Cleanup and restore update — September 4, 2026

All 74 Python tests passed locally. The new tests cover fixed bounded selections, wrong mailbox and missing permission, draft rejection and a draft race, repeated operations, Trash and restore, ambiguous POST outcomes, stopping remaining work, legacy read/send compatibility, and the transport allowlist blocking permanent deletion and unrelated writes. The synthetic benchmark now measures 27 discovery tokens and 576 full-skill tokens; search/read payload sizes are unchanged.

All four mailboxes reconnected with exactly `gmail.modify`. Each connection verified the configured identity and a real refresh exchange, storing renewable grants in macOS Keychain. Google returned no fixed refresh-token expiration interval. The existing DittoDub setup delivery test was moved to Trash and restored; both states were checked, and the original complete label set was restored. No new mail was sent or bulk cleanup performed.


## Organization, attachments, and Gmail settings — September 5, 2026

All 100 Python tests pass locally. Added checks cover organization and inverse changes, mailbox-bound selections, label validity/drafts, uncertain writes and batch stops, attachment size and identity, inline and fetched attachment bytes, output path/symlink/overwrite protection, full-query filter criteria, unknown/forwarding action rejection, filter creation replay/concurrency/conflicts, removal backups and absence verification, bounded list output, and empty HTTP 204 filter lists observed from Gmail.

All four configured accounts reconnected with exactly `gmail.modify` and `gmail.settings.basic`, with matching profiles and real refresh verification. All four passed label/filter access checks. A live setup message's inbox, read/unread, star, and importance states were changed and its original label set restored. An inert temporary filter was created, verified, backed up, deleted, and verified absent. A selected existing 1,117,302-byte attachment was downloaded with mode 600, verified by size and SHA-256, then its temporary local copy removed. No new email or lasting saved rule was created.

The synthetic benchmark now measures 28 discovery tokens and 615 full-skill tokens. The longer mailbox command reference loads only for relevant tasks. Search remains 827 tokens for ten fixture headers; the bounded read is 785 tokens, including labels, versus 21,955 for the full fixture.
