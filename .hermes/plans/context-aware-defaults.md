# Context-Aware Dialog Defaults for OpenSnitch

## Problem
Currently, the prompt dialog remembers the last selected options (Allow/Deny, duration,
advanced checkboxes) GLOBALLY. Whatever you pick for Steam becomes the default for
curl, Firefox, everything. This is frustrating because different apps need different
defaults.

## Goal
Make dialog defaults context-aware: if you set "Allow 1h + filter by dst IP" for Steam,
that becomes the default for Steam-related processes. If you set "Deny" for a suspicious
curl command, that becomes the default for similar curl commands. But games launched by
Steam should NOT inherit Steam's defaults.

## Context Matching Hierarchy (most specific -> least specific)

1. **Exact process path** - `/home/user/.local/share/Steam/ubuntu12_32/steamwebhelper`
2. **Process name + parent directory** - `steamwebhelper` in `ubuntu12_32/`
   (groups steam siblings: steam, steamwebhelper, steamclient, steamerrorreporter)
3. **Process name + installation root** - anything under `.local/share/Steam/`
   EXCEPT `SteamApps/common/` (excludes games launched by Steam)
4. **Process command line** - `curl https://example.com`
5. **Destination host** - `steamcommunity.com`
6. **Global LAST_USED_*** - current fallback behavior

## Files to Modify

- `ui/opensnitch/config.py` - Add LAST_USED_*_CTX_* constants, context management methods
- `ui/opensnitch/dialogs/prompt/utils.py` - Context key extraction function
- `ui/opensnitch/dialogs/prompt/dialog.py` - Modify `_render_connection()` and `_send_rule()`

## Task Breakdown

### TASK 1: Context key extraction logic (utils.py)
- Create `build_context_keys(connection)` function
- Input: connection object (has process_path, process_args, dst_ip, dst_host)
- Output: ordered list of context identifiers (most specific first)
- Handle edge cases: /proc paths, very long cmdlines, empty fields
- Special: exclude SteamApps/common/ from Steam directory grouping

### TASK 2: Config constants + context storage (config.py)
- Add pattern: `LAST_USED_{field}_CTX_{context_hash}`
- Keep global LAST_USED_* for backward compatibility
- Add: `MAX_CONTEXTS` (default 100), `CONTEXT_EXPIRY_DAYS` (default 30)
- Add: `get_context_setting(field, context_keys)` method
- Add: `set_context_setting(field, value, context_key)` method
- Add: `cleanup_old_contexts()` method

### TASK 3: Modify _render_connection() load logic (dialog.py)
- Call `build_context_keys(connection)` to get ordered list
- For each LAST_USED_* field, call `get_context_setting()` which walks the list
- Use first match found, fall back to global LAST_USED_*, then DEFAULT_*
- Add debug logging: which context matched (or didn't)

### TASK 4: Modify _send_rule() save logic (dialog.py)
- After user clicks Allow/Deny, call `set_context_setting()` with the most
  specific context key from `build_context_keys()`
- ALSO update global LAST_USED_* keys (backward compatibility)
- Track usage timestamp for cleanup

### TASK 5: Context cleanup mechanism
- In `config.py`, add `cleanup_old_contexts()` that:
  - Scans all LAST_USED_*_CTX_* keys
  - Removes keys not accessed in N days
  - Removes oldest keys if count exceeds MAX_CONTEXTS
- Call cleanup on app startup (once per session)
- Add "Clear Context History" button in settings dialog

### TASK 6: Settings UI integration
- Add checkbox: "Use context-aware defaults" (enable/disable feature)
- Add button: "Clear Context History"
- Add slider: "Max remembered contexts" (10-500, default 100)
- Add slider: "Expire after N days" (7-365, default 30)

### TASK 7: Debug logging
- Log which context matched for each prompt
- Log when a new context is saved
- Log cleanup events (keys removed)

### TASK 8: Testing
- Steam from desktop shortcut vs terminal (should share via directory)
- Steam siblings (steamwebhelper, steamclient) - should share defaults
- Games launched from Steam (dota2, csgo) - should NOT share with Steam
- curl with different URLs - separate contexts via command line
- Unknown processes - fall back to global defaults
- Edge cases: /proc/self paths, very long command lines, empty process info

## Current Code Reference

### config.py LAST_USED constants (lines ~528-561):
LAST_USED_ACTION = "global/popup_last_action"
LAST_USED_DURATION = "global/popup_last_duration"
LAST_USED_TARGET = "global/popup_last_target"
LAST_USED_ADVANCED = "global/popup_last_advanced"
LAST_USED_DSTIP = "global/popup_last_dstip"
LAST_USED_DSTPORT = "global/popup_last_dstport"
LAST_USED_UID = "global/popup_last_uid"
LAST_USED_CHECKSUM = "global/popup_last_checksum"

### dialog.py _render_connection() load logic (lines ~555-600):
Loads global LAST_USED_* values into UI widgets (whatCombo, durationCombo,
checkDstIP, checkDstPort, checkUserID, checkSum, checkAdvanced).

### dialog.py _send_rule() save logic (lines ~735-743):
self._cfg.setSettings(self._cfg.LAST_USED_ACTION, self._default_action)
self._cfg.setSettings(self._cfg.LAST_USED_DURATION, self.durationCombo.currentIndex())
self._cfg.setSettings(self._cfg.LAST_USED_TARGET, self.whatCombo.currentIndex())
self._cfg.setSettings(self._cfg.LAST_USED_ADVANCED, self._ischeckAdvanceded)
self._cfg.setSettings(self._cfg.LAST_USED_DSTIP, self.checkDstIP.isChecked())
self._cfg.setSettings(self._cfg.LAST_USED_DSTPORT, self.checkDstPort.isChecked())
self._cfg.setSettings(self._cfg.LAST_USED_UID, self.checkUserID.isChecked())
self._cfg.setSettings(self._cfg.LAST_USED_CHECKSUM, self.checkSum.isChecked())

## Progress
- [ ] TASK 1: Context key extraction (utils.py)
- [ ] TASK 2: Config constants + context storage (config.py)
- [ ] TASK 3: Modify _render_connection() (dialog.py)
- [ ] TASK 4: Modify _send_rule() (dialog.py)
- [ ] TASK 5: Context cleanup mechanism
- [ ] TASK 6: Settings UI integration
- [ ] TASK 7: Debug logging
- [ ] TASK 8: Testing