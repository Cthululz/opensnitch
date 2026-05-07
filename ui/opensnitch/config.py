from PyQt6 import QtCore
from opensnitch.database import Database

class Config:
    __instance = None

    HELP_URL = "https://github.com/evilsocket/opensnitch/wiki/"
    HELP_RULES_URL = "https://github.com/evilsocket/opensnitch/wiki/Rules"
    HELP_SYS_RULES_URL = "https://github.com/evilsocket/opensnitch/wiki/System-rules#upgrading-from-previous-versions"
    HELP_SYSFW_URL = "https://github.com/evilsocket/opensnitch/wiki/System-rules"
    HELP_CONFIG_URL = "https://github.com/evilsocket/opensnitch/wiki/Configurations"
    HELP_SYSTRAY_WARN = "https://github.com/evilsocket/opensnitch/wiki/GUI-known-problems#gui-does-not-show-up"

    OPERAND_PROCESS_ID = "process.id"
    OPERAND_PROCESS_PATH = "process.path"
    OPERAND_PROCESS_COMMAND = "process.command"
    OPERAND_PROCESS_ENV = "process.env."
    OPERAND_PROCESS_HASH_MD5 = "process.hash.md5"
    OPERAND_PROCESS_HASH_SHA1 = "process.hash.sha1"
    OPERAND_USER_ID = "user.id"
    OPERAND_IFACE_OUT = "iface.out"
    OPERAND_IFACE_IN = "iface.in"
    OPERAND_SOURCE_IP = "source.ip"
    OPERAND_SOURCE_PORT = "source.port"
    OPERAND_DEST_IP = "dest.ip"
    OPERAND_DEST_HOST = "dest.host"
    OPERAND_DEST_PORT = "dest.port"
    OPERAND_DEST_NETWORK = "dest.network"
    OPERAND_SOURCE_NETWORK = "source.network"
    OPERAND_PROTOCOL = "protocol"
    OPERAND_LIST_DOMAINS = "lists.domains"
    OPERAND_LIST_DOMAINS_REGEXP = "lists.domains_regexp"
    OPERAND_LIST_IPS = "lists.ips"
    OPERAND_LIST_NETS = "lists.nets"

    RULE_TYPE_LIST = "list"
    RULE_TYPE_LISTS = "lists"
    RULE_TYPE_SIMPLE = "simple"
    RULE_TYPE_REGEXP = "regexp"
    RULE_TYPE_NETWORK = "network"
    RulesTypes = (RULE_TYPE_LIST, RULE_TYPE_LISTS, RULE_TYPE_SIMPLE, RULE_TYPE_REGEXP, RULE_TYPE_NETWORK)

    DEFAULT_TARGET_PROCESS = 0
    ACTION_DROP_IDX = 0
    ACTION_DENY_IDX = 0
    ACTION_ALLOW_IDX = 1
    ACTION_REJECT_IDX = 2

    # Missing from upstream 1.8.0
    DEFAULT_PERSIST_INTERCEPTION_STATE = "global/persist_interception_state"
    DEFAULT_FW_INTERCEPTION_ENABLED = "global/fw_interception_enabled"
    LAST_USED_ACTION = "global/last_used_action"
    LAST_USED_DURATION = "global/last_used_duration"
    LAST_USED_TARGET = "global/last_used_target"
    LAST_USED_UID = "global/last_used_uid"
    LAST_USED_DSTIP = "global/last_used_dstip"
    LAST_USED_DSTPORT = "global/last_used_dstport"
    LAST_USED_CHECKSUM = "global/last_used_checksum"
    LAST_USED_ADVANCED = "global/last_used_advanced"
    RULE_TYPE_RANGE = "range"

    # Duration constants referenced but missing
    DURATION_5 = "5m"
    DURATION_15 = "15m"
    DURATION_30 = "30m"
    DURATION_1 = "1h"
    DURATION_12 = "12h"
    # CONTEXT_FIELD_ is just a prefix used in string matching, not a real constant

    # don't translate
    ACTION_ALLOW = "allow"
    ACTION_DENY = "deny"
    ACTION_REJECT = "reject"
    ACTION_ACCEPT = "accept"
    ACTION_DROP = "drop"
    ACTION_JUMP = "jump"
    ACTION_REDIRECT = "redirect"
    ACTION_RETURN = "return"
    ACTION_TPROXY = "tproxy"
    ACTION_SNAT = "snat"
    ACTION_DNAT = "dnat"
    ACTION_MASQUERADE = "masquerade"
    ACTION_QUEUE = "queue"
    ACTION_LOG = "log"
    ACTION_STOP = "stop"

    DURATION_FIELD = "duration"
    DURATION_UNTIL_RESTART = "until restart"
    DURATION_ALWAYS = "always"
    DURATION_ONCE = "once"
    DURATION_12h = "12h"
    DURATION_1h = "1h"
    DURATION_30m = "30m"
    DURATION_15m = "15m"
    DURATION_5m = "5m"
    DURATION_30s = "30s"
    DEFAULT_DURATION_OPTIONS = [
        DURATION_ONCE, DURATION_30s, DURATION_5m,
        DURATION_15m, DURATION_30m, DURATION_1h,
        DURATION_12h,
        DURATION_UNTIL_RESTART,
        DURATION_ALWAYS
    ]

    # Rules of this list are ignored/deleted
    RULES_DURATION_FILTER = ()
    # Rules of this list are active
    RULES_ACTIVE_TEMPORARY_RULES = ()
    RULES_TEMPORARY_LIST = list(DEFAULT_DURATION_OPTIONS[:-1])
    CUSTOM_DURATIONS_KEY = "global/custom_durations"

    DEFAULT_DURATION_IDX = 6 # until restart

    POPUP_CENTER = 0
    POPUP_TOP_RIGHT = 1
    POPUP_BOTTOM_RIGHT = 2
    POPUP_TOP_LEFT = 3
    POPUP_BOTTOM_LEFT = 4

    DEFAULT_THEME = "global/theme"
    DEFAULT_THEME_DENSITY_SCALE = "global/theme_density_scale"
    DEFAULT_LANGUAGE = "global/language"
    DEFAULT_LANGNAME = "global/langname"
    DEFAULT_DISABLE_POPUPS = "global/disable_popups"
    DEFAULT_TIMEOUT_KEY  = "global/default_timeout"
    DEFAULT_ACTION_KEY   = "global/default_action"
    DEFAULT_DURATION_KEY = "global/default_duration"
    DEFAULT_TARGET_KEY   = "global/default_target"
    DEFAULT_IGNORE_RULES = "global/default_ignore_rules"
    DEFAULT_IGNORE_TEMPORARY_RULES = "global/default_ignore_temporary_rules"
    DEFAULT_POPUP_POSITION = "global/default_popup_position"
    DEFAULT_POPUP_ADVANCED = "global/default_popup_advanced"
    DEFAULT_POPUP_ADVANCED_DSTIP = "global/default_popup_advanced_dstip"
    DEFAULT_POPUP_ADVANCED_DSTPORT = "global/default_popup_advanced_dstport"
    DEFAULT_POPUP_ADVANCED_UID = "global/default_popup_advanced_uid"
    DEFAULT_POPUP_ADVANCED_CHECKSUM = "global/default_popup_advanced_checksum"
    # Global last-used popup settings (backward compatibility)
    DEFAULT_POPUP_LAST_ACTION = "global/popup_last_action"
    DEFAULT_POPUP_LAST_DURATION = "global/popup_last_duration"
    DEFAULT_POPUP_LAST_TARGET = "global/popup_last_target"
    DEFAULT_POPUP_LAST_DSTIP = "global/popup_last_dstip"
    DEFAULT_POPUP_LAST_DSTPORT = "global/popup_last_dstport"
    DEFAULT_POPUP_LAST_USERID = "global/popup_last_userid"
    DEFAULT_POPUP_LAST_ADVANCED = "global/popup_last_advanced"

    # Context-aware popup settings (keyed by process/command/host)
    CONTEXT_AWARE_ENABLED = "global/context_aware_enabled"
    CONTEXT_MAX_KEYS = "global/context_max_keys"
    CONTEXT_EXPIRY_DAYS = "global/context_expiry_days"
    CONTEXT_KEY_PREFIX = "global.popup_ctx."

    # Fields stored per context
    CONTEXT_FIELD_ACTION = "action"
    CONTEXT_FIELD_DURATION = "duration"
    CONTEXT_FIELD_TARGET = "target"
    CONTEXT_FIELD_ADVANCED = "advanced"
    CONTEXT_FIELD_DSTIP = "dstip"
    CONTEXT_FIELD_DSTPORT = "dstport"
    CONTEXT_FIELD_UID = "uid"
    CONTEXT_FIELD_CHECKSUM = "checksum"
    CONTEXT_FIELDS = [
        CONTEXT_FIELD_ACTION, CONTEXT_FIELD_DURATION, CONTEXT_FIELD_TARGET,
        CONTEXT_FIELD_ADVANCED, CONTEXT_FIELD_DSTIP, CONTEXT_FIELD_DSTPORT,
        CONTEXT_FIELD_UID, CONTEXT_FIELD_CHECKSUM
    ]

    # Defaults
    DEFAULT_CONTEXT_MAX_KEYS = 100
    DEFAULT_CONTEXT_EXPIRY_DAYS = 30
    DEFAULT_SERVER_ADDR  = "global/server_address"
    NOTIFICATIONS_MISSED_POPUP_TMPL = "notifications/missed_popup_tmpl"
    DEFAULT_SERVER_LOG_FILE = "global/server_log_file"
    DEFAULT_SERVER_LOG_LEVEL = "global/server_log_level"
    DEFAULT_SERVER_KEEPALIVE = "global/server_keepalive"
    DEFAULT_SERVER_KEEPALIVE_TIMEOUT = "global/server_keepalive_timeout"
    DEFAULT_SERVER_MAX_MESSAGE_LENGTH  = "global/server_max_message_length"
    DEFAULT_SERVER_MAX_WORKERS = "global/server_max_workers"
    DEFAULT_SERVER_MAX_CLIENTS = "global/server_max_clients"
    DEFAULT_HIDE_SYSTRAY_WARN  = "global/hide_systray_warning"
    DEFAULT_DB_TYPE_KEY       = "database/type"
    DEFAULT_DB_FILE_KEY       = "database/file"
    DEFAULT_DB_PURGE_OLDEST   = "database/purge_oldest"
    DEFAULT_DB_MAX_DAYS       = "database/max_days"
    DEFAULT_DB_PURGE_INTERVAL = "database/purge_interval"
    DEFAULT_DB_JRNL_WAL       = "database/jrnl_wal"
    LAST_BOOT_ID = "global/last_boot_id"

    DEFAULT_TIMEOUT = 30

    NOTIFICATIONS_ENABLED = "notifications/enabled"
    NOTIFICATIONS_TYPE = "notifications/type"
    NOTIFICATION_TYPE_SYSTEM = 0
    NOTIFICATION_TYPE_QT = 1

    STATS_REFRESH_INTERVAL = "statsDialog/refresh_interval"
    STATS_GEOMETRY = "statsDialog/geometry"
    STATS_MAXIMIZED = "statsDialog/maximized"
    STATS_LAST_TAB = "statsDialog/last_tab"
    STATS_FILTER_TEXT = "statsDialog/general_filter_text"
    STATS_FILTER_ACTION = "statsDialog/general_filter_action"
    STATS_LIMIT_RESULTS = "statsDialog/general_limit_results"
    STATS_SHOW_COLUMNS = "statsDialog/show_columns"
    STATS_NODES_COL_STATE = "statsDialog/nodes_columns_state"
    STATS_GENERAL_COL_STATE = "statsDialog/general_columns_state"
    STATS_GENERAL_FILTER_TEXT = "statsDialog/"
    STATS_GENERAL_FILTER_ACTION = "statsDialog/"
    STATS_RULES_COL_STATE = "statsDialog/rules_columns_state"
    STATS_FW_COL_STATE = "statsDialog/firewall_columns_state"
    STATS_ALERTS_COL_STATE = "statsDialog/alerts_columns_state"
    STATS_NETSTAT_COL_STATE = "statsDialog/netstat_columns_state"
    STATS_RULES_TREE_EXPANDED_0 = "statsDialog/rules_tree_0_expanded"
    STATS_RULES_TREE_EXPANDED_1 = "statsDialog/rules_tree_1_expanded"
    STATS_RULES_SPLITTER_POS = "statsDialog/rules_splitter_pos"
    STATS_NODES_SPLITTER_POS = "statsDialog/nodes_splitter_pos"
    STATS_VIEW_COL_STATE =  "statsDialog/view_columns_state"
    STATS_VIEW_DETAILS_COL_STATE =  "statsDialog/view_details_columns_state"
    STATS_NETSTAT_FILTER_PROTO = "statsDialog/netstat_proto_filter"
    STATS_NETSTAT_FILTER_FAMILY = "statsDialog/netstat_family_filter"
    STATS_NETSTAT_FILTER_STATE = "statsDialog/netstat_state_filter"

    QT_PLATFORM_PLUGIN = "global/qt_platform_plugin"
    QT_AUTO_SCREEN_SCALE_FACTOR = "global/screen_scale_factor_auto"
    QT_SCREEN_SCALE_FACTOR = "global/screen_scale_factor"

    INFOWIN_GEOMETRY = "infoWindow/geometry"

    PLUGINS = "plugins/list"

    AUTH_TYPE = "auth/type"
    AUTH_CA_CERT = "auth/cacert"
    AUTH_CERT = "auth/cert"
    AUTH_CERTKEY = "auth/certkey"
    # don't translate

    @staticmethod
    def init():
        Config.__instance = Config()
        return Config.__instance

    @staticmethod
    def get():
        if Config.__instance == None:
            Config.__instance = Config()
        return Config.__instance

    def __init__(self):
        self.settings = QtCore.QSettings("opensnitch", "settings")

        if self.settings.value(self.DEFAULT_TIMEOUT_KEY) == None:
            self.setSettings(self.DEFAULT_TIMEOUT_KEY, self.DEFAULT_TIMEOUT)
        if self.settings.value(self.DEFAULT_ACTION_KEY) == None:
            self.setSettings(self.DEFAULT_ACTION_KEY, self.ACTION_DROP_IDX)
        if self.settings.value(self.DEFAULT_DURATION_KEY) == None:
            self.setSettings(self.DEFAULT_DURATION_KEY, self.DEFAULT_DURATION_IDX)
        if self.settings.value(self.DEFAULT_TARGET_KEY) == None:
            self.setSettings(self.DEFAULT_TARGET_KEY, self.DEFAULT_TARGET_PROCESS)
        if self.settings.value(self.DEFAULT_DB_TYPE_KEY) == None:
            self.setSettings(self.DEFAULT_DB_TYPE_KEY, Database.DB_TYPE_MEMORY)
            self.setSettings(self.DEFAULT_DB_FILE_KEY, Database.DB_IN_MEMORY)
            self.setSettings(self.DEFAULT_DB_JRNL_WAL, Database.DB_JRNL_WAL)

        self.setRulesDurationFilter(
            self.getBool(self.DEFAULT_IGNORE_RULES),
            self.getInt(self.DEFAULT_IGNORE_TEMPORARY_RULES)
        )

    def reload(self):
        self.settings = QtCore.QSettings("opensnitch", "settings")

    def hasKey(self, key):
        return self.settings.contains(key)

    def setSettings(self, path, value):
        self.settings.setValue(path, value)
        self.settings.sync()

    def getSettings(self, path):
        return self.settings.value(path)

    def getBool(self, path, default_value=False):
        return self.settings.value(path, type=bool, defaultValue=default_value)

    def getInt(self, path, default_value=0):
        try:
            return self.settings.value(path, type=int, defaultValue=default_value)
        except Exception:
            return default_value

    def getDefaultAction(self):
        _default_action = self.getInt(self.DEFAULT_ACTION_KEY)
        if _default_action == self.ACTION_ALLOW_IDX:
            return self.ACTION_ALLOW
        else:
            # TODO: use ACTION_DROP when 'drop' is added to the daemon
            return self.ACTION_DENY

    def get_duration_options(self):
        """Return configured durations, ensuring mandatory entries and sane order."""
        durations = []
        stored = self.getSettings(self.CUSTOM_DURATIONS_KEY)
        if stored:
            try:
                if isinstance(stored, str) and stored.strip().startswith("["):
                    import json
                    durations = json.loads(stored)
                elif isinstance(stored, (list, tuple)):
                    durations = list(stored)
                else:
                    durations = [d.strip() for d in str(stored).split(",")]
            except Exception:
                durations = []

        if len(durations) == 0:
            durations = list(self.DEFAULT_DURATION_OPTIONS)

        cleaned = []
        for d in durations:
            if d is None:
                continue
            val = str(d).strip()
            if val == "":
                continue
            if val not in cleaned:
                cleaned.append(val)

        required_first = [self.DURATION_ONCE]
        required_last = [self.DURATION_UNTIL_RESTART, self.DURATION_ALWAYS]

        result = []
        for req in required_first:
            if req not in result:
                result.append(req)

        for item in cleaned:
            if item in required_first or item in required_last:
                continue
            result.append(item)

        for req in required_last:
            if req not in result:
                result.append(req)

        Config.RULES_TEMPORARY_LIST = [d for d in result if d != self.DURATION_ALWAYS]
        return result

    def normalize_duration_index(self, idx):
        opts = self.get_duration_options()
        if idx is None:
            return 0
        try:
            idx = int(idx)
        except Exception:
            return 0
        if idx < 0:
            return 0
        if idx >= len(opts):
            return len(opts) - 1
        return idx

    def setRulesDurationFilter(self, ignore_temporary_rules=False, temp_rules=1):
        try:
            if ignore_temporary_rules:
                opts = Config.RULES_TEMPORARY_LIST
                Config.RULES_DURATION_FILTER = [rule for rule in opts if opts.index(rule) < temp_rules]
                Config.RULES_ACTIVE_TEMPORARY_RULES = [rule for rule in opts if opts.index(rule) >= temp_rules]
                #print("Temp rules preserved (RULES_DURATION_FILTER):", Config.RULES_DURATION_FILTER)
                #print("Temp rules to delete (ACTIVE_TEMPORARY_RULES):", Config.RULES_ACTIVE_TEMPORARY_RULES)

            else:
                Config.RULES_DURATION_FILTER = []
        except Exception as e:
            print("setRulesDurationFilter() exception:", e)

    def getMaxMsgLength(self):
        """return maximum configured length for the gRPC channel.
        Default size is 4MB, but in some scenarios it's not enough.
        """
        maxmsglen = 4194304
        maxmsglencfg = self.getSettings(Config.DEFAULT_SERVER_MAX_MESSAGE_LENGTH)
        if maxmsglencfg == '4MiB':
            maxmsglen = 4194304
        elif maxmsglencfg == '8MiB':
            maxmsglen = 8388608
        elif maxmsglencfg == '16MiB':
            maxmsglen = 16777216

        print("gRPC Max Message Length:", maxmsglencfg)
        print("                  Bytes:", maxmsglen)

        return maxmsglen

    # ---- Context-aware popup settings ----

    def context_aware_enabled(self):
        """Check if context-aware defaults are enabled."""
        return self.getBool(Config.CONTEXT_AWARE_ENABLED, default_value=True)

    def get_max_context_keys(self):
        """Get maximum number of context keys to store."""
        return self.getInt(Config.CONTEXT_MAX_KEYS, self.DEFAULT_CONTEXT_MAX_KEYS)

    def get_context_expiry_days(self):
        """Get number of days before context keys expire."""
        return self.getInt(Config.CONTEXT_EXPIRY_DAYS, self.DEFAULT_CONTEXT_EXPIRY_DAYS)

    def _context_key(self, context_id, field):
        """Build a full context setting key."""
        return f"{Config.CONTEXT_KEY_PREFIX}{context_id}/{field}"

    def get_context_setting(self, field, context_keys):
        """
        Look up a setting from the most specific context key (per-app path key).

        Args:
            field: One of Config.CONTEXT_FIELD_* constants
            context_keys: List of context identifiers (most specific first)

        Returns:
            The setting value, or None if not found
        """
        if not self.context_aware_enabled() or not context_keys:
            return None

        ctx_id = context_keys[0]
        key = self._context_key(ctx_id, field)
        if self.hasKey(key):
            self.setSettings(key + "/_last_access", self._now_timestamp())
            return self.getSettings(key)

        return None

    def set_context_setting(self, field, value, context_keys):
        """Save to the most specific context key (per-app path key)."""
        if not self.context_aware_enabled() or not context_keys:
            return

        ctx_id = context_keys[0]
        key = self._context_key(ctx_id, field)
        self.setSettings(key, value)
        self.setSettings(key + "/_last_access", self._now_timestamp())
        self.settings.sync()

    def clear_context_settings(self):
        """Clear all context-aware settings."""
        prefix = Config.CONTEXT_KEY_PREFIX
        all_keys = self.settings.allKeys()
        for key in all_keys:
            if key.startswith(prefix):
                self.settings.remove(key)
        self.settings.sync()

    def cleanup_old_contexts(self):
        """Remove expired or excess context keys."""
        import time

        max_keys = self.get_max_context_keys()
        expiry_days = self.get_context_expiry_days()
        expiry_seconds = expiry_days * 86400
        now = time.time()

        prefix = Config.CONTEXT_KEY_PREFIX
        all_keys = self.settings.allKeys()

        # Find all context keys with timestamps
        context_keys = []
        for key in all_keys:
            if key.startswith(prefix) and not key.endswith("/_last_access"):
                ts_key = key + "/_last_access"
                ts_value = self.settings.value(ts_key)
                if ts_value is not None:
                    try:
                        ts = float(ts_value)
                        context_keys.append((key, ts))
                    except (ValueError, TypeError):
                        context_keys.append((key, 0))
                else:
                    context_keys.append((key, 0))

        # Sort by timestamp (oldest first)
        context_keys.sort(key=lambda x: x[1])

        removed = 0
        # Remove expired keys
        to_remove = []
        for key, ts in context_keys:
            if now - ts > expiry_seconds:
                to_remove.append(key)
        for key in to_remove:
            self.settings.remove(key)
            self.settings.remove(key + "/_last_access")
            removed += 1

        # If still over limit, remove oldest
        remaining = [k for k, _ in context_keys if k not in to_remove]
        while len(remaining) > max_keys:
            oldest = remaining.pop(0)
            self.settings.remove(oldest)
            self.settings.remove(oldest + "/_last_access")
            removed += 1

        self.settings.sync()
        return removed

    @staticmethod
    def _now_timestamp():
        """Return current Unix timestamp as float."""
        import time
        return time.time()
