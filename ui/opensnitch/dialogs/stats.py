import threading
import datetime
import sys
import os
import csv
import io
import json
import math

from PyQt6 import QtCore, QtGui, uic, QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.version import version
from opensnitch.nodes import Nodes
from opensnitch.firewall import Firewall, Rules as FwRules
from opensnitch.database.enums import AlertFields, RuleFields
from opensnitch.dialogs.firewall import FirewallDialog
from opensnitch.dialogs.preferences import PreferencesDialog
from opensnitch.dialogs.ruleseditor import RulesEditorDialog
from opensnitch.dialogs.processdetails import ProcessDetailsDialog
from opensnitch.dialogs.conndetails import ConnDetails
from opensnitch.customwidgets.colorizeddelegate import ColorizedDelegate
from opensnitch.customwidgets.firewalltableview import FirewallTableModel
from opensnitch.customwidgets.generictableview import GenericTableModel
from opensnitch.customwidgets.addresstablemodel import AddressTableModel
from opensnitch.customwidgets.netstattablemodel import NetstatTableModel
from opensnitch.utils import Message, QuickHelp, AsnDB, Icons
from opensnitch.utils.duration import to_seconds
from opensnitch.utils.infowindow import InfoWindow
from opensnitch.utils.xdg import xdg_current_desktop
from opensnitch.actions import Actions
from opensnitch.plugins import PluginBase
from opensnitch.rules import Rule, Rules

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

DIALOG_UI_PATH = "%s/../res/stats.ui" % os.path.dirname(sys.modules[__name__].__file__)
class StatsDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    _trigger = QtCore.pyqtSignal(bool, bool)
    settings_saved = QtCore.pyqtSignal()
    close_trigger = QtCore.pyqtSignal()
    _status_changed_trigger = QtCore.pyqtSignal(bool)
    _shown_trigger = QtCore.pyqtSignal()
    _notification_trigger = QtCore.pyqtSignal(ui_pb2.Notification)
    _notification_callback = QtCore.pyqtSignal(str, ui_pb2.NotificationReply)
    _timeleft_timer = None

    SORT_ORDER = ["ASC", "DESC"]
    LIMITS = ["LIMIT 50", "LIMIT 100", "LIMIT 200", "LIMIT 300", ""]
    LAST_GROUP_BY = ""

    # general
    COL_TIME    = 0
    COL_NODE    = 1
    COL_ACTION  = 2
    COL_SRCPORT = 3
    COL_SRCIP   = 4
    COL_DSTIP   = 5
    COL_DSTHOST = 6
    COL_DSTPORT = 7
    COL_PROTO   = 8
    COL_UID     = 9
    COL_PID     = 10
    COL_PROCS   = 11
    COL_CMDLINE = 12
    COL_RULES   = 13
    # total number of columns: cols + 1
    GENERAL_COL_NUM = 14

    # nodes
    COL_N_STATUS = 2
    COL_N_HOSTNAME = 3
    COL_N_VERSION = 4
    COL_N_UPTIME = 5
    COL_N_RULES = 6
    COL_N_CONNECTIONS = 7
    COL_N_DROPPED = 8
    COL_N_KERNEL = 9

    # stats
    COL_WHAT   = 0

    # rules
    COL_R_NODE = 1
    COL_R_NAME = 2
    COL_R_ENABLED = 3
    COL_R_ACTION = 4
    COL_R_DURATION = 5
    COL_R_TIMELEFT = 6
    COL_R_DESCRIPTION = 7
    COL_R_CREATED = 8
    COL_R_TIMELEFT = 9

    # alerts
    COL_ALERT_TYPE = 2
    COL_ALERT_BODY = 3
    COL_ALERT_WHAT = 4
    COL_ALERT_PRIO = 5

    # procs
    COL_PROC_PID = 11

    CLEAR_APP = "app"
    CLEAR_DST = "dst"
    FILTER_RULES_ALL = 0
    FILTER_RULES_PERM = 1
    FILTER_RULES_TEMP_ACTIVE = 2
    FILTER_RULES_TEMP_EXPIRED = 3

    # netstat
    COL_NET_COMM = 0
    COL_NET_PROC = 1
    COL_NET_DST_IP = 5
    COL_NET_DST_PORT = 6
    COL_NET_UID = 8
    COL_NET_PID = 9
    COL_NET_FAMILY = 10
    COL_NET_IFACE = 11
    COL_NET_METADATA = 12

    TAB_MAIN  = 0
    TAB_NODES = 1
    TAB_RULES = 2
    TAB_HOSTS = 3
    TAB_PROCS = 4
    TAB_ADDRS = 5
    TAB_PORTS = 6
    TAB_USERS = 7
    TAB_NETSTAT = 8
    # these "specials" tables must be placed after the "real" tabs
    TAB_FIREWALL = 9 # in rules tab
    TAB_ALERTS = 10 # in rules tab

    # tree's top level items
    RULES_TREE_APPS  = 0
    RULES_TREE_ALERTS = 1
    RULES_TREE_NODES = 2
    RULES_TREE_FIREWALL = 3

    RULES_TREE_PERMANENT = 0
    RULES_TREE_TEMPORARY = 1

    RULES_COMBO_PERMANENT = 1
    RULES_COMBO_TEMPORARY = 2
    RULES_COMBO_ALERTS = 3
    RULES_COMBO_FW = 4

    RULES_TYPE_PERMANENT = 0
    RULES_TYPE_TEMPORARY = 1
    RULES_ACTION_ALL = "all"
    RULES_ACTION_ALLOW = "allow"
    RULES_ACTION_DENY = "deny"
    RULE_FOCUS_LABEL_STYLE = "color: rgb(206, 92, 0); font-weight: bold;"

    FILTER_TREE_APPS = 0
    FILTER_TREE_NODES = 3

    FILTER_TREE_FW_NODE = 0
    FILTER_TREE_FW_TABLE = 1
    FILTER_TREE_FW_CHAIN = 2

    # FIXME: don't translate, used only for default argument on _update_status_label
    FIREWALL_DISABLED = "Disabled"

    # if the user clicks on an item of a table, it'll enter into the detail
    # view. From there, deny further clicks on the items.
    IN_DETAIL_VIEW = {
        TAB_MAIN: False,
        TAB_NODES: False,
        TAB_RULES: False,
        TAB_HOSTS: False,
        TAB_PROCS: False,
        TAB_ADDRS: False,
        TAB_PORTS: False,
        TAB_USERS: False,
        TAB_NETSTAT: False,
        TAB_FIREWALL: False,
        TAB_ALERTS: False
    }

    TABLES = {
        TAB_MAIN: {
            "name": "connections",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "commonDelegateConfig",
            "display_fields": "time as Time, " \
                    "node, " \
                    "action, " \
                    "src_port, " \
                    "src_ip, " \
                    "dst_ip, " \
                    "dst_host, " \
                    "dst_port, " \
                    "protocol, " \
                    "uid, " \
                    "pid, " \
                    "process, " \
                    "process_args, " \
                    "rule",
            "group_by": LAST_GROUP_BY,
            "last_order_by": "1",
            "last_order_to": 1,
            "tracking_column:": COL_TIME
        },
        TAB_NODES: {
            "name": "nodes",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "commonDelegateConfig",
            "display_fields": "last_connection as LastConnection, "\
                    "addr as Addr, " \
                    "status as Status, " \
                    "hostname as Hostname, " \
                    "daemon_version as Version, " \
                    "daemon_uptime as Uptime, " \
                    "daemon_rules as Rules," \
                    "cons as Connections," \
                    "cons_dropped as Dropped," \
                    "version as Version",
            "header_labels": [],
            "last_order_by": "1",
            "last_order_to": 1,
            "tracking_column:": COL_TIME
        },
        TAB_RULES: {
            "name": "rules",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "defaultRulesDelegateConfig",
            "display_fields": "time as Time," \
                    "node as Node," \
                    "name as Name," \
                    "enabled as Enabled," \
                    "action as Action," \
                    "duration as Duration," \
                    "'' as TimeLeft," \
                    "description as Description, " \
                    "created as Created",
            "header_labels": [],
            "last_order_by": "2",
            "last_order_to": 0,
            "tracking_column:": COL_R_NAME
        },
        TAB_HOSTS: {
            "name": "hosts",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "commonDelegateConfig",
            "display_fields": "*",
            "header_labels": [],
            "last_order_by": "2",
            "last_order_to": 1,
            "tracking_column:": COL_TIME
        },
        TAB_PROCS: {
            "name": "procs",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "commonDelegateConfig",
            "display_fields": "*",
            "header_labels": [],
            "last_order_by": "2",
            "last_order_to": 1,
            "tracking_column:": COL_TIME
        },
        TAB_ADDRS: {
            "name": "addrs",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "commonDelegateConfig",
            "display_fields": "*",
            "header_labels": [],
            "last_order_by": "2",
            "last_order_to": 1,
            "tracking_column:": COL_TIME
        },
        TAB_PORTS: {
            "name": "ports",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "commonDelegateConfig",
            "display_fields": "*",
            "header_labels": [],
            "last_order_by": "2",
            "last_order_to": 1,
            "tracking_column:": COL_TIME
        },
        TAB_USERS: {
            "name": "users",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "commonDelegateConfig",
            "display_fields": "*",
            "header_labels": [],
            "last_order_by": "2",
            "last_order_to": 1,
            "tracking_column:": COL_TIME
        },
        TAB_NETSTAT: {
            "name": "sockets",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "netstatDelegateConfig",
            "display_fields": "proc_comm as Comm," \
                "proc_path as Process, " \
                "state as State, " \
                "src_port as SrcPort, " \
                "src_ip as SrcIP, " \
                "dst_ip as DstIP, " \
                "dst_port as DstPort, " \
                "proto as Protocol, " \
                "uid as UID, " \
                "proc_pid as PID, " \
                "family as Family, " \
                "iface as IFace, " \
                "'inode: ' || inode || ', cookies: '|| cookies || ', rqueue: ' || rqueue || ', wqueue: ' || wqueue || ', expires: ' || expires || ', retrans: ' || retrans || ', timer: ' || timer as Metadata ",
            "header_labels": [],
            "last_order_by": "2",
            "last_order_to": 1,
            "tracking_column:": COL_TIME
        },
        TAB_FIREWALL: {
            "name": "firewall",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "defaultFWDelegateConfig",
            "display_fields": "*",
            "header_labels": [],
            "last_order_by": "2",
            "last_order_to": 0,
            "tracking_column:": COL_TIME
        },
        TAB_ALERTS: {
            "name": "alerts",
            "label": None,
            "cmd": None,
            "cmdCleanStats": None,
            "view": None,
            "filterLine": None,
            "model": None,
            "delegate": "defaultRulesDelegateConfig",
            "display_fields": "time as Time, " \
                "node as Node, " \
                "type as Type, " \
                "substr(what, 0, 128) as What, " \
                "substr(body, 0, 128) as Description ",
            "header_labels": [],
            "last_order_by": "1",
            "last_order_to": 0,
            "tracking_column:": COL_TIME
        }
    }

    def __init__(self, parent=None, address=None, db=None, dbname="db", appicon=None):
        super(StatsDialog, self).__init__(parent)

        self.setWindowFlags(QtCore.Qt.WindowType.Window)
        self.setupUi(self)
        self.setWindowIcon(appicon)

        # columns names. Must be added here in order to names be translated.
        self.COL_STR_NAME = QC.translate("stats", "Name", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_ADDR = QC.translate("stats", "Address", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_STATUS = QC.translate("stats", "Status", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_HOSTNAME = QC.translate("stats", "Hostname", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_UPTIME = QC.translate("stats", "Uptime", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_VERSION = QC.translate("stats", "Version", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_RULES_NUM = QC.translate("stats", "Rules", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_TIME = QC.translate("stats", "Time", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_CREATED = QC.translate("stats", "Created", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_ACTION = QC.translate("stats", "Action", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DURATION = QC.translate("stats", "Duration", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DESCRIPTION = QC.translate("stats", "Description", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_NODE = QC.translate("stats", "Node", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_ENABLED = QC.translate("stats", "Enabled", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PRECEDENCE = QC.translate("stats", "Precedence", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_HITS = QC.translate("stats", "Hits", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PROTOCOL = QC.translate("stats", "Protocol", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PROCESS = QC.translate("stats", "Process", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PROC_CMDLINE = QC.translate("stats", "Cmdline", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DESTINATION = QC.translate("stats", "Destination", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_SRC_PORT = QC.translate("stats", "SrcPort", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_SRC_IP = QC.translate("stats", "SrcIP", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DST_IP = QC.translate("stats", "DstIP", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DST_HOST = QC.translate("stats", "DstHost", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DST_PORT = QC.translate("stats", "DstPort", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_RULE = QC.translate("stats", "Rule", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_UID = QC.translate("stats", "UserID", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PID = QC.translate("stats", "PID", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_LAST_CONNECTION = QC.translate("stats", "LastConnection", "This is a word, without spaces and symbols.").replace(" ", "")

        self.FIREWALL_STOPPED  = QC.translate("stats", "Not running")
        self.FIREWALL_DISABLED = QC.translate("stats", "Disabled")
        self.FIREWALL_RUNNING  = QC.translate("stats", "Running")

        # restore scrollbar position when going back from a detail view
        self.LAST_SCROLL_VALUE = None
        # try to restore last selection
        self.LAST_SELECTED_ITEM = ""
        self.LAST_TAB = 0

        self._db = db
        self._db_sqlite = self._db.get_db()
        self._db_name = dbname

        self.asndb = AsnDB.instance()

        self._cfg = Config.get()
        self._nodes = Nodes.instance()
        self._fw = Firewall().instance()
        self._rules = Rules.instance()
        self._fw.rules.rulesUpdated.connect(self._cb_fw_rules_updated)
        self._nodes.nodesUpdated.connect(self._cb_nodes_updated)
        self._rules.updated.connect(self._cb_app_rules_updated)
        self._actions = Actions().instance()
        self._action_list = self._actions.getByType(PluginBase.TYPE_MAIN_DIALOG)
        self._last_update = datetime.datetime.now()
        self._rules_filter_mode = self.FILTER_RULES_ALL
        self._rules_filter_state = {
            "parent_row": -1,
            "item_row": self.RULES_TREE_APPS,
            "what": "",
            "what1": "",
            "what2": "",
            "action_filter": None,
            "rule_focus": None
        }
        self._rule_focus_breadcrumbs = []
        self._rule_reference_notice = None
        self._navigation_stack = []
        self._rules_filter_state_initialized = False
        self._setup_rules_action_subfilters()
        self._timeleft_timer = QtCore.QTimer(self)
        self._timeleft_timer.setInterval(5000)
        self._timeleft_timer.timeout.connect(self._update_timeleft_column)
        self._timeleft_timer.start()
        # keep track of expired temp rules we've already disabled
        self._expired_processed = set()

        # TODO: allow to display multiples dialogs
        self._proc_details_dialog = ProcessDetailsDialog(appicon=appicon)
        # TODO: allow to navigate records by offsets
        self.prevButton.setVisible(False)
        self.nextButton.setVisible(False)


        self.fwTable.setVisible(False)
        self.alertsTable.setVisible(False)
        self.rulesTable.setVisible(True)

        self.daemon_connected = False
        # skip table updates if a context menu is active
        self._context_menu_active = False
        # used to skip updates while the user is moving the scrollbar
        self.scrollbar_active = False

        self._lock = threading.RLock()
        self._address = address
        self._stats = None
        self._notifications_sent = {}

        self._fw_dialog = FirewallDialog(appicon=appicon)
        self._prefs_dialog = PreferencesDialog(appicon=appicon)
        self._rules_dialog = RulesEditorDialog(appicon=appicon)
        self._prefs_dialog.saved.connect(self._on_settings_saved)
        self._trigger.connect(self._on_update_triggered)
        self._notification_callback.connect(self._cb_notification_callback)

        self.nodeLabel.setText("")
        self.nodeLabel.setStyleSheet('color: green;font-size:12pt; font-weight:600;')
        self.rulesSplitter.setStretchFactor(0,0)
        self.rulesSplitter.setStretchFactor(1,5)
        self.nodesSplitter.setStretchFactor(0,0)
        self.nodesSplitter.setStretchFactor(0,3)
        self.rulesTreePanel.resizeColumnToContents(0)
        self.rulesTreePanel.resizeColumnToContents(1)
        self.rulesTreePanel.itemExpanded.connect(self._cb_rules_tree_item_expanded)

        self.startButton.clicked.connect(self._cb_start_clicked)
        self.nodeStartButton.clicked.connect(self._cb_node_start_clicked)
        self.nodeStartButton.setVisible(False)
        self.nodePrefsButton.setVisible(False)
        self.nodeActionsButton.setVisible(False)
        self.nodeDeleteButton.setVisible(False)
        self.nodeDeleteButton.clicked.connect(self._cb_node_delete_clicked)
        self.prefsButton.clicked.connect(self._cb_prefs_clicked)
        self.nodePrefsButton.clicked.connect(self._cb_node_prefs_clicked)
        self.fwButton.clicked.connect(lambda: self._fw_dialog.show())
        self.comboAction.currentIndexChanged.connect(self._cb_combo_action_changed)
        self.limitCombo.currentIndexChanged.connect(self._cb_limit_combo_changed)
        self.tabWidget.currentChanged.connect(self._cb_tab_changed)
        self.delRuleButton.clicked.connect(self._cb_del_rule_clicked)
        self.rulesSplitter.splitterMoved.connect(lambda pos, index: self._cb_splitter_moved(self.TAB_RULES, pos, index))
        self.nodesSplitter.splitterMoved.connect(lambda pos, index: self._cb_splitter_moved(self.TAB_NODES, pos, index))
        self.rulesTreePanel.itemClicked.connect(self._cb_rules_tree_item_clicked)
        self.rulesTreePanel.itemDoubleClicked.connect(self._cb_rules_tree_item_double_clicked)
        self.enableRuleCheck.clicked.connect(self._cb_enable_rule_toggled)
        self.editRuleButton.clicked.connect(self._cb_edit_rule_clicked)
        self.newRuleButton.clicked.connect(self._cb_new_rule_clicked)
        self.cmdProcDetails.clicked.connect(self._cb_proc_details_clicked)
        self.comboRulesFilter.currentIndexChanged.connect(self._cb_rules_filter_combo_changed)
        self.helpButton.clicked.connect(self._cb_help_button_clicked)
        self.nextButton.clicked.connect(self._cb_next_button_clicked)
        self.prevButton.clicked.connect(self._cb_prev_button_clicked)


        # TODO: move to utils/
        self.comboNetstatProto.clear()
        self.comboNetstatProto.addItem(QC.translate("stats", "ALL"), 0)
        self.comboNetstatProto.addItem("TCP", 6)
        self.comboNetstatProto.addItem("UDP", 17)
        self.comboNetstatProto.addItem("SCTP", 132)
        self.comboNetstatProto.addItem("DCCP", 33)
        self.comboNetstatProto.addItem("ICMP", 1)
        self.comboNetstatProto.addItem("ICMPv6", 58)
        self.comboNetstatProto.addItem("IGMP", 2)
        self.comboNetstatProto.addItem("RAW", 255)

        # These are sockets states. Conntrack uses a different enum.
        self.comboNetstatStates.clear()
        self.comboNetstatStates.addItem(QC.translate("stats", "ALL"), 0)
        self.comboNetstatStates.addItem("Established", 1)
        self.comboNetstatStates.addItem("TCP_SYN_SENT", 2)
        self.comboNetstatStates.addItem("TCP_SYN_RECV", 3)
        self.comboNetstatStates.addItem("TCP_FIN_WAIT1", 4)
        self.comboNetstatStates.addItem("TCP_FIN_WAIT2", 5)
        self.comboNetstatStates.addItem("TCP_TIME_WAIT", 6)
        self.comboNetstatStates.addItem("CLOSE", 7)
        self.comboNetstatStates.addItem("TCP_CLOSE_WAIT", 8)
        self.comboNetstatStates.addItem("TCP_LAST_ACK", 9)
        self.comboNetstatStates.addItem("LISTEN", 10)
        self.comboNetstatStates.addItem("TCP_CLOSING", 11)
        self.comboNetstatStates.addItem("TCP_NEW_SYN_RECV", 12)

        self.comboNetstatFamily.clear()
        self.comboNetstatFamily.addItem(QC.translate("stats", "ALL"), 0)
        self.comboNetstatFamily.addItem("AF_INET", 2)
        self.comboNetstatFamily.addItem("AF_INET6", 10)
        self.comboNetstatFamily.addItem("AF_PACKET", 17) # 0x11
        self.comboNetstatFamily.addItem("AF_XDP", 44)

        self.comboNetstatInterval.currentIndexChanged.connect(lambda index: self._cb_combo_netstat_changed(0, index))
        self.comboNetstatNodes.activated.connect(lambda index: self._cb_combo_netstat_changed(1, index))
        self.comboNetstatProto.currentIndexChanged.connect(lambda index: self._cb_combo_netstat_changed(2, index))
        self.comboNetstatFamily.currentIndexChanged.connect(lambda index: self._cb_combo_netstat_changed(3, index))
        self.comboNetstatStates.currentIndexChanged.connect(lambda index: self._cb_combo_netstat_changed(4, index))

        self.enableRuleCheck.setVisible(False)
        self.delRuleButton.setVisible(False)
        self.editRuleButton.setVisible(False)
        self.nodeRuleLabel.setVisible(False)
        self.comboRulesFilter.setVisible(False)

        menu = QtWidgets.QMenu()
        menu.addAction(Icons.new(self, "go-up"), QC.translate("stats", "Export rules")).triggered.connect(self._on_menu_node_export_clicked)
        menu.addAction(Icons.new(self, "go-down"), QC.translate("stats", "Import rules")).triggered.connect(self._on_menu_node_import_clicked)
        self.nodeActionsButton.setMenu(menu)

        menuActions = QtWidgets.QMenu()
        menuActions.addAction(Icons.new(self, "go-up"), QC.translate("stats", "Export rules")).triggered.connect(self._on_menu_export_clicked)
        menuActions.addAction(Icons.new(self, "go-down"), QC.translate("stats", "Import rules")).triggered.connect(self._on_menu_import_clicked)
        menuActions.addAction(Icons.new(self, "document-save"), QC.translate("stats", "Export events to CSV")).triggered.connect(self._on_menu_export_csv_clicked)
        menuActions.addAction(Icons.new(self, "application-exit"), QC.translate("stats", "Quit")).triggered.connect(self._on_menu_exit_clicked)
        self.actionsButton.setMenu(menuActions)

        # translations must be done here, otherwise they don't take effect
        self.TABLES[self.TAB_NODES]['header_labels'] = [
            self.COL_STR_LAST_CONNECTION,
            self.COL_STR_ADDR,
            self.COL_STR_STATUS,
            self.COL_STR_HOSTNAME,
            self.COL_STR_VERSION,
            self.COL_STR_UPTIME,
            QC.translate("stats", "Rules", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Connections", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Dropped", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Version", "This is a word, without spaces and symbols.").replace(" ", ""),
        ]

        self.TABLES[self.TAB_RULES]['header_labels'] = [
            self.COL_STR_TIME,
            self.COL_STR_NODE,
            self.COL_STR_NAME,
            self.COL_STR_ENABLED,
            self.COL_STR_ACTION,
            self.COL_STR_DURATION,
            QC.translate("stats", "Time left"),
            self.COL_STR_DESCRIPTION,
            self.COL_STR_CREATED,
        ]

        self.TABLES[self.TAB_ALERTS]['header_labels'] = [
            self.COL_STR_TIME,
            self.COL_STR_NODE,
            "Type",
            "What",
            self.COL_STR_DESCRIPTION,
            "Priority"
        ]

        stats_headers = [
            QC.translate("stats", "What", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Hits", "This is a word, without spaces and symbols.").replace(" ", ""),
        ]

        self.TABLES[self.TAB_HOSTS]['header_labels'] = stats_headers
        self.TABLES[self.TAB_PROCS]['header_labels'] = stats_headers
        self.TABLES[self.TAB_ADDRS]['header_labels'] = stats_headers
        self.TABLES[self.TAB_PORTS]['header_labels'] = stats_headers
        self.TABLES[self.TAB_USERS]['header_labels'] = stats_headers

        self.LAST_NETSTAT_NODE = None
        self.TABLES[self.TAB_NETSTAT]['header_labels'] = [
            "Comm",
            self.COL_STR_PROCESS,
            QC.translate("stats", "State", "This is a word, without spaces and symbols.").replace(" ", ""),
            self.COL_STR_SRC_PORT,
            self.COL_STR_SRC_IP,
            self.COL_STR_DST_IP,
            self.COL_STR_DST_PORT,
            self.COL_STR_PROTOCOL,
            self.COL_STR_UID,
            self.COL_STR_PID,
            QC.translate("stats", "Family", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Iface", "This is a word, without spaces and symbols.").replace(" ", ""),
            QC.translate("stats", "Metadata", "This is a word, without spaces and symbols.").replace(" ", "")
        ]

        self.TABLES[self.TAB_MAIN]['view'] = self._setup_table(QtWidgets.QTableView, self.eventsTable, "connections",
                self.TABLES[self.TAB_MAIN]['display_fields'],
                order_by="1",
                group_by=self.TABLES[self.TAB_MAIN]['group_by'],
                delegate=self.TABLES[self.TAB_MAIN]['delegate'],
                resize_cols=(),
                model=GenericTableModel("connections", [
                    self.COL_STR_TIME,
                    self.COL_STR_NODE,
                    self.COL_STR_ACTION,
                    self.COL_STR_SRC_PORT,
                    self.COL_STR_SRC_IP,
                    self.COL_STR_DST_IP,
                    self.COL_STR_DST_HOST,
                    self.COL_STR_DST_PORT,
                    self.COL_STR_PROTOCOL,
                    self.COL_STR_UID,
                    self.COL_STR_PID,
                    self.COL_STR_PROCESS,
                    self.COL_STR_PROC_CMDLINE,
                    self.COL_STR_RULE,
                ]),
                verticalScrollBar=self.connectionsTableScrollBar,
                limit=self._get_limit()
                )
        self.TABLES[self.TAB_NODES]['view'] = self._setup_table(QtWidgets.QTableView, self.nodesTable, "nodes",
                self.TABLES[self.TAB_NODES]['display_fields'],
                order_by="3,2,1",
                resize_cols=(self.COL_NODE,),
                model=GenericTableModel("nodes", self.TABLES[self.TAB_NODES]['header_labels']),
                verticalScrollBar=self.verticalScrollBar,
                sort_direction=self.SORT_ORDER[1],
                delegate=self.TABLES[self.TAB_NODES]['delegate'])
        self.TABLES[self.TAB_RULES]['view'] = self._setup_table(QtWidgets.QTableView, self.rulesTable, "rules",
                fields=self.TABLES[self.TAB_RULES]['display_fields'],
                model=GenericTableModel("rules", self.TABLES[self.TAB_RULES]['header_labels']),
                verticalScrollBar=self.rulesScrollBar,
                delegate=self.TABLES[self.TAB_RULES]['delegate'],
                order_by="2",
                sort_direction=self.SORT_ORDER[0],
                tracking_column=self.COL_R_NAME)
        rules_model = self.TABLES[self.TAB_RULES]['view'].model()
        rules_model.timeleft_index = self.COL_R_TIMELEFT
        self.TABLES[self.TAB_RULES]['view'].setSortingEnabled(True)
        rules_model.setSortRole(QtCore.Qt.ItemDataRole.UserRole)
        # make rules header configurable
        rules_header = self.rulesTable.horizontalHeader()
        rules_header.setStretchLastSection(False)
        rules_header.setSectionsMovable(True)
        rules_header.setSectionResizeMode(self.COL_R_TIMELEFT, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        self.TABLES[self.TAB_FIREWALL]['view'] = self._setup_table(QtWidgets.QTableView, self.fwTable, "firewall",
                model=FirewallTableModel("firewall"),
                verticalScrollBar=None,
                delegate=self.TABLES[self.TAB_FIREWALL]['delegate'],
                order_by="2",
                sort_direction=self.SORT_ORDER[0])
        self.TABLES[self.TAB_ALERTS]['view'] = self._setup_table(QtWidgets.QTableView, self.alertsTable, "alerts",
                fields=self.TABLES[self.TAB_ALERTS]['display_fields'],
                model=GenericTableModel("alerts", self.TABLES[self.TAB_ALERTS]['header_labels']),
                verticalScrollBar=self.rulesScrollBar,
                delegate=self.TABLES[self.TAB_ALERTS]['delegate'],
                order_by="1",
                sort_direction=self.SORT_ORDER[0])
        self.TABLES[self.TAB_HOSTS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.hostsTable, "hosts",
                model=GenericTableModel("hosts", self.TABLES[self.TAB_HOSTS]['header_labels']),
                verticalScrollBar=self.hostsScrollBar,
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_HOSTS]['delegate'],
                order_by="2",
                limit=self._get_limit()
                )
        self.TABLES[self.TAB_PROCS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.procsTable, "procs",
                model=GenericTableModel("procs", self.TABLES[self.TAB_PROCS]['header_labels']),
                verticalScrollBar=self.procsScrollBar,
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_PROCS]['delegate'],
                order_by="2",
                limit=self._get_limit()
                )
        self.TABLES[self.TAB_ADDRS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.addrTable, "addrs",
                model=AddressTableModel("addrs", self.TABLES[self.TAB_ADDRS]['header_labels']),
                verticalScrollBar=self.addrsScrollBar,
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_ADDRS]['delegate'],
                order_by="2",
                limit=self._get_limit()
                )
        self.TABLES[self.TAB_PORTS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.portsTable, "ports",
                model=GenericTableModel("ports", self.TABLES[self.TAB_PORTS]['header_labels']),
                verticalScrollBar=self.portsScrollBar,
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_PORTS]['delegate'],
                order_by="2",
                limit=self._get_limit()
                )
        self.TABLES[self.TAB_USERS]['view'] = self._setup_table(QtWidgets.QTableView,
                self.usersTable, "users",
                model=GenericTableModel("users", self.TABLES[self.TAB_USERS]['header_labels']),
                verticalScrollBar=self.usersScrollBar,
                resize_cols=(self.COL_WHAT,),
                delegate=self.TABLES[self.TAB_USERS]['delegate'],
                order_by="2",
                limit=self._get_limit()
                )
        self.TABLES[self.TAB_NETSTAT]['view'] = self._setup_table(QtWidgets.QTableView,
                self.netstatTable, "sockets",
                self.TABLES[self.TAB_NETSTAT]['display_fields'],
                model=NetstatTableModel("sockets", self.TABLES[self.TAB_NETSTAT]['header_labels']),
                verticalScrollBar=self.netstatScrollBar,
                #resize_cols=(),
                delegate=self.TABLES[self.TAB_NETSTAT]['delegate'],
                order_by="2",
                limit=self._get_limit(),
                tracking_column=self.COL_NET_METADATA
                )

        self.TABLES[self.TAB_NODES]['label'] = self.nodesLabel
        self.TABLES[self.TAB_RULES]['label'] = self.ruleLabel
        self.TABLES[self.TAB_HOSTS]['label'] = self.hostsLabel
        self.TABLES[self.TAB_PROCS]['label'] = self.procsLabel
        self.TABLES[self.TAB_ADDRS]['label'] = self.addrsLabel
        self.TABLES[self.TAB_PORTS]['label'] = self.portsLabel
        self.TABLES[self.TAB_USERS]['label'] = self.usersLabel
        self.TABLES[self.TAB_NETSTAT]['label'] = self.netstatLabel

        self.TABLES[self.TAB_NODES]['cmd'] = self.cmdNodesBack
        self.TABLES[self.TAB_RULES]['cmd'] = self.cmdRulesBack
        self.TABLES[self.TAB_HOSTS]['cmd'] = self.cmdHostsBack
        self.TABLES[self.TAB_PROCS]['cmd'] = self.cmdProcsBack
        self.TABLES[self.TAB_ADDRS]['cmd'] = self.cmdAddrsBack
        self.TABLES[self.TAB_PORTS]['cmd'] = self.cmdPortsBack
        self.TABLES[self.TAB_USERS]['cmd'] = self.cmdUsersBack
        self.TABLES[self.TAB_NETSTAT]['cmd'] = self.cmdNetstatBack

        self.TABLES[self.TAB_MAIN]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[self.TAB_NODES]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[self.TAB_RULES]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[self.TAB_HOSTS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[self.TAB_PROCS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[self.TAB_ADDRS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[self.TAB_PORTS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[self.TAB_USERS]['cmdCleanStats'] = self.cmdCleanSql
        self.TABLES[self.TAB_NETSTAT]['cmdCleanStats'] = self.cmdCleanSql
        # the rules clean button is only for a particular rule, not all.
        self.TABLES[self.TAB_MAIN]['cmdCleanStats'].clicked.connect(lambda: self._cb_clean_sql_clicked(self.TAB_MAIN))

        self.TABLES[self.TAB_MAIN]['filterLine'] = self.filterLine
        self.TABLES[self.TAB_MAIN]['view'].doubleClicked.connect(self._cb_main_table_double_clicked)
        self.TABLES[self.TAB_MAIN]['view'].installEventFilter(self)
        self.TABLES[self.TAB_MAIN]['filterLine'].textChanged.connect(self._cb_events_filter_line_changed)

        for idx in range(1,10):
            if self.TABLES[idx]['cmd'] != None:
                self.TABLES[idx]['cmd'].hide()
                self.TABLES[idx]['cmd'].setVisible(False)
                self.TABLES[idx]['cmd'].clicked.connect(lambda: self._cb_cmd_back_clicked(idx))
            if self.TABLES[idx]['cmdCleanStats'] != None:
                self.TABLES[idx]['cmdCleanStats'].clicked.connect(lambda: self._cb_clean_sql_clicked(idx))
            if self.TABLES[idx]['label'] != None:
                self.TABLES[idx]['label'].setStyleSheet('font-weight:600;')
                self.TABLES[idx]['label'].setVisible(False)
            self.TABLES[idx]['view'].doubleClicked.connect(self._cb_table_double_clicked)
            self.TABLES[idx]['view'].selectionModel().selectionChanged.connect(self._cb_table_selection_changed)
            self.TABLES[idx]['view'].installEventFilter(self)

        for idx in self.TABLES:
            view = self.TABLES[idx].get('view')
            if view is None:
                continue
            view.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
            view.customContextMenuRequested.connect(self._cb_table_context_menu)

        self.TABLES[self.TAB_FIREWALL]['view'].rowsReordered.connect(self._cb_fw_table_rows_reordered)

        self._load_settings()

        self._tables = ( \
            self.TABLES[self.TAB_MAIN]['view'],
            self.TABLES[self.TAB_NODES]['view'],
            self.TABLES[self.TAB_RULES]['view'],
            self.TABLES[self.TAB_HOSTS]['view'],
            self.TABLES[self.TAB_PROCS]['view'],
            self.TABLES[self.TAB_ADDRS]['view'],
            self.TABLES[self.TAB_PORTS]['view'],
            self.TABLES[self.TAB_USERS]['view'],
            self.TABLES[self.TAB_NETSTAT]['view']
        )
        self._file_names = ( \
            'events.csv',
            'nodes.csv',
            'rules.csv',
            'hosts.csv',
            'procs.csv',
            'addrs.csv',
            'ports.csv',
            'users.csv',
            'netstat.csv'
        )

        self.iconStart = Icons.new(self, "media-playback-start")
        self.iconPause = Icons.new(self, "media-playback-pause")

        self.fwTreeEdit = QtWidgets.QPushButton()
        self.fwTreeEdit.setIcon(QtGui.QIcon().fromTheme("preferences-desktop"))
        self.fwTreeEdit.autoFillBackground = True
        self.fwTreeEdit.setFlat(True)
        self.fwTreeEdit.setSizePolicy(
            QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Fixed)
        )
        self.fwTreeEdit.clicked.connect(self._cb_tree_edit_firewall_clicked)
        self._configure_buttons_icons()
        self._configure_plugins()

    #Sometimes a maximized window which had been minimized earlier won't unminimize
    #To workaround, we explicitely maximize such windows when unminimizing happens
    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.Type.WindowStateChange:
            if event.oldState() & QtCore.Qt.WindowState.WindowMinimized and event.oldState() & QtCore.Qt.WindowState.WindowMaximized:
                #a previously minimized maximized window ...
                if self.windowState() ^ QtCore.Qt.WindowState.WindowMinimized and xdg_current_desktop == "KDE":
                    # is not minimized anymore, i.e. it was unminimized
                    # docs: https://doc.qt.io/qt-5/qwidget.html#setWindowState
                    self.setWindowState(self.windowState() & ~QtCore.Qt.WindowState.WindowMinimized | QtCore.Qt.WindowState.WindowActive)

    def show(self):
        super(StatsDialog, self).show()
        self._shown_trigger.emit()
        window_title = QC.translate("stats", "OpenSnitch Network Statistics {0}").format(version)
        if self._address is not None:
            window_title = QC.translate("stats", "OpenSnitch Network Statistics for {0}").format(self._address)
            self.nodeLabel.setText(self._address)
        self._load_settings()
        self._add_rulesTree_nodes()
        self._add_rulesTree_fw_chains()
        self.setWindowTitle(window_title)
        self._refresh_active_table()
        self._show_columns()

    def eventFilter(self, source, event):
        if event.type() == QtCore.QEvent.Type.KeyPress:
            if event.matches(QtGui.QKeySequence.StandardKey.Copy):
                self._copy_selected_rows()
                return True
            elif event.key() == QtCore.Qt.Key.Key_Delete:
                table = self._get_active_table()
                selection = table.selectedRows()
                if selection:
                    model = table.model()
                    self._table_menu_delete(self.tabWidget.currentIndex(), model, selection)
                    # we need to manually refresh the model
                    table.selectionModel().clear()
                    self._refresh_active_table()
                return True
        return super(StatsDialog, self).eventFilter(source, event)

    def _configure_plugins(self):
        for conf in self._action_list:
            action = self._action_list[conf]
            for name in action['actions']:
                try:
                    action['actions'][name].configure(self)
                except Exception as e:
                    print("stats._configure_plugins() exception:", name, "-", e)

    def _configure_buttons_icons(self):

        newRuleIcon = Icons.new(self, "document-new")
        delRuleIcon = Icons.new(self, "edit-delete")
        editRuleIcon = Icons.new(self, "accessories-text-editor")
        prefsIcon = Icons.new(self, "preferences-system")
        searchIcon = Icons.new(self, "system-search")
        clearIcon = Icons.new(self, "edit-clear-all")
        leftArrowIcon = Icons.new(self, "go-previous")
        fwIcon = Icons.new(self, "security-high")
        optsIcon = Icons.new(self, "format-justify-fill")
        helpIcon = Icons.new(self, "help-browser")
        eventsIcon = Icons.new(self, "view-sort-ascending")
        rulesIcon = Icons.new(self, "address-book-new")
        procsIcon = Icons.new(self, "system-run")

        if QtGui.QIcon().hasThemeIcon("preferences-desktop") == False:
            self.fwTreeEdit.setText("+")

        self.tabWidget.setTabIcon(self.TAB_MAIN, eventsIcon)
        self.tabWidget.setTabIcon(self.TAB_RULES, rulesIcon)
        self.tabWidget.setTabIcon(self.TAB_PROCS, procsIcon)
        self.newRuleButton.setIcon(newRuleIcon)
        self.delRuleButton.setIcon(delRuleIcon)
        self.editRuleButton.setIcon(editRuleIcon)
        self.prefsButton.setIcon(prefsIcon)
        self.helpButton.setIcon(helpIcon)
        self.startButton.setIcon(self.iconStart)
        self.fwButton.setIcon(fwIcon)
        self.cmdProcDetails.setIcon(searchIcon)
        self.nodeStartButton.setIcon(self.iconStart)
        self.nodePrefsButton.setIcon(prefsIcon)
        self.nodeDeleteButton.setIcon(clearIcon)
        self.nodeActionsButton.setIcon(optsIcon)
        self.actionsButton.setIcon(optsIcon)
        self.TABLES[self.TAB_MAIN]['cmdCleanStats'].setIcon(clearIcon)
        for idx in range(1,8):
            self.TABLES[idx]['cmd'].setIcon(leftArrowIcon)
            if self.TABLES[idx]['cmdCleanStats'] != None:
                self.TABLES[idx]['cmdCleanStats'].setIcon(clearIcon)

    def _load_settings(self):
        self._ui_refresh_interval = self._cfg.getInt(Config.STATS_REFRESH_INTERVAL, 0)
        dialog_geometry = self._cfg.getSettings(Config.STATS_GEOMETRY)
        dialog_maximized = self._cfg.getBool(Config.STATS_MAXIMIZED)
        dialog_last_tab = self._cfg.getSettings(Config.STATS_LAST_TAB)
        dialog_general_filter_text = self._cfg.getSettings(Config.STATS_FILTER_TEXT)
        dialog_general_filter_action = self._cfg.getSettings(Config.STATS_FILTER_ACTION)
        dialog_general_limit_results = self._cfg.getSettings(Config.STATS_LIMIT_RESULTS)
        if dialog_geometry != None:
            self.restoreGeometry(dialog_geometry)
        if dialog_maximized and self.isVisible():
            self.showMaximized()
        if dialog_last_tab != None:
            self.tabWidget.setCurrentIndex(int(dialog_last_tab))
        if dialog_general_filter_action != None:
            self.comboAction.setCurrentIndex(int(dialog_general_filter_action))
        if dialog_general_limit_results != None:
            # XXX: a little hack, because if the saved index is 0, the signal is not fired.
            # XXX: this causes to fire the event twice
            self.limitCombo.blockSignals(True);
            self.limitCombo.setCurrentIndex(4)
            self.limitCombo.setCurrentIndex(int(dialog_general_limit_results))
            self.limitCombo.blockSignals(False);

        rules_splitter_pos = self._cfg.getSettings(Config.STATS_RULES_SPLITTER_POS)
        if type(rules_splitter_pos) == QtCore.QByteArray:
            self.rulesSplitter.restoreState(rules_splitter_pos)
            rulesSizes = self.rulesSplitter.sizes()
            if self.IN_DETAIL_VIEW[self.TAB_RULES] == True:
                self.comboRulesFilter.setVisible(False)
            elif len(rulesSizes) > 0:
                self.comboRulesFilter.setVisible(rulesSizes[0] == 0)
        else:
            # default position when the user hasn't moved it yet.

            # FIXME: The first time show() event is fired, this widget has no
            # real width yet. The second time is fired the width of the widget
            # is correct.
            w = self.rulesSplitter.width()
            self.rulesSplitter.setSizes([int(w/4), int(w/1)])

        nodes_splitter_pos = self._cfg.getSettings(Config.STATS_NODES_SPLITTER_POS)
        if type(nodes_splitter_pos) == QtCore.QByteArray:
            self.nodesSplitter.restoreState(nodes_splitter_pos)
            nodesSizes = self.nodesSplitter.sizes()
            self.nodesSplitter.setVisible(not self.IN_DETAIL_VIEW[self.TAB_NODES] and nodesSizes[0] > 0)
        else:
            w = self.nodesSplitter.width()
            self.nodesSplitter.setSizes([w, 0])

        self._configure_netstat_combos()

        self._restore_details_view_columns(self.eventsTable.horizontalHeader(), Config.STATS_GENERAL_COL_STATE)
        self._restore_details_view_columns(self.nodesTable.horizontalHeader(), Config.STATS_NODES_COL_STATE)
        self._restore_details_view_columns(self.rulesTable.horizontalHeader(), Config.STATS_RULES_COL_STATE)
        self._restore_details_view_columns(self.fwTable.horizontalHeader(), Config.STATS_FW_COL_STATE)
        self._restore_details_view_columns(self.alertsTable.horizontalHeader(), Config.STATS_ALERTS_COL_STATE)
        self._restore_details_view_columns(self.netstatTable.horizontalHeader(), Config.STATS_NETSTAT_COL_STATE)

        rulesTreeNodes_expanded = self._cfg.getBool(Config.STATS_RULES_TREE_EXPANDED_1)
        if rulesTreeNodes_expanded != None:
            rules_tree_nodes = self._get_rulesTree_item(self.RULES_TREE_NODES)
            if rules_tree_nodes != None:
                rules_tree_nodes.setExpanded(rulesTreeNodes_expanded)
        rulesTreeApps_expanded = self._cfg.getBool(Config.STATS_RULES_TREE_EXPANDED_0)
        if rulesTreeApps_expanded != None:
            rules_tree_apps = self._get_rulesTree_item(self.RULES_TREE_APPS)
            if rules_tree_apps != None:
                rules_tree_apps.setExpanded(rulesTreeApps_expanded)

        if dialog_general_filter_text != None:
            self.filterLine.setText(dialog_general_filter_text)

    def _save_settings(self):
        self._cfg.setSettings(Config.STATS_MAXIMIZED, self.isMaximized())
        self._cfg.setSettings(Config.STATS_GEOMETRY, self.saveGeometry())
        self._cfg.setSettings(Config.STATS_LAST_TAB, self.tabWidget.currentIndex())
        self._cfg.setSettings(Config.STATS_LIMIT_RESULTS, self.limitCombo.currentIndex())
        self._cfg.setSettings(Config.STATS_FILTER_TEXT, self.filterLine.text())

        header = self.eventsTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_GENERAL_COL_STATE, header.saveState())
        nodesHeader = self.nodesTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_NODES_COL_STATE, nodesHeader.saveState())
        rulesHeader = self.rulesTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_RULES_COL_STATE, rulesHeader.saveState())
        fwHeader = self.fwTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_FW_COL_STATE, fwHeader.saveState())
        alertsHeader = self.alertsTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_ALERTS_COL_STATE, alertsHeader.saveState())
        netstatHeader = self.netstatTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_NETSTAT_COL_STATE, netstatHeader.saveState())

        rules_tree_apps = self._get_rulesTree_item(self.RULES_TREE_APPS)
        if rules_tree_apps != None:
            self._cfg.setSettings(Config.STATS_RULES_TREE_EXPANDED_0, rules_tree_apps.isExpanded())
        rules_tree_nodes = self._get_rulesTree_item(self.RULES_TREE_NODES)
        if rules_tree_nodes != None:
            self._cfg.setSettings(Config.STATS_RULES_TREE_EXPANDED_1, rules_tree_nodes.isExpanded())

    def _del_by_field(self, cur_idx, table, value):
        model = self._get_active_table().model()
        # get left side of the query: * GROUP BY ...
        qstr = model.query().lastQuery().split("GROUP BY")[0]
        # get right side of the query: ... WHERE *
        q = qstr.split("WHERE")

        field = "dst_host"
        if cur_idx == self.TAB_NODES:
            field = "node"
        elif cur_idx == self.TAB_PROCS:
            field = "process"
        elif cur_idx == self.TAB_ADDRS:
            field = "dst_ip"
        elif cur_idx == self.TAB_PORTS:
            field = "dst_port"
        elif cur_idx == self.TAB_USERS:
            field = "uid"

        ret1 = self._db.remove("DELETE FROM {0} WHERE what = '{1}'".format(table, value))
        ret2 = self._db.remove("DELETE FROM connections WHERE {0} = '{1}'".format(field, value))

        return ret1 and ret2

    def _del_rule(self, rule_name, node_addr):
        if rule_name == None or node_addr == None:
            print("_del_rule() invalid parameters")
            return
        nid, noti = self._nodes.delete_rule(rule_name, node_addr, self._notification_callback)
        if nid == None:
            return
        self._notifications_sent[nid] = noti

    # https://stackoverflow.com/questions/40225270/copy-paste-multiple-items-from-qtableview-in-pyqt4
    def _copy_selected_rows(self):
        cur_idx = self.tabWidget.currentIndex()
        if self.tabWidget.currentIndex() == self.TAB_RULES and self.fwTable.isVisible():
            cur_idx = self.TAB_FIREWALL
        elif self.tabWidget.currentIndex() == self.TAB_RULES and not self.fwTable.isVisible():
            cur_idx = self.TAB_RULES
        selection = self.TABLES[cur_idx]['view'].selectedRows()
        if selection:
            stream = io.StringIO()
            csv.writer(stream, delimiter=',').writerows(selection)
            QtWidgets.QApplication.clipboard().setText(stream.getvalue())

    def _configure_netstat_combos(self):
        self.comboNetstatStates.blockSignals(True);
        self.comboNetstatStates.setCurrentIndex(
            self._cfg.getInt(Config.STATS_NETSTAT_FILTER_STATE, 0)
        )
        self.comboNetstatStates.blockSignals(False);
        self.comboNetstatFamily.blockSignals(True);
        self.comboNetstatFamily.setCurrentIndex(
            self._cfg.getInt(Config.STATS_NETSTAT_FILTER_FAMILY, 0)
        )
        self.comboNetstatFamily.blockSignals(False);
        self.comboNetstatProto.blockSignals(True);
        self.comboNetstatProto.setCurrentIndex(
            self._cfg.getInt(Config.STATS_NETSTAT_FILTER_PROTO, 0)
        )
        self.comboNetstatProto.blockSignals(False);

    def _configure_events_contextual_menu(self, pos):
        try:
            cur_idx = self.tabWidget.currentIndex()
            table = self._get_active_table()
            model = table.model()

            selection = table.selectionModel().selectedRows()
            if not selection:
                return False

            rule_name = model.index(selection[0].row(), self.COL_RULES).data()
            menu = QtWidgets.QMenu()
            _menu_details = menu.addAction(QC.translate("stats", "Details"))
            rulesMenu = QtWidgets.QMenu(QC.translate("stats", "Rules"))
            _menu_new_rule = rulesMenu.addAction(QC.translate("stats", "New"))
            _menu_goto_rule = None
            rule_index = None
            if rule_name not in (None, "") and self.COL_RULES < model.columnCount():
                rule_index = model.index(selection[0].row(), self.COL_RULES)
                if rule_index is not None and rule_index.isValid():
                    _menu_goto_rule = rulesMenu.addAction(QC.translate("stats", "Show rule"))
            menu.addMenu(rulesMenu)

            # move away menu a few pixels to the right, to avoid clicking on it by mistake
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec(table.mapToGlobal(point))

            model = table.model()

            if action == _menu_new_rule:
                self._table_menu_new_rule_from_row(cur_idx, model, selection)
            elif action == _menu_details:
                coltime = model.index(selection[0].row(), self.COL_TIME).data()
                o = ConnDetails(self)
                o.showByField("time", coltime)
            elif action == _menu_goto_rule and rule_index is not None:
                self._focus_rule_from_index(rule_index)

        except Exception as e:
            print(e)
        finally:
            self._clear_rows_selection()
            return True

    def _configure_rule_reference_context_menu(self, pos):
        """Context menu for tables that only need the rule focus shortcut."""
        table = self._get_active_table()
        if table is None:
            return False
        model = table.model()
        if model is None:
            return False
        selection_model = table.selectionModel()
        try:
            index = table.indexAt(pos)
            if not index.isValid():
                if selection_model is None:
                    return False
                selection = selection_model.selectedRows()
                if not selection:
                    return False
                index = selection[0]
            row = index.row()
            rule_name, node_name = self._get_rule_focus_target_from_row(model, row)
            if not rule_name or not node_name:
                return False
            rule_index = self._get_rule_index_for_row(model, row)
            if rule_index is None:
                return False
            try:
                table.selectRow(row)
            except Exception:
                pass
            menu = QtWidgets.QMenu()
            _menu_goto_rule = menu.addAction(QC.translate("stats", "Show rule"))
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec(table.mapToGlobal(point))
            if action == _menu_goto_rule:
                table.clearSelection()
                self._focus_rule_from_index(rule_index)
        except Exception as e:
            print(e)
        finally:
            try:
                table.clearSelection()
            except Exception:
                pass
        return False

    def _configure_fwrules_contextual_menu(self, pos):
        try:
            cur_idx = self.tabWidget.currentIndex()
            table = self._get_active_table()
            model = table.model()
            menu = QtWidgets.QMenu()
            exportMenu = QtWidgets.QMenu(QC.translate("stats", "Export"))

            selection = table.selectionModel().selectedRows()
            if not selection:
                return False
            is_rule_enabled = model.index(selection[0].row(), FirewallTableModel.COL_ENABLED).data()
            rule_action = model.index(selection[0].row(), FirewallTableModel.COL_ACTION).data()
            rule_action = rule_action.lower()

            if rule_action == Config.ACTION_ACCEPT or \
                    rule_action == Config.ACTION_DROP or \
                    rule_action == Config.ACTION_RETURN or \
                    rule_action == Config.ACTION_REJECT:
                actionsMenu = QtWidgets.QMenu(QC.translate("stats", "Action"))
                _action_accept = actionsMenu.addAction(Config.ACTION_ACCEPT)
                _action_drop = actionsMenu.addAction(Config.ACTION_DROP)
                _action_reject = actionsMenu.addAction(Config.ACTION_REJECT)
                _action_return = actionsMenu.addAction(Config.ACTION_RETURN)
                menu.addSeparator()
                menu.addMenu(actionsMenu)

            _label_enable = QC.translate("stats", "Disable")
            if is_rule_enabled == "False":
                _label_enable = QC.translate("stats", "Enable")
            _menu_enable = menu.addAction(_label_enable)
            _menu_delete = menu.addAction(QC.translate("stats", "Delete"))
            _menu_edit = menu.addAction(QC.translate("stats", "Edit"))

            menu.addSeparator()
            _toClipboard = exportMenu.addAction(QC.translate("stats", "To clipboard"))
            #_toDisk = exportMenu.addAction(QC.translate("stats", "To disk"))
            menu.addMenu(exportMenu)

            # move away menu a few pixels to the right, to avoid clicking on it by mistake
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec(table.mapToGlobal(point))

            model = table.model()

            # block fw rules signals, to prevent reloading them per operation,
            # which can lead to race conditions.
            self._fw.rules.blockSignals(True)
            if action == _menu_delete:
                self._table_menu_delete(cur_idx, model, selection)
            elif action == _menu_enable:
                self._table_menu_enable(cur_idx, model, selection, is_rule_enabled)
            elif action == _menu_edit:
                self._table_menu_edit(cur_idx, model, selection)
            elif action == _action_accept or \
                action == _action_drop or \
                action == _action_reject or \
                action == _action_return:
                self._table_menu_change_rule_field(cur_idx, model, selection, FwRules.FIELD_TARGET, action.text())
            elif action == _toClipboard:
                self._table_menu_export_clipboard(cur_idx, model, selection)
            #elif action == _toDisk:
            #    self._table_menu_export_disk(cur_idx, model, selection)

            self._fw.rules.blockSignals(False)

        except Exception as e:
            print("fwrules contextual menu error:", e)
        finally:
            self._clear_rows_selection()
            return True

    def _configure_rules_contextual_menu(self, pos):
        try:
            cur_idx = self.tabWidget.currentIndex()
            table = self._get_active_table()
            model = table.model()

            selection = table.selectedRows()

            menu = QtWidgets.QMenu()
            durMenu = QtWidgets.QMenu(self.COL_STR_DURATION)
            actionMenu = QtWidgets.QMenu(self.COL_STR_ACTION)
            nodesMenu = QtWidgets.QMenu(QC.translate("stats", "Apply to"))
            exportMenu = QtWidgets.QMenu(QC.translate("stats", "Export"))
            nodes_menu = []
            if self._nodes.count() > 0:
                for node in self._nodes.get_nodes():
                    nodes_menu.append([nodesMenu.addAction(node), node])
                menu.addMenu(nodesMenu)

            _actAllow = actionMenu.addAction(QC.translate("stats", "Allow"))
            _actDeny = actionMenu.addAction(QC.translate("stats", "Deny"))
            _actReject = actionMenu.addAction(QC.translate("stats", "Reject"))
            menu.addMenu(actionMenu)

            dur_actions = []
            for d in Config.get().get_duration_options():
                label = d
                if d == Config.DURATION_ALWAYS:
                    label = QC.translate("stats", "Always")
                elif d == Config.DURATION_UNTIL_RESTART:
                    label = QC.translate("stats", "Until reboot")
                act = durMenu.addAction(label)
                act.setData(d)
                dur_actions.append(act)
            menu.addMenu(durMenu)

            is_rule_enabled = True
            _menu_enable = None
            # if there's more than one rule selected, we choose an action
            # based on the status of the first rule.
            if selection and len(selection) > 0:
                is_rule_enabled = selection[0][self.COL_R_ENABLED]
                menu_label_enable = QC.translate("stats", "Disable")
                if is_rule_enabled == "False":
                    menu_label_enable = QC.translate("stats", "Enable")

                _menu_enable = menu.addAction(QC.translate("stats", menu_label_enable))

            _menu_duplicate = menu.addAction(QC.translate("stats", "Duplicate"))
            _menu_edit = menu.addAction(QC.translate("stats", "Edit"))
            _menu_delete = menu.addAction(QC.translate("stats", "Delete"))
            menu.addSeparator()
            _menu_clear_expired = menu.addAction(QC.translate("stats", "Clear expired temp rules"))

            # scoped clear options
            _menu_clear_app = None
            _menu_clear_dst = None
            if selection and len(selection) > 0:
                node_addr = selection[0][self.COL_R_NODE]
                rule_name = selection[0][self.COL_R_NAME]
                rec = self._get_rule(rule_name, node_addr)
                if rec is not None:
                    operand = rec.value(RuleFields.OpOperand)
                    if operand in (Config.OPERAND_PROCESS_PATH, Config.OPERAND_PROCESS_COMMAND, Config.OPERAND_PROCESS_ID):
                        _menu_clear_app = menu.addAction(QC.translate("stats", "Clear temp rules for this app"))
                    if operand in (Config.OPERAND_DEST_IP, Config.OPERAND_DEST_HOST, Config.OPERAND_DEST_PORT, Config.OPERAND_DEST_NETWORK):
                        _menu_clear_dst = menu.addAction(QC.translate("stats", "Clear temp rules for this destination"))

            menu.addSeparator()
            _toClipboard = exportMenu.addAction(QC.translate("stats", "To clipboard"))
            _toDisk = exportMenu.addAction(QC.translate("stats", "To disk"))
            menu.addMenu(exportMenu)

            # move away menu a few pixels to the right, to avoid clicking on it by mistake
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec(table.mapToGlobal(point))

            model = table.model()

            if self._nodes.count() > 0:
                for nmenu in nodes_menu:
                    node_action = nmenu[0]
                    node_addr = nmenu[1]
                    if action == node_action:
                        ret = Message.yes_no(
                            QC.translate("stats", "    Apply this rule to {0}  ".format(node_addr)),
                            QC.translate("stats", "    Are you sure?"),
                            QtWidgets.QMessageBox.Icon.Warning)
                        if ret == QtWidgets.QMessageBox.StandardButton.Cancel:
                            return False
                        self._table_menu_apply_to_node(cur_idx, model, selection, node_addr)
                        return False

            if action == _menu_delete:
                self._table_menu_delete(cur_idx, model, selection)
            elif action == _menu_edit:
                self._table_menu_edit(cur_idx, model, selection)
            elif action == _menu_enable:
                self._table_menu_enable(cur_idx, model, selection, is_rule_enabled)
            elif action == _menu_duplicate:
                self._table_menu_duplicate(cur_idx, model, selection)
            elif action == _menu_clear_expired:
                self._clear_expired_temp_rules()
            elif action == _menu_clear_app:
                self._clear_temp_rules_by_scope(selection[0][self.COL_R_NODE], self.CLEAR_APP)
            elif action == _menu_clear_dst:
                self._clear_temp_rules_by_scope(selection[0][self.COL_R_NODE], self.CLEAR_DST)
            elif action in dur_actions:
                self._table_menu_change_rule_field(cur_idx, model, selection, "duration", action.data())
            elif action == _actAllow:
                self._table_menu_change_rule_field(cur_idx, model, selection, "action", Config.ACTION_ALLOW)
            elif action == _actDeny:
                self._table_menu_change_rule_field(cur_idx, model, selection, "action", Config.ACTION_DENY)
            elif action == _actReject:
                self._table_menu_change_rule_field(cur_idx, model, selection, "action", Config.ACTION_REJECT)
            elif action == _toClipboard:
                self._table_menu_export_clipboard(cur_idx, model, selection)
            elif action == _toDisk:
                self._table_menu_export_disk(cur_idx, model, selection)

        except Exception as e:
            print("rules contextual menu exception:", e)
        finally:
            self._clear_rows_selection()
            return True

    def _clear_expired_temp_rules(self):
        """
        Remove temporary rules that are expired, even if still marked enabled.
        Prefer the currently displayed rows (Rules tab), fall back to DB lookup.
        """
        # refresh time-left so rows have up-to-date expiration status
        try:
            self._update_timeleft_column()
        except Exception:
            pass

        names = []
        try:
            model = self.rulesTable.model()
            items = getattr(model, "items", [])
            if items:
                for row in items:
                    try:
                        dur = str(row[self.COL_R_DURATION]).strip()
                        if self._is_permanent_duration(dur):
                            continue
                        tleft = self._compute_timeleft(row)
                        if tleft != QC.translate("stats", "expired"):
                            continue
                        names.append((row[self.COL_R_NAME], row[self.COL_R_NODE]))
                    except Exception:
                        continue
        except Exception:
            pass

        if not names:
            names = self._rules.get_expired_temp_rules()
        if len(names) == 0:
            return
        for name, node in names:
            try:
                # delete expired temp rules entirely
                nid, noti = self._nodes.delete_rule(name, node, self._notification_callback)
                if nid is not None:
                    self._notifications_sent[nid] = noti
            except Exception as e:
                print("clear_expired_temp_rules error:", e)
        self._rules.updated.emit(0)

    def _clear_temp_rules_by_scope(self, node_addr, scope):
        selection = self.rulesTable.selectedRows()
        if not selection:
            return
        rule_name = selection[0][self.COL_R_NAME]
        rec = self._get_rule(rule_name, node_addr)
        if rec is None:
            return
        operand = rec.value(RuleFields.OpOperand)
        data = rec.value(RuleFields.OpData)

        # guard: ensure scope matches operand
        if scope == self.CLEAR_APP and operand not in (Config.OPERAND_PROCESS_PATH, Config.OPERAND_PROCESS_COMMAND, Config.OPERAND_PROCESS_ID):
            return
        if scope == self.CLEAR_DST and operand not in (Config.OPERAND_DEST_IP, Config.OPERAND_DEST_HOST, Config.OPERAND_DEST_PORT, Config.OPERAND_DEST_NETWORK):
            return

        matches = self._rules.get_temp_rules_by_operand(node_addr, operand, data)
        if len(matches) == 0:
            return
        for name, node in matches:
            try:
                nid, noti = self._nodes.delete_rule(name, node, self._notification_callback)
                if nid is not None:
                    self._notifications_sent[nid] = noti
            except Exception as e:
                print("clear_temp_rules_by_scope error:", e)
        self._rules.updated.emit(0)

    def _configure_alerts_contextual_menu(self, pos):
        try:
            cur_idx = self.tabWidget.currentIndex()
            table = self._get_active_table()
            model = table.model()

            selection = table.selectionModel().selectedRows()
            if not selection:
                return False

            menu = QtWidgets.QMenu()
            exportMenu = QtWidgets.QMenu(QC.translate("stats", "Export"))

            #is_rule_enabled = model.index(selection[0].row(), self.COL_R_ENABLED).data()
            #menu_label_enable = QC.translate("stats", "Disable")
            #if is_rule_enabled == "False":
            #    menu_label_enable = QC.translate("stats", "Enable")

            _menu_view = menu.addAction(QC.translate("stats", "View"))
            _menu_delete = menu.addAction(QC.translate("stats", "Delete"))

            menu.addSeparator()
            _toClipboard = exportMenu.addAction(QC.translate("stats", "To clipboard"))
            _toDisk = exportMenu.addAction(QC.translate("stats", "To disk"))
            menu.addMenu(exportMenu)

            # move away menu a few pixels to the right, to avoid clicking on it by mistake
            point = QtCore.QPoint(pos.x()+10, pos.y()+5)
            action = menu.exec(table.mapToGlobal(point))

            model = table.model()

            if action == _menu_delete:
                self._table_menu_delete(cur_idx, model, selection)
            elif action == _menu_view:
                for idx in selection:
                    atime = model.index(idx.row(), self.COL_TIME).data()
                    anode = model.index(idx.row(), self.COL_NODE).data()
                    self._display_alert_info(atime, anode)

            elif action == _toClipboard:
                self._table_menu_export_clipboard(cur_idx, model, selection)
            elif action == _toDisk:
                self._table_menu_export_disk(cur_idx, model, selection)

        except Exception as e:
            print("alerts contextual menu exception:", e)
        finally:
            self._clear_rows_selection()
            return True

    def _table_menu_export_clipboard(self, cur_idx, model, selection):
        rules_list = []
        if cur_idx == self.TAB_RULES and self.fwTable.isVisible():
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                r = self._fw.get_protorule_by_uuid(node, uuid)
                if r:
                    rules_list.append(self._fw.rule_to_json(r))

        elif cur_idx == self.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                rule_name = row[self.COL_R_NAME]
                node_addr = row[self.COL_R_NODE]

                json_rule = self._nodes.rule_to_json(node_addr, rule_name)
                if json_rule != None:
                    rules_list.append(json_rule)
                else:
                    print("export to clipboard: ERROR converting \"{0}\" to json".format(rule_name))

        elif cur_idx == self.TAB_RULES and self.alertsTable.isVisible():
            for idx in selection:
                atime = model.index(idx.row(), self.COL_TIME).data()
                anode = model.index(idx.row(), self.COL_NODE).data()
                atype = model.index(idx.row(), self.COL_ALERT_TYPE).data()
                abody = model.index(idx.row(), self.COL_ALERT_BODY).data()
                awhat = model.index(idx.row(), self.COL_ALERT_WHAT).data()
                aprio = model.index(idx.row(), self.COL_ALERT_PRIO).data()

                rules_list.append("{0},{1},{2},{3},{4},{5}".format(atime, anode, atype, abody, awhat, aprio))

        cliptext=""
        for r in rules_list:
            cliptext = "{0}\n{1}".format(cliptext, r)

        QtWidgets.QApplication.clipboard().setText(cliptext)

    def _table_menu_export_disk(self, cur_idx, model, selection):
        outdir = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            os.path.expanduser("~"),
            QC.translate("stats", 'Select a directory to export rules'),
            QtWidgets.QFileDialog.Option.ShowDirsOnly | QtWidgets.QFileDialog.Option.DontResolveSymlinks
        )
        if outdir == "":
            return

        error_list = []
        for row in selection:
            node_addr = row[self.COL_R_NODE]
            rule_name = row[self.COL_R_NAME]

            ok = self._nodes.export_rule(node_addr, rule_name, outdir)
            if not ok:
                error_list.append(rule_name)

        if len(error_list) == 0:
            Message.ok("Rules export",
                       QC.translate("stats", "Rules exported to {0}".format(outdir)),
                       QtWidgets.QMessageBox.Icon.Information)
        else:
            error_text = ""
            for e in error_list:
                error_text = "{0}<br>{1}".format(error_text, e)

            Message.ok("Rules export error",
                        QC.translate("stats",
                                     "Error exporting the following rules:<br><br>".format(error_text)
                                    ),
                        QtWidgets.QMessageBox.Icon.Warning)

    def _table_menu_duplicate(self, cur_idx, model, selection):

        for row in selection:
            node_addr = row[self.COL_R_NODE]
            rule_name = row[self.COL_R_NAME]
            records = self._db.get_rule(rule_name, node_addr)
            if records.next() == False:
                print("[stats clone] rule not found:", rule_name, node_addr)
                continue
            rule = Rule.new_from_records(records)

            temp_name = rule_name
            for idx in range(0,100):
                temp_name = temp_name.split("-duplicated-")[0]
                temp_name = "{0}-duplicated-{1}".format(temp_name, idx)

                rec = self._rules.get_by_name(node_addr, temp_name)
                if rec.next() == False:
                    rule.name = temp_name
                    self._rules.add_rules(node_addr, [rule])
                    break

            if records != None and records.size() == -1:
                noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
                nid = self._nodes.send_notification(node_addr, noti, self._notification_callback)
                if nid != None:
                    self._notifications_sent[nid] = noti

    def _table_menu_apply_to_node(self, cur_idx, model, selection, node_addr):

        for idx in selection:
            rule_name = model.index(idx.row(), self.COL_R_NAME).data()
            records = self._get_rule(rule_name, None)
            rule = Rule.new_from_records(records)

            noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
            nid = self._nodes.send_notification(node_addr, noti, self._notification_callback)
            if nid != None:
                self._rules.add_rules(node_addr, [rule])
                self._notifications_sent[nid] = noti

    def _table_menu_change_rule_field(self, cur_idx, model, selection, field, value):
        if cur_idx == self.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                rule_name = row[self.COL_R_NAME]
                node_addr = row[self.COL_R_NODE]

                records = self._get_rule(rule_name, node_addr)
                rule = Rule.new_from_records(records)

                noti = None
                if field == "action":
                    rule.action = value
                    noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
                elif field == "duration":
                    # update duration in place; reset timestamps to restart timer and re-enable
                    rule.duration = value
                    rule.enabled = True
                    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    # created is stored as timestamp in proto
                    rule.created = int(datetime.datetime.strptime(now_str, "%Y-%m-%d %H:%M:%S").timestamp())
                    # update local DB entry
                    self._db.update(
                        table="rules",
                        fields="duration=?, created=?, enabled='True'",
                        values=[value, now_str],
                        condition="name='{0}' AND node='{1}'".format(rule_name, node_addr),
                        action_on_conflict=""
                    )
                    noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
                elif field == "precedence":
                    rule.precedence = value
                    noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
                else:
                    self._db.update(table="rules", fields="{0}=?".format(field),
                                    values=[value], condition="name='{0}' AND node='{1}'".format(rule_name, node_addr),
                                    action_on_conflict="")
                    noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])

                if noti is not None:
                    nid = self._nodes.send_notification(node_addr, noti, self._notification_callback)
                    if nid != None:
                        self._notifications_sent[nid] = noti
        elif cur_idx == self.TAB_RULES and self.fwTable.isVisible():
            nodes_updated = []
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                updated, err = self._fw.change_rule_field(node, uuid, field, value)
                if updated:
                    nodes_updated.append(node)
                else:
                    print("error updating fw rule field", field, "value:", value)

            for addr in nodes_updated:
                node = self._nodes.get_node(addr)
                nid, noti = self._nodes.reload_fw(addr, node['firewall'], self._notification_callback)
                self._notifications_sent[nid] = noti

    def _table_menu_enable(self, cur_idx, model, selection, is_rule_enabled):
        rule_status = "False" if is_rule_enabled == "True" else "True"
        enable_rule = False if is_rule_enabled == "True" else True

        if cur_idx == self.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                rule_name = row[self.COL_R_NAME]
                node_addr = row[self.COL_R_NODE]

                records = self._get_rule(rule_name, node_addr)
                rule = Rule.new_from_records(records)
                rule_type = ui_pb2.DISABLE_RULE if is_rule_enabled == "True" else ui_pb2.ENABLE_RULE

                self._db.update(table="rules", fields="enabled=?",
                                values=[rule_status], condition="name='{0}' AND node='{1}'".format(rule_name, node_addr),
                                action_on_conflict="")

                noti = ui_pb2.Notification(type=rule_type, rules=[rule])
                nid = self._nodes.send_notification(node_addr, noti, self._notification_callback)
                if nid != None:
                    self._notifications_sent[nid] = noti

        elif cur_idx == self.TAB_RULES and self.fwTable.isVisible():
            nodes_updated = []
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                updated, err = self._fw.enable_rule(node, uuid, enable_rule)
                if updated:
                    nodes_updated.append(node)

            for addr in nodes_updated:
                node = self._nodes.get_node(addr)
                nid, noti = self._nodes.reload_fw(addr, node['firewall'], self._notification_callback)
                self._notifications_sent[nid] = noti

    def _table_menu_delete(self, cur_idx, model, selection):
        if cur_idx == self.TAB_MAIN or cur_idx == self.TAB_NODES or self.IN_DETAIL_VIEW[cur_idx]:
            return

        msg = QC.translate("stats", "    You are about to delete this rule.    ")
        if cur_idx != self.TAB_RULES:
            msg = QC.translate("stats", "    You are about to delete this entry.    ")

        ret = Message.yes_no(msg,
            QC.translate("stats", "    Are you sure?"),
            QtWidgets.QMessageBox.Icon.Warning)
        if ret == QtWidgets.QMessageBox.StandardButton.Cancel:
            return False

        if cur_idx == self.TAB_RULES and self.fwTable.isVisible():
            nodes_updated = {}
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                ok, fw_config = self._fw.delete_rule(node, uuid)
                if ok:
                    nodes_updated[node] = fw_config
                else:
                    print("error deleting fw rule:", uuid, "row:", idx.row())

            for addr in nodes_updated:
                nid, noti = self._nodes.reload_fw(addr, nodes_updated[addr], self._notification_callback)
                self._notifications_sent[nid] = noti

        elif cur_idx == self.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                node = row[self.COL_R_NODE]
                name = row[self.COL_R_NAME]
                self._del_rule(name, node)
            self._refresh_active_table()

        elif cur_idx == self.TAB_RULES and self.alertsTable.isVisible():
            for idx in selection:
                time = model.index(idx.row(), self.COL_TIME).data()
                node = model.index(idx.row(), self.COL_NODE).data()
                self._db.delete_alert(time, node)

        elif cur_idx == self.TAB_HOSTS or cur_idx == self.TAB_PROCS or cur_idx == self.TAB_ADDRS or \
            cur_idx == self.TAB_USERS or cur_idx == self.TAB_PORTS:
            do_refresh = False
            for idx in selection:
                field = model.index(idx.row(), self.COL_WHAT).data()
                if field == "":
                    continue
                ok = self._del_by_field(cur_idx, self.TABLES[cur_idx]['name'], field)
                do_refresh |= ok
            if do_refresh:
                self._refresh_active_table()

    def _table_menu_new_rule_from_row(self, cur_idx, model, selection):
        coltime = model.index(selection[0].row(), self.COL_TIME).data()
        if self._rules_dialog.new_rule_from_connection(coltime) == False:

            Message.ok(QC.translate("stats", "New rule error"),
                        QC.translate("stats",
                                    "Error creating new rule from event ({0})".format(coltime)
                                    ),
                        QtWidgets.QMessageBox.Icon.Warning)

    def _table_menu_edit(self, cur_idx, model, selection):
        if cur_idx == self.TAB_RULES and self.rulesTable.isVisible():
            for row in selection:
                node = row[self.COL_R_NODE]
                name = row[self.COL_R_NAME]
                records = self._get_rule(name, node)
                if records == None or records == -1:
                    Message.ok(QC.translate("stats", "New rule error"),
                            QC.translate("stats", "Rule not found by that name and node"),
                            QtWidgets.QMessageBox.Icon.Warning)
                    return
                r = RulesEditorDialog(modal=False)
                r.edit_rule(records, node)
                break

        elif cur_idx == self.TAB_RULES and self.fwTable.isVisible():
            for idx in selection:
                uuid = model.index(idx.row(), FirewallTableModel.COL_UUID).data()
                node = model.index(idx.row(), FirewallTableModel.COL_ADDR).data()
                self._fw_dialog.load_rule(node, uuid)

                break

    def _cb_fw_rules_updated(self):
        self._add_rulesTree_fw_chains()

    def _cb_app_rules_updated(self, what):
        self._refresh_active_table()

    def _cb_nodes_updated(self, count):
        prevNode = self.comboNetstatNodes.currentIndex()
        self.comboNetstatNodes.blockSignals(True);
        self.comboNetstatNodes.clear()
        node_list = self._nodes.get_nodes()
        for node in node_list:
            self.comboNetstatNodes.addItem(node)

        if prevNode == -1:
            prevNode = 0
        self.comboNetstatNodes.setCurrentIndex(prevNode)
        if count == 0:
            self.netstatLabel.setText("")
            self.comboNetstatInterval.setCurrentIndex(0)

        showNodes = len(node_list) > 1
        self.comboNetstatNodes.setVisible(showNodes)

        self.comboNetstatNodes.blockSignals(False);

    @QtCore.pyqtSlot(str)
    def _cb_fw_table_rows_reordered(self, node_addr):
        node = self._nodes.get_node(node_addr)
        nid, notif = self._nodes.reload_fw(node_addr, node['firewall'], self._notification_callback)
        self._notifications_sent[nid] = {'addr': node_addr, 'notif': notif}

    # ignore updates while the user is using the scrollbar.
    def _cb_scrollbar_pressed(self):
        self.scrollbar_active = True

    def _cb_scrollbar_released(self):
        self.scrollbar_active = False

    def _cb_tree_edit_firewall_clicked(self):
        self._fw_dialog.show()

    def _cb_proc_details_clicked(self):
        table = self._tables[self.tabWidget.currentIndex()]
        nrows = table.model().rowCount()
        pids = {}
        for row in range(0, nrows):
            pid = table.model().index(row, self.COL_PROC_PID).data()
            node = table.model().index(row, self.COL_NODE).data()
            if pid not in pids:
                pids[pid] = node

        self._proc_details_dialog.monitor(pids)

    @QtCore.pyqtSlot(str, ui_pb2.NotificationReply)
    def _cb_notification_callback(self, node_addr, reply):
        if reply.id in self._notifications_sent:
            noti = self._notifications_sent[reply.id]

            # convert dictionary sent from _cb_fw_table_rows_reordered()
            if isinstance(noti, dict) and isinstance(noti["notif"].type, int):
                noti = noti["notif"]

            if noti.type == ui_pb2.TASK_START and reply.code != ui_pb2.ERROR:
                noti_data = json.loads(noti.data)
                if noti_data['name'] == "node-monitor":
                    self._update_node_info(reply.data)
                elif noti_data['name'] == "sockets-monitor":
                    self._update_netstat_table(node_addr, reply.data)
                else:
                    print("_cb_notification_callback, unknown task reply?", noti_data)
                return
            elif noti.type == ui_pb2.TASK_START and reply.code == ui_pb2.ERROR:
                self.netstatLabel.setText("error starting netstat table: {0}".format(reply.data))
            elif reply.code == ui_pb2.ERROR:
                Message.ok(
                    QC.translate("stats", "Error:"),
                    "{0}".format(reply.data),
                    QtWidgets.QMessageBox.Icon.Warning)
            else:
                print("_cb_notification_callback, unknown reply:", reply)

            del self._notifications_sent[reply.id]

        else:
            print("_cb_notification_callback, reply not in the list:", reply)
            Message.ok(
                QC.translate("stats", "Warning:"),
                "{0}".format(reply.data),
                QtWidgets.QMessageBox.Icon.Warning)

    def _cb_tab_changed(self, index):
        self.comboAction.setVisible(index == self.TAB_MAIN)

        if index != self.TAB_NETSTAT and self.LAST_TAB == self.TAB_NETSTAT:
            self._unmonitor_node_netstat(self.LAST_SELECTED_ITEM)
            self.comboNetstatNodes.setCurrentIndex(0)

        if self.LAST_TAB == self.TAB_NODES and self.LAST_SELECTED_ITEM != "":
            self._unmonitor_deselected_node(self.LAST_SELECTED_ITEM)

        self.TABLES[index]['cmdCleanStats'].setVisible(True)
        if index == self.TAB_MAIN:
            self._set_events_query()
        elif index == self.TAB_NETSTAT:
            self._monitor_node_netstat()
        else:
            if index == self.TAB_RULES:
                # display the clean buton only if not in detail view
                self.TABLES[index]['cmdCleanStats'].setVisible( self.IN_DETAIL_VIEW[index] )
                self._add_rulesTree_nodes()

            elif index == self.TAB_PROCS:
                # make the button visible depending if we're in the detail view
                nrows = self._get_active_table().model().rowCount()
                self.cmdProcDetails.setVisible(self.IN_DETAIL_VIEW[index] and nrows > 0)
            elif index == self.TAB_NODES:
                self.TABLES[index]['cmdCleanStats'].setVisible( self.IN_DETAIL_VIEW[index] )

        self.LAST_TAB = index
        self._refresh_active_table()
        self._update_rule_focus_indicator()

    def _cb_table_context_menu(self, pos):
        cur_idx = self.tabWidget.currentIndex()
        if cur_idx == self.TAB_RULES and self.IN_DETAIL_VIEW[self.TAB_RULES]:
            return

        self._context_menu_active = True
        refresh_table = False
        try:
            if cur_idx == self.TAB_MAIN:
                refresh_table = self._configure_events_contextual_menu(pos)
            elif cur_idx == self.TAB_RULES:
                if self.fwTable.isVisible():
                    refresh_table = self._configure_fwrules_contextual_menu(pos)
                elif self.alertsTable.isVisible():
                    refresh_table = self._configure_alerts_contextual_menu(pos)
                else:
                    refresh_table = self._configure_rules_contextual_menu(pos)
            else:
                self._configure_rule_reference_context_menu(pos)
        finally:
            self._context_menu_active = False

        if refresh_table:
            self._refresh_active_table()


    def _cb_table_header_clicked(self, pos, sortIdx):
        # sortIdx is a SortOrder enum

        cur_idx = self.tabWidget.currentIndex()
        # TODO: allow ordering by Network column
        if cur_idx == self.TAB_ADDRS and pos == 2:
            return

        model = self._get_active_table().model()
        qstr = model.query().lastQuery().split("ORDER BY")[0]

        q = qstr.strip(" ") + " ORDER BY %d %s" % (pos+1, self.SORT_ORDER[sortIdx.value])
        if cur_idx > 0 and self.TABLES[cur_idx]['cmd'].isVisible() == False:
            self.TABLES[cur_idx]['last_order_by'] = pos+1
            self.TABLES[cur_idx]['last_order_to'] = sortIdx.value

            q = qstr.strip(" ") + self._get_order()

        q += self._get_limit()
        self.setQuery(model, q)

    def _cb_events_filter_line_changed(self, text):
        cur_idx = self.tabWidget.currentIndex()

        model = self.TABLES[cur_idx]['view'].model()
        qstr = None
        if cur_idx == StatsDialog.TAB_MAIN:
            self._cfg.setSettings(Config.STATS_FILTER_TEXT, text)
            self._set_events_query()
            return

        elif cur_idx == StatsDialog.TAB_NODES:
            qstr = self._get_nodes_filter_query(model.query().lastQuery(), text)

        elif cur_idx == StatsDialog.TAB_RULES and self.fwTable.isVisible():
            self.TABLES[self.TAB_FIREWALL]['view'].filterByQuery(text)
            return

        elif self.IN_DETAIL_VIEW[cur_idx] == True:
            qstr = self._get_indetail_filter_query(model.query().lastQuery(), text)

        else:
            if cur_idx == StatsDialog.TAB_RULES and not self.fwTable.isVisible() and not self.alertsTable.isVisible():
                self._reapply_rules_filter(update_timeleft=True)
                return
            where_clause = self._get_filter_line_clause(cur_idx, text)
            qstr = self._db.get_query( self.TABLES[cur_idx]['name'], self.TABLES[cur_idx]['display_fields'] ) + \
                where_clause + self._get_order()
            if text == "":
                qstr = qstr + self._get_limit()

        if qstr != None:
            self.setQuery(model, qstr)
            if cur_idx == StatsDialog.TAB_RULES:
                self._update_timeleft_column()

    def _cb_combo_netstat_changed(self, combo, idx):
        refreshIndex = self.comboNetstatInterval.currentIndex()
        self._unmonitor_node_netstat(self.LAST_NETSTAT_NODE)
        if refreshIndex > 0:
            self._monitor_node_netstat()

        if combo == 2:
            self._cfg.setSettings(Config.STATS_NETSTAT_FILTER_PROTO, self.comboNetstatProto.currentIndex())
        elif combo == 3:
            self._cfg.setSettings(Config.STATS_NETSTAT_FILTER_FAMILY, self.comboNetstatFamily.currentIndex())
        elif combo == 4:
            self._cfg.setSettings(Config.STATS_NETSTAT_FILTER_STATE, self.comboNetstatStates.currentIndex())

        self.LAST_NETSTAT_NODE = self.comboNetstatNodes.currentText()

    def _cb_limit_combo_changed(self, idx):
        if self.tabWidget.currentIndex() == self.TAB_MAIN:
            self._set_events_query()
        else:
            model = self._get_active_table().model()
            qstr = model.query().lastQuery()
            if "LIMIT" in qstr:
                qs = qstr.split(" LIMIT ")
                q = qs[0]
                l = qs[1]
                qstr = q + self._get_limit()
            else:
                qstr = qstr + self._get_limit()
            self.setQuery(model, qstr)

    def _cb_combo_action_changed(self, idx):
        if self.tabWidget.currentIndex() != self.TAB_MAIN:
            return

        self._cfg.setSettings(Config.STATS_GENERAL_FILTER_ACTION, idx)
        self._set_events_query()

    def _cb_clean_sql_clicked(self, idx):
        cur_idx = self.tabWidget.currentIndex()
        if cur_idx == StatsDialog.TAB_RULES:
            self._db.empty_rule(self.TABLES[cur_idx]['label'].text())
        elif self.IN_DETAIL_VIEW[cur_idx]:
            self._del_by_field(cur_idx, self.TABLES[cur_idx]['name'], self.TABLES[cur_idx]['label'].text())
        else:
            self._db.clean(self.TABLES[cur_idx]['name'])
        self._refresh_active_table()

    def _cb_cmd_back_clicked(self, idx):
        try:
            cur_idx = self.tabWidget.currentIndex()
            self.IN_DETAIL_VIEW[cur_idx] = False

            self._set_active_widgets(cur_idx, False)
            if cur_idx == StatsDialog.TAB_RULES:
                self._restore_rules_tab_widgets(True)
                return
            elif cur_idx == StatsDialog.TAB_PROCS:
                self.cmdProcDetails.setVisible(False)

            model = self._get_active_table().model()
            where_clause = ""
            if self.TABLES[cur_idx]['filterLine'] != None:
                filter_text = self.TABLES[cur_idx]['filterLine'].text()
                where_clause = self._get_filter_line_clause(cur_idx, filter_text)

            self.setQuery(model,
                        self._db.get_query(
                            self.TABLES[cur_idx]['name'],
                            self.TABLES[cur_idx]['display_fields']) + where_clause + " " + self._get_order() + self._get_limit()
                        )
        finally:
            self._restore_details_view_columns(
                self.TABLES[cur_idx]['view'].horizontalHeader(),
                "{0}{1}".format(Config.STATS_VIEW_COL_STATE, cur_idx)
            )
            self._restore_scroll_value()
            self._restore_last_selected_row()

    def _cb_main_table_double_clicked(self, row):
        origin_tab = self.tabWidget.currentIndex()
        if self._maybe_focus_rule_from_index(row, origin_tab=origin_tab):
            return
        prev_idx = origin_tab
        data = row.data()
        idx = row.column()
        cur_idx = 1

        if idx == StatsDialog.COL_NODE:
            cur_idx = self.TAB_NODES
            self.IN_DETAIL_VIEW[cur_idx] = True
            self.LAST_SELECTED_ITEM = row.model().index(row.row(), self.COL_NODE).data()
            self._push_navigation_state(origin_tab, cur_idx)
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_active_widgets(prev_idx, True, str(data))
            self._set_nodes_query(data)

        elif idx == StatsDialog.COL_RULES:
            cur_idx = self.TAB_RULES
            self.IN_DETAIL_VIEW[cur_idx] = True
            self.LAST_SELECTED_ITEM = row.model().index(row.row(), self.COL_RULES).data()
            r_name, node = self._set_rules_tab_active(row, cur_idx, self.COL_RULES, self.COL_NODE)
            self._push_navigation_state(origin_tab, cur_idx)
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_active_widgets(prev_idx, True, str(data))
            self._set_rules_query(r_name, node)

        elif idx == StatsDialog.COL_DSTIP:
            cur_idx = self.TAB_ADDRS
            self.IN_DETAIL_VIEW[cur_idx] = True
            rowdata = row.model().index(row.row(), self.COL_DSTIP).data()
            ip = rowdata
            self.LAST_SELECTED_ITEM = ip
            self._push_navigation_state(origin_tab, cur_idx)
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_active_widgets(prev_idx, True, ip)
            self._set_addrs_query(ip)

        elif idx == StatsDialog.COL_DSTHOST:
            cur_idx = self.TAB_HOSTS
            self.IN_DETAIL_VIEW[cur_idx] = True
            rowdata = row.model().index(row.row(), self.COL_DSTHOST).data()
            host = rowdata
            if host == "":
                return
            self.LAST_SELECTED_ITEM = host
            self._push_navigation_state(origin_tab, cur_idx)
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_active_widgets(prev_idx, True, host)
            self._set_hosts_query(host)

        elif idx == StatsDialog.COL_DSTPORT:
            cur_idx = self.TAB_PORTS
            self.IN_DETAIL_VIEW[cur_idx] = True
            rowdata = row.model().index(row.row(), self.COL_DSTPORT).data()
            port = rowdata
            self.LAST_SELECTED_ITEM = port
            self._push_navigation_state(origin_tab, cur_idx)
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_active_widgets(prev_idx, True, port)
            self._set_ports_query(port)

        elif idx == StatsDialog.COL_UID:
            cur_idx = self.TAB_USERS
            self.IN_DETAIL_VIEW[cur_idx] = True
            rowdata = row.model().index(row.row(), self.COL_UID).data()
            uid = rowdata
            self.LAST_SELECTED_ITEM = uid
            self._push_navigation_state(origin_tab, cur_idx)
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_active_widgets(prev_idx, True, uid)
            self._set_users_query(uid)

        elif idx == StatsDialog.COL_PID:
            node = row.model().index(row.row(), self.COL_NODE).data()
            pid = row.model().index(row.row(), self.COL_PID).data()
            self.LAST_SELECTED_ITEM = pid
            self._proc_details_dialog.monitor(
                {pid: node}
            )
            return
        else:
            cur_idx = self.TAB_PROCS
            self.IN_DETAIL_VIEW[cur_idx] = True
            self.LAST_SELECTED_ITEM = row.model().index(row.row(), self.COL_PROCS).data()
            self._push_navigation_state(origin_tab, cur_idx)
            self.tabWidget.setCurrentIndex(cur_idx)
            self._set_active_widgets(prev_idx, True, self.LAST_SELECTED_ITEM)
            self._set_process_query(self.LAST_SELECTED_ITEM)

        self._restore_details_view_columns(
            self.TABLES[cur_idx]['view'].horizontalHeader(),
            "{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx)
        )

    def _cb_table_selection_changed(self, selected, deselected):
        cur_idx = self.tabWidget.currentIndex()
        if cur_idx == self.TAB_NODES:
            if not deselected.isEmpty():
                self.LAST_SELECTED_ITEM = ""
                last_addr = deselected.indexes()[self.COL_NODE].data()
                self._unmonitor_deselected_node(last_addr)

            if not selected.isEmpty():
                node_addr = selected.indexes()[self.COL_NODE].data()
                if node_addr == self.LAST_SELECTED_ITEM:
                    return
                self.LAST_SELECTED_ITEM = node_addr
                self._monitor_selected_node(
                    node_addr,
                    selected.indexes()[self.COL_N_UPTIME].data(),
                    selected.indexes()[self.COL_N_HOSTNAME].data(),
                    selected.indexes()[self.COL_N_VERSION].data(),
                    selected.indexes()[self.COL_N_KERNEL].data()
                )

    def _cb_table_double_clicked(self, row):
        cur_idx = self.tabWidget.currentIndex()
        origin_tab = self.tabWidget.currentIndex()
        if self._maybe_focus_rule_from_index(row, origin_tab=origin_tab):
            return
        if self.IN_DETAIL_VIEW[cur_idx]:
            return

        if cur_idx == self.TAB_RULES and self.fwTable.isVisible():
            uuid = row.model().index(row.row(), 1).data(QtCore.Qt.ItemDataRole.UserRole.value+1)
            addr = row.model().index(row.row(), 2).data(QtCore.Qt.ItemDataRole.UserRole.value+1)
            self._fw_dialog.load_rule(addr, uuid)
            return

        elif cur_idx == self.TAB_RULES and self.alertsTable.isVisible():
            atime = row.model().index(row.row(), self.COL_TIME).data()
            anode = row.model().index(row.row(), self.COL_NODE).data()
            self._display_alert_info(atime, anode)
            return

        self.IN_DETAIL_VIEW[cur_idx] = True
        self.LAST_SELECTED_ITEM = row.model().index(row.row(), self.COL_TIME).data()
        self.LAST_SCROLL_VALUE = self.TABLES[cur_idx]['view'].vScrollBar.value()

        data = row.data()

        if cur_idx == self.TAB_RULES:
            if self.alertsTable.isVisible():
                return

            rule_name = row.model().index(row.row(), self.COL_R_NAME).data()
            self._set_active_widgets(cur_idx, True, rule_name)
            r_name, node = self._set_rules_tab_active(row, cur_idx, self.COL_R_NAME, self.COL_R_NODE)
            self.LAST_SELECTED_ITEM = row.model().index(row.row(), self.COL_R_NAME).data()
            self._set_rules_query(r_name, node)
            self._restore_details_view_columns(
                self.TABLES[cur_idx]['view'].horizontalHeader(),
                "{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx)
            )
            return
        if cur_idx == self.TAB_NODES:
            data = row.model().index(row.row(), self.COL_NODE).data()
            self.LAST_SELECTED_ITEM = row.model().index(row.row(), self.COL_NODE).data()
        if cur_idx > self.TAB_RULES:
            self.LAST_SELECTED_ITEM = row.model().index(row.row(), self.COL_WHAT).data()
            data = row.model().index(row.row(), self.COL_WHAT).data()
        if cur_idx == self.TAB_NETSTAT:
            self.IN_DETAIL_VIEW[cur_idx] = False

            if row.column() == self.COL_NET_DST_IP:
                cur_idx = StatsDialog.TAB_ADDRS
                data = row.model().index(row.row(), self.COL_NET_DST_IP).data()
            elif row.column() == self.COL_NET_DST_PORT:
                cur_idx = StatsDialog.TAB_PORTS
                data = row.model().index(row.row(), self.COL_NET_DST_PORT).data()
            elif row.column() == self.COL_NET_UID:
                cur_idx = StatsDialog.TAB_USERS
                data = row.model().index(row.row(), self.COL_NET_UID).data()
            elif row.column() == self.COL_NET_PID:
                pid = row.model().index(row.row(), self.COL_NET_PID).data()
                self._proc_details_dialog.monitor({pid: self.comboNetstatNodes.currentText()})
                return
            else:
                cur_idx = StatsDialog.TAB_PROCS
                data = row.model().index(row.row(), self.COL_NET_PROC).data()
                if data == "":
                    return
            self._push_navigation_state(origin_tab, cur_idx)
            self.tabWidget.setCurrentIndex(cur_idx)

        self._set_active_widgets(cur_idx, True, str(data))

        if cur_idx == StatsDialog.TAB_NODES:
            self._set_nodes_query(data)
        elif cur_idx == StatsDialog.TAB_HOSTS:
            self._set_hosts_query(data)
        elif cur_idx == StatsDialog.TAB_PROCS:
            self._set_process_query(data)
        elif cur_idx == StatsDialog.TAB_ADDRS:
            lbl_text = self.TABLES[cur_idx]['label'].text()
            if lbl_text != "":
                asn = self.asndb.get_asn(lbl_text)
                if asn != "":
                    lbl_text += " (" + asn + ")"
            self.TABLES[cur_idx]['label'].setText(lbl_text)
            self._set_addrs_query(data)
        elif cur_idx == StatsDialog.TAB_PORTS:
            self._set_ports_query(data)
        elif cur_idx == StatsDialog.TAB_USERS:
            self._set_users_query(data)

        self._restore_details_view_columns(
            self.TABLES[cur_idx]['view'].horizontalHeader(),
            "{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx)
        )

    def _cb_prefs_clicked(self):
        self._prefs_dialog.show()

    def _cb_rules_filter_combo_changed(self, idx):
        if idx == self.RULES_TREE_APPS:
            self._set_rules_filter()
        elif idx == self.RULES_COMBO_PERMANENT:
            self._set_rules_filter(self.RULES_TREE_APPS, self.RULES_TREE_PERMANENT)
        elif idx == self.RULES_COMBO_TEMPORARY:
            self._set_rules_filter(self.RULES_TREE_APPS, self.RULES_TREE_TEMPORARY)
        elif idx == self.RULES_TREE_ALERTS:
            self._set_rules_filter(-1, self.RULES_TREE_ALERTS)
        elif idx == self.RULES_COMBO_FW:
            self._set_rules_filter(-1, self.RULES_TREE_FIREWALL)

    def _cb_rules_tree_item_expanded(self, item):
        self.rulesTreePanel.resizeColumnToContents(0)
        self.rulesTreePanel.resizeColumnToContents(1)

    def _cb_rules_tree_item_double_clicked(self, item, col):
        # TODO: open fw chain editor
        pass

    def _cb_rules_tree_item_clicked(self, item, col):
        """
        Event fired when the user clicks on the left panel of the rules tab
        """
        item_model = self.rulesTreePanel.indexFromItem(item, col)
        item_row = item_model.row()
        parent = item.parent()
        parent_row = -1
        node_addr = ""
        fw_table = ""

        rulesHeader = self.rulesTable.horizontalHeader()
        self._cfg.setSettings(Config.STATS_RULES_COL_STATE, rulesHeader.saveState())

        self._clear_rows_selection()

        filter_meta = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
        if isinstance(filter_meta, tuple) and len(filter_meta) == 2 and \
                filter_meta[0] in (self.RULES_TYPE_PERMANENT, self.RULES_TYPE_TEMPORARY):
            self._handle_rules_action_filter(filter_meta)
            return

        # FIXME: find a clever way of handling these options

        # top level items
        if parent != None:
            parent_model = self.rulesTreePanel.indexFromItem(parent, 0)
            parent_row = parent_model.row()
            node_addr = parent_model.data()

            # 1st level items: nodes, rules types
            if parent.parent() != None:
                parent = parent.parent()
                parent_model = self.rulesTreePanel.indexFromItem(parent, 0)
                item_row =  self.FILTER_TREE_FW_TABLE
                parent_row = self.RULES_TREE_FIREWALL
                fw_table = parent_model.data()

                # 2nd level items: chains
                if parent.parent() != None:
                    parent = parent.parent()
                    parent_model = self.rulesTreePanel.indexFromItem(parent.parent(), 0)
                    item_row =  self.FILTER_TREE_FW_CHAIN
                    parent_row = self.RULES_TREE_FIREWALL

        if node_addr == None:
            return

        showFwTable = (parent_row == self.RULES_TREE_FIREWALL or (parent_row == -1 and item_row == self.RULES_TREE_FIREWALL))
        showAlertsTable = (parent_row == -1 and item_row == self.RULES_TREE_ALERTS)
        self.fwTable.setVisible(showFwTable)
        self.alertsTable.setVisible(showAlertsTable)
        self.rulesTable.setVisible(not showFwTable and not showAlertsTable)
        self.rulesScrollBar.setVisible(not showFwTable)

        self._set_rules_filter(parent_row, item_row, item.text(0), node_addr, fw_table)

    def _cb_splitter_moved(self, tab, pos, index):
        if tab == self.TAB_RULES:
            self.comboRulesFilter.setVisible(pos == 0)
            self._cfg.setSettings(Config.STATS_RULES_SPLITTER_POS, self.rulesSplitter.saveState())
        elif tab == self.TAB_NODES:
            #w = self.nodesSplitter.width()
            #if pos >= w-2:
            #    self._unmonitor_deselected_node()
            self._cfg.setSettings(Config.STATS_NODES_SPLITTER_POS, self.nodesSplitter.saveState())

    def _cb_start_clicked(self):
        if self.daemon_connected == False:
            self.startButton.setChecked(False)
            self.startButton.setIcon(self.iconStart)
            return

        self.update_interception_status(self.startButton.isChecked())
        self._status_changed_trigger.emit(self.startButton.isChecked())

        if self.startButton.isChecked():
            nid, noti = self._nodes.start_interception(_callback=self._notification_callback)
        else:
            nid, noti = self._nodes.stop_interception(_callback=self._notification_callback)

        self._notifications_sent[nid] = noti

    def _cb_node_start_clicked(self):
        addr = self.TABLES[self.TAB_NODES]['label'].text()
        if addr == "":
            return
        if self.nodeStartButton.isChecked():
            self._update_nodes_interception_status()
            nid, noti = self._nodes.start_interception(_addr=addr, _callback=self._notification_callback)
        else:
            self._update_nodes_interception_status(disable=True)
            nid, noti = self._nodes.stop_interception(_addr=addr, _callback=self._notification_callback)

        self._notifications_sent[nid] = noti

    def _cb_node_prefs_clicked(self):
        addr = self.TABLES[self.TAB_NODES]['label'].text()
        if addr == "":
            return
        self._prefs_dialog.show_node_prefs(addr)

    def _cb_node_delete_clicked(self):
        ret = Message.yes_no(
            QC.translate("stats", "    You are about to delete this node.    "),
            QC.translate("stats", "    Are you sure?"),
            QtWidgets.QMessageBox.Icon.Warning)
        if ret == QtWidgets.QMessageBox.StandardButton.Cancel:
            return

        addr = self.TABLES[self.TAB_NODES]['label'].text()
        if self._db.remove("DELETE FROM nodes WHERE addr = '{0}'".format(addr)) == False:
            Message.ok(
                QC.translate("stats",
                                "<b>Error deleting node</b><br><br>",
                                "{0}").format(addr),
                QtWidgets.QMessageBox.Icon.Warning)
            return

        self._nodes.delete(addr)
        self.TABLES[self.TAB_NODES]['cmd'].click()
        self.TABLES[self.TAB_NODES]['label'].setText("")
        self._refresh_active_table()

    def _cb_new_rule_clicked(self):
        self._rules_dialog.new_rule()

    def _cb_edit_rule_clicked(self):
        cur_idx = self.tabWidget.currentIndex()
        records = self._get_rule(self.TABLES[cur_idx]['label'].text(), self.nodeRuleLabel.text())
        if records == None:
            return

        self._rules_dialog.edit_rule(records, self.nodeRuleLabel.text())

    def _cb_del_rule_clicked(self):
        ret = Message.yes_no(
            QC.translate("stats", "    You are about to delete this rule.    "),
            QC.translate("stats", "    Are you sure?"),
            QtWidgets.QMessageBox.Icon.Warning)
        if ret == QtWidgets.QMessageBox.StandardButton.Cancel:
            return

        self._del_rule(self.TABLES[self.tabWidget.currentIndex()]['label'].text(), self.nodeRuleLabel.text())
        self.TABLES[self.TAB_RULES]['cmd'].click()
        self.nodeRuleLabel.setText("")
        self._refresh_active_table()

    def _cb_enable_rule_toggled(self, state):
        rule = ui_pb2.Rule(name=self.TABLES[self.tabWidget.currentIndex()]['label'].text())
        rule.enabled = False
        rule.action = ""
        rule.duration = ""
        rule.operator.type = ""
        rule.operator.operand = ""
        rule.operator.data = ""

        notType = ui_pb2.DISABLE_RULE
        if state == True:
            notType = ui_pb2.ENABLE_RULE
        rule.enabled = state
        noti = ui_pb2.Notification(type=notType, rules=[rule])
        self._notification_trigger.emit(noti)

    def _cb_prev_button_clicked(self):
        model = self._get_active_table().model()
        model.fetchMore()

    def _cb_next_button_clicked(self):
        model = self._get_active_table().model()
        model.fetchMore()

    def _cb_help_button_clicked(self):
        QuickHelp.show(
            QC.translate("stats",
                         "<p><b>Quick help</b></p>" \
                         "<p>- Use CTRL+c to copy selected rows.</p>" \
                         "<p>- Use Home,End,PgUp,PgDown,PgUp,Up or Down keys to navigate rows.</p>" \
                         "<p>- Use right click on a row to stop refreshing the view.</p>" \
                         "<p>- Selecting more than one row also stops refreshing the view.</p>"
                         "<p>- On the Events view, clicking on columns Node, Process or Rule<br>" \
                         "jumps to the view of the selected item.</p>" \
                         "<p>- On the rest of the views, double click on a row to get detailed<br>" \
                         " information.</p><br>" \
                         "<p>For more information visit the <a href=\"{0}\">wiki</a></p>" \
                         "<br>".format(Config.HELP_URL)
                         )
        )

    def _display_alert_info(self, time, node):
        text = ""
        records = self._db.get_alert(time, node)
        if records != None and records.next() == False:
            return

        inf = InfoWindow(self)
        text += text + """
                    <b>{0}</b><br>
                    <b>Node:</b> {1}<br>
                    <b>Type:</b> {2} &ndash; <b>Severity:</b> {3}<br><br>
                    <b>{4}</b><br><br>
                    {5}

                    ---
""".format(
    records.value(AlertFields.Time),
    records.value(AlertFields.Node),
    records.value(AlertFields.Type),
    records.value(AlertFields.Priority),
    records.value(AlertFields.What),
    records.value(AlertFields.Body)
)

        inf.showHtml(text)

    # must be called after setModel() or setQuery()
    def _show_columns(self):
        cols = self._cfg.getSettings(Config.STATS_SHOW_COLUMNS)
        if cols == None:
            return

        for c in range(StatsDialog.GENERAL_COL_NUM):
            self.eventsTable.setColumnHidden(c, str(c) not in cols)

    def _update_status_label(self, running=False, text=FIREWALL_DISABLED):
        self.statusLabel.setText("%12s" % text)
        if running:
            self.statusLabel.setStyleSheet('color: green; margin: 5px')
            self.startButton.setIcon(self.iconPause)
        else:
            self.statusLabel.setStyleSheet('color: rgb(206, 92, 0); margin: 5px')
            self.startButton.setIcon(self.iconStart)

        self._add_rulesTree_nodes()
        self._add_rulesTree_fw_chains()

    def _get_rulesTree_item(self, index):
        try:
            return self.rulesTreePanel.topLevelItem(index)
        except Exception:
            return None

    def _setup_rules_action_subfilters(self):
        try:
            appsItem = self.rulesTreePanel.topLevelItem(self.RULES_TREE_APPS)
            if appsItem is None:
                return
            permItem = appsItem.child(self.RULES_TREE_PERMANENT)
            tempItem = appsItem.child(self.RULES_TREE_TEMPORARY)
            self._prepare_rules_tree_item(permItem, self.RULES_TYPE_PERMANENT)
            self._prepare_rules_tree_item(tempItem, self.RULES_TYPE_TEMPORARY)
        except Exception:
            pass

    def _prepare_rules_tree_item(self, item, section):
        if item is None:
            return
        item.setData(0, QtCore.Qt.ItemDataRole.UserRole, (section, self.RULES_ACTION_ALL))
        if item.childCount() > 0:
            return
        allowed_item = QtWidgets.QTreeWidgetItem([QC.translate("stats", "Allowed")])
        allowed_item.setData(0, QtCore.Qt.ItemDataRole.UserRole, (section, self.RULES_ACTION_ALLOW))
        allowed_icon = QtGui.QIcon.fromTheme("emblem-checked")
        if allowed_icon.isNull():
            allowed_icon = self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_DialogApplyButton)
        allowed_item.setIcon(0, allowed_icon)
        denied_item = QtWidgets.QTreeWidgetItem([QC.translate("stats", "Denied / Rejected")])
        denied_item.setData(0, QtCore.Qt.ItemDataRole.UserRole, (section, self.RULES_ACTION_DENY))
        denied_icon = QtGui.QIcon.fromTheme("dialog-cancel")
        if denied_icon.isNull():
            denied_icon = self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_DialogCancelButton)
        denied_item.setIcon(0, denied_icon)
        for child in (allowed_item, denied_item):
            base_font = item.font(0)
            child.setFont(0, base_font)
            size = child.sizeHint(0)
            child.setSizeHint(0, QtCore.QSize(size.width(), size.height() + 8))
            item.addChild(child)

    def _handle_rules_action_filter(self, meta):
        try:
            section, action = meta
        except Exception:
            return
        self.fwTable.setVisible(False)
        self.alertsTable.setVisible(False)
        self.rulesTable.setVisible(True)
        self.rulesScrollBar.setVisible(True)
        if section == self.RULES_TYPE_PERMANENT:
            self._set_rules_filter(
                self.RULES_TREE_APPS,
                self.RULES_TREE_PERMANENT,
                self.RULES_TYPE_PERMANENT,
                action_filter=action
            )
        elif section == self.RULES_TYPE_TEMPORARY:
            self._set_rules_filter(
                self.RULES_TREE_APPS,
                self.RULES_TREE_TEMPORARY,
                self.RULES_TYPE_TEMPORARY,
                action_filter=action
            )

    def _add_rulesTree_nodes(self):
        if self._nodes.count() > 0:
            nodesItem = self.rulesTreePanel.topLevelItem(self.RULES_TREE_NODES)
            nodesItem.takeChildren()
            for n in self._nodes.get_nodes():
                nodesItem.addChild(QtWidgets.QTreeWidgetItem([n]))

    def _find_tree_fw_items(self, item_data):
        """find fw items by data stored in UserRole role.
        """
        fwItem = self.rulesTreePanel.topLevelItem(self.RULES_TREE_FIREWALL)
        it = QtWidgets.QTreeWidgetItemIterator(fwItem)
        items = []
        while it.value():
            x = it.value()
            if x.data(0, QtCore.Qt.ItemDataRole.UserRole) == item_data:
                items.append(x)
            it+=1

        return items

    def _add_rulesTree_fw_chains(self):
        expanded = list()
        selected = None
        scrollValue = self.rulesTreePanel.verticalScrollBar().value()
        fwItem = self.rulesTreePanel.topLevelItem(self.RULES_TREE_FIREWALL)
        it = QtWidgets.QTreeWidgetItemIterator(fwItem)
        # save tree selected rows
        try:
            while it.value():
                x = it.value()
                if x.isExpanded():
                    expanded.append(x)
                if x.isSelected():
                    selected = x
                it += 1
        except Exception:
            pass

        self.rulesTreePanel.setAnimated(False)
        fwItem.takeChildren()
        self.rulesTreePanel.setItemWidget(fwItem, 1, self.fwTreeEdit)
        chains = self._fw.get_chains()
        for addr in chains:
            # add nodes
            nodeRoot = QtWidgets.QTreeWidgetItem(["{0}".format(addr)])
            nodeRoot.setData(0, QtCore.Qt.ItemDataRole.UserRole, addr)
            fwItem.addChild(nodeRoot)
            for nodeChains in chains[addr]:
                # exclude legacy system rules
                if len(nodeChains) == 0:
                    continue
                for cc in nodeChains:
                    # add tables
                    tableName = "{0}-{1}".format(cc.Table, cc.Family)
                    nodeTable = QtWidgets.QTreeWidgetItem([tableName])
                    nodeTable.setData(0, QtCore.Qt.ItemDataRole.UserRole, "{0}-{1}".format(addr, tableName))

                    chainName = "{0}-{1}".format(cc.Name, cc.Hook)
                    nodeChain = QtWidgets.QTreeWidgetItem([chainName, cc.Policy])
                    nodeChain.setData(0, QtCore.Qt.ItemDataRole.UserRole, "{0}-{1}".format(addr, chainName))

                    items = self._find_tree_fw_items("{0}-{1}".format(addr, tableName))
                    if len(items) == 0:
                        # add table
                        nodeTable.addChild(nodeChain)
                        nodeRoot.addChild(nodeTable)
                    else:
                        # add chains
                        node = items[0]
                        node.addChild(nodeChain)

        # restore previous selected rows
        try:
            for item in expanded:
                items = self.rulesTreePanel.findItems(item.text(0), QtCore.Qt.MatchRecursive)
                for it in items:
                        it.setExpanded(True)
                        if selected != None and selected.text(0) == it.text(0):
                            it.setSelected(True)
        except:
            pass

        self.rulesTreePanel.verticalScrollBar().setValue(scrollValue)
        self.rulesTreePanel.setAnimated(True)
        self.rulesTreePanel.resizeColumnToContents(0)
        self.rulesTreePanel.resizeColumnToContents(1)
        expanded = None

    def _clear_rows_selection(self):
        cur_idx = self.tabWidget.currentIndex()
        self.TABLES[cur_idx]['view'].clearSelection()

    def _are_rows_selected(self):
        cur_idx = self.tabWidget.currentIndex()
        view = self.TABLES[cur_idx]['view']
        ret = False
        if view != None:
            ret = len(view.selectionModel().selectedRows(0)) > 0
        return ret

    def _find_rules_node_tree_item(self, node_name):
        nodes_item = self.rulesTreePanel.topLevelItem(self.RULES_TREE_NODES)
        if nodes_item is None:
            return (None, -1)
        for idx in range(nodes_item.childCount()):
            child = nodes_item.child(idx)
            if child is not None and child.text(0) == node_name:
                return (child, idx)
        return (None, -1)

    def _get_column_index_by_name(self, model, target_name):
        if model is None or target_name is None:
            return None
        try:
            column_count = model.columnCount()
        except Exception:
            column_count = 0
        for col in range(column_count):
            header = model.headerData(col, QtCore.Qt.Orientation.Horizontal)
            if not header:
                continue
            if str(header).replace(" ", "") == target_name:
                return col
        return None

    def _get_rule_focus_target_from_row(self, model, row):
        """Return (rule_name, node_name) for the given model row, if present."""
        if model is None:
            return (None, None)
        try:
            row = int(row)
        except Exception:
            return (None, None)
        rule_name = None
        node_name = None
        try:
            cur_tab = self.tabWidget.currentIndex()
        except Exception:
            cur_tab = self.TAB_MAIN
        try:
            if cur_tab == self.TAB_MAIN:
                if self.COL_RULES < model.columnCount():
                    idx = model.index(row, self.COL_RULES)
                    if idx.isValid():
                        rule_name = idx.data()
                if self.COL_NODE < model.columnCount():
                    idx = model.index(row, self.COL_NODE)
                    if idx.isValid():
                        node_name = idx.data()
            else:
                rule_col = self._get_column_index_by_name(model, self.COL_STR_RULE)
                if rule_col is not None:
                    idx = model.index(row, rule_col)
                    if idx.isValid():
                        rule_name = idx.data()
                node_col = self._get_column_index_by_name(model, self.COL_STR_NODE)
                if node_col is not None:
                    idx = model.index(row, node_col)
                    if idx.isValid():
                        node_name = idx.data()
        except Exception:
            return (None, None)
        return (rule_name, node_name)

    def _get_rule_index_for_row(self, model, row):
        if model is None:
            return None
        try:
            row = int(row)
        except Exception:
            return None
        try:
            cur_tab = self.tabWidget.currentIndex()
        except Exception:
            cur_tab = self.TAB_MAIN
        try:
            if cur_tab == self.TAB_MAIN:
                if self.COL_RULES >= model.columnCount():
                    return None
                index = model.index(row, self.COL_RULES)
                return index if index.isValid() else None
            rule_col = self._get_column_index_by_name(model, self.COL_STR_RULE)
            if rule_col is None:
                return None
            index = model.index(row, rule_col)
            if not index.isValid():
                return None
            return index
        except Exception:
            return None

    def _focus_rule_from_index(self, model_index):
        """Focus a rule while temporarily disabling the context-menu guard."""
        if model_index is None or not model_index.isValid():
            return False
        was_menu_active = getattr(self, "_context_menu_active", False)
        try:
            origin_tab = self.tabWidget.currentIndex()
        except Exception:
            origin_tab = self.TAB_MAIN
        self._context_menu_active = False
        try:
            return self._maybe_focus_rule_from_index(model_index, origin_tab=origin_tab)
        finally:
            self._context_menu_active = was_menu_active

    def _maybe_focus_rule_from_index(self, model_index, origin_tab=None):
        if model_index is None or not model_index.isValid():
            return False
        try:
            model = model_index.model()
            if model is None:
                return False
            cur_tab = self.tabWidget.currentIndex()
            if cur_tab == self.TAB_MAIN:
                if model_index.column() != self.COL_RULES:
                    return False
            else:
                header = model.headerData(model_index.column(), QtCore.Qt.Orientation.Horizontal)
                normalized = str(header).replace(" ", "") if header else ""
                if normalized != self.COL_STR_RULE:
                    return False
            rule_name, node_name = self._get_rule_focus_target_from_row(model, model_index.row())
            if not rule_name or not node_name:
                return False
            return self._focus_rule_in_rules_tab(rule_name, node_name, origin_tab=origin_tab)
        except Exception:
            return False

    def _focus_rule_in_rules_tab(self, rule_name, node_name, origin_tab=None):
        """Ensure the given rule is visible and selected on the Rules tab."""
        rule_name = "" if rule_name is None else str(rule_name).strip()
        node_name = "" if node_name is None else str(node_name).strip()
        if rule_name == "" or node_name == "":
            return False
        try:
            records = self._db.get_rule(rule_name, node_name)
            if not records.next():
                if origin_tab is None:
                    try:
                        origin_tab = self.tabWidget.currentIndex()
                    except Exception:
                        origin_tab = self.TAB_MAIN
                self._set_rule_reference_notice(
                    origin_tab,
                    QC.translate("stats", "Rule \"{0}\" @ {1} no longer exists.").format(
                        rule_name or QC.translate("stats", "(rule)"),
                        node_name or QC.translate("stats", "(node)")
                    )
                )
                return False
        except Exception:
            return False

        if origin_tab is None:
            try:
                origin_tab = self.tabWidget.currentIndex()
            except Exception:
                origin_tab = self.TAB_MAIN
        self._clear_rule_reference_notice()
        self._remember_rule_focus_origin(origin_tab)
        self.tabWidget.setCurrentIndex(self.TAB_RULES)
        self.IN_DETAIL_VIEW[self.TAB_RULES] = False
        self._restore_rules_tab_widgets(True)
        self.rulesTable.setVisible(True)
        self.alertsTable.setVisible(False)
        self.fwTable.setVisible(False)
        self.rulesScrollBar.setVisible(True)
        self._rules_filter_mode = self.FILTER_RULES_ALL

        node_item, node_row = self._find_rules_node_tree_item(node_name)
        if node_item is not None and node_row >= 0:
            try:
                self.rulesTreePanel.setCurrentItem(node_item)
            except Exception:
                pass
            self._set_rules_filter(
                self.RULES_TREE_NODES,
                node_row,
                node_name,
                rule_focus=(rule_name, node_name)
            )
        else:
            self._set_rules_filter(rule_focus=(rule_name, node_name))

        try:
            self.rulesTable.selectItem(rule_name, self.COL_R_NAME)
        except Exception:
            pass
        return True

    def _is_rule_focus_active(self):
        state = getattr(self, "_rules_filter_state", None)
        if not state:
            return False
        focus = state.get("rule_focus")
        if isinstance(focus, tuple):
            return any(focus)
        return bool(focus)

    def _update_rule_focus_indicator(self, model=None):
        try:
            cur_idx = self.tabWidget.currentIndex()
        except Exception:
            cur_idx = self.TAB_MAIN
        notice = getattr(self, "_rule_reference_notice", None)
        if notice:
            if notice.get("tab") == cur_idx:
                self.labelRowsCount.setStyleSheet(self.RULE_FOCUS_LABEL_STYLE)
                self.labelRowsCount.setText(notice.get("text", ""))
                return
            else:
                self._rule_reference_notice = None
        if cur_idx == self.TAB_RULES and self._is_rule_focus_active():
            state = getattr(self, "_rules_filter_state", None) or {}
            focus_rule, focus_node = state.get("rule_focus", ("", ""))
            rule_txt = focus_rule or QC.translate("stats", "(rule)")
            node_txt = focus_node or QC.translate("stats", "(node)")
            focus_text = QC.translate("stats", "Rule filter: {0} @ {1} (Esc to clear)").format(
                rule_txt,
                node_txt
            )
            self.labelRowsCount.setStyleSheet(self.RULE_FOCUS_LABEL_STYLE)
            self.labelRowsCount.setText(focus_text)
            return

        self.labelRowsCount.setStyleSheet("")
        if cur_idx != self.TAB_MAIN:
            if model is None:
                try:
                    view = self.TABLES[cur_idx]['view']
                    if view is not None:
                        model = view.model()
                except Exception:
                    model = None
            if model is not None and hasattr(model, "totalRowCount"):
                self.labelRowsCount.setText("{0}".format(model.totalRowCount))
            else:
                self.labelRowsCount.setText("")
        else:
            self.labelRowsCount.setText("")

    def _remember_rule_focus_origin(self, tab_index):
        if tab_index == self.TAB_RULES:
            return
        stack = getattr(self, "_rule_focus_breadcrumbs", None)
        if stack is None:
            stack = []
            self._rule_focus_breadcrumbs = stack
        stack.append({"tab": tab_index})

    def _pop_rule_focus_breadcrumb(self):
        stack = getattr(self, "_rule_focus_breadcrumbs", None)
        if not stack:
            return False
        while stack:
            info = stack.pop()
            tab_idx = info.get("tab")
            if tab_idx is None:
                continue
            try:
                self.tabWidget.setCurrentIndex(tab_idx)
            except Exception:
                pass
            return True
        return False

    def _reset_rule_focus_navigation(self):
        stack = getattr(self, "_rule_focus_breadcrumbs", None)
        if stack is not None:
            stack.clear()
        self._clear_rule_reference_notice()
        self.tabWidget.setCurrentIndex(self.TAB_RULES)
        self.IN_DETAIL_VIEW[self.TAB_RULES] = False
        self._restore_rules_tab_widgets(True)
        self._rules_filter_mode = self.FILTER_RULES_ALL
        self._set_rules_filter()
        self._update_rule_focus_indicator()
        return True

    def _push_navigation_state(self, origin_tab, target_tab):
        try:
            origin_tab = int(origin_tab)
            target_tab = int(target_tab)
        except Exception:
            return
        if origin_tab == target_tab:
            return
        stack = getattr(self, "_navigation_stack", None)
        if stack is None:
            stack = []
            self._navigation_stack = stack
        stack.append(origin_tab)

    def _pop_navigation_tab(self):
        stack = getattr(self, "_navigation_stack", None)
        if not stack:
            return False
        # Ensure we leave any detail view before jumping back to the origin tab.
        self._maybe_exit_detail_view()
        while stack:
            tab_idx = stack.pop()
            if tab_idx is None:
                continue
            try:
                self.tabWidget.setCurrentIndex(tab_idx)
                return True
            except Exception:
                continue
        return False

    def _clear_navigation_history(self):
        stack = getattr(self, "_navigation_stack", None)
        if stack is not None:
            stack.clear()

    def _maybe_exit_detail_view(self):
        """If the current tab is in detail view, exit back to the summary list."""
        try:
            cur_idx = self.tabWidget.currentIndex()
        except Exception:
            return False
        try:
            in_detail = self.IN_DETAIL_VIEW[cur_idx]
        except Exception:
            in_detail = False
        if not in_detail:
            return False
        cmd = self.TABLES.get(cur_idx, {}).get('cmd')
        if cmd is None:
            return False
        try:
            cmd.click()
            return True
        except Exception:
            return False

    def _set_rule_reference_notice(self, tab_index, text):
        try:
            tab_index = int(tab_index)
        except Exception:
            return
        self._rule_reference_notice = {
            "tab": tab_index,
            "text": text
        }
        self._update_rule_focus_indicator()

    def _clear_rule_reference_notice(self, tab_index=None):
        notice = getattr(self, "_rule_reference_notice", None)
        if not notice:
            return
        if tab_index is not None and notice.get("tab") != tab_index:
            return
        self._rule_reference_notice = None

    def _get_rule(self, rule_name, node_name, suppress_ui=False):
        """
        get rule records, given the name of the rule and the node
        """
        records = self._db.get_rule(rule_name, node_name)
        if records.next() == False:
            if not suppress_ui:
                print("[stats dialog] edit rule, no records: ", rule_name, node_name)
            return None
        return records

    def _get_filter_line_clause(self, idx, text):
        conditions = []

        if idx == StatsDialog.TAB_RULES:
            if text != "":
                conditions.append("(rules.name LIKE '%{0}%' OR rules.operator_data LIKE '%{1}%')".format(text, text))
            if self._rules_filter_mode == self.FILTER_RULES_PERM:
                conditions.append("(duration IN ('{0}','{1}'))".format(Config.DURATION_ALWAYS, Config.DURATION_UNTIL_RESTART))
            elif self._rules_filter_mode == self.FILTER_RULES_TEMP_ACTIVE:
                conditions.append("(duration NOT IN ('{0}','{1}') AND enabled='True')".format(Config.DURATION_ALWAYS, Config.DURATION_UNTIL_RESTART))
            elif self._rules_filter_mode == self.FILTER_RULES_TEMP_EXPIRED:
                conditions.append("(duration NOT IN ('{0}','{1}') AND enabled='False')".format(Config.DURATION_ALWAYS, Config.DURATION_UNTIL_RESTART))
        elif idx == StatsDialog.TAB_HOSTS or \
            idx == StatsDialog.TAB_PROCS or \
            idx == StatsDialog.TAB_ADDRS or \
            idx == StatsDialog.TAB_PORTS or \
            idx == StatsDialog.TAB_USERS:
            if text != "":
                conditions.append("what LIKE '%{0}%' ".format(text))
        elif idx == StatsDialog.TAB_NETSTAT:
            if text != "":
                conditions.append("(proc_comm LIKE '%{0}%' OR" \
                " proc_path LIKE '%{0}%' OR" \
                " state LIKE '%{0}%' OR" \
                " src_port LIKE '%{0}%' OR" \
                " src_ip LIKE '%{0}%' OR" \
                " dst_ip LIKE '%{0}%' OR" \
                " dst_port LIKE '%{0}%' OR" \
                " proto LIKE '%{0}%' OR" \
                " uid LIKE '%{0}%' OR" \
                " proc_pid LIKE '%{0}%' OR" \
                " family LIKE '%{0}%' OR" \
                " iface LIKE '%{0}%' OR" \
                " inode LIKE '%{0}%')".format(text))

        if len(conditions) == 0:
            return ""
        return " WHERE " + " AND ".join(conditions)

    def _get_limit(self):
        return " " + self.LIMITS[self.limitCombo.currentIndex()]

    def _get_order(self, field=None):
        cur_idx = self.tabWidget.currentIndex()
        order_field = self.TABLES[cur_idx]['last_order_by']
        if field != None:
           order_field  = field
        return " ORDER BY %s %s" % (order_field, self.SORT_ORDER[self.TABLES[cur_idx]['last_order_to']])

    def _set_rules_filter_mode(self, mode):
        self._rules_filter_mode = mode
        self._refresh_active_table()

    def _is_permanent_duration(self, dur):
        return str(dur).strip() in (Config.DURATION_ALWAYS, Config.DURATION_UNTIL_RESTART)

    def _format_timeleft(self, secs):
        if secs <= 0:
            return QC.translate("stats", "expired")
        if secs < 60:
            return "<1m"
        total_mins = math.ceil(secs / 60)
        hours = total_mins // 60
        mins = total_mins % 60
        if hours == 0:
            return "{0}m".format(total_mins)
        return "{0}h {1}m".format(hours, mins)

    def _compute_timeleft(self, row):
        def _parse_dt(val):
            """Parse DB datetime or timestamp; return None on failure."""
            if val is None:
                return None
            s = str(val).strip()
            if s == "":
                return None
            # numeric timestamp
            if s.replace(".", "", 1).isdigit():
                try:
                    return datetime.datetime.fromtimestamp(float(s))
                except Exception:
                    pass
            # ISO or Y-m-d H:M:S[.micro][Z]
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
                try:
                    return datetime.datetime.strptime(s.replace("Z", ""), fmt)
                except Exception:
                    pass
            try:
                return datetime.datetime.fromisoformat(s.replace("Z", ""))
            except Exception:
                return None

        try:
            enabled_raw = str(row[self.COL_R_ENABLED]).strip().lower()
            enabled = enabled_raw not in ("false", "0", "no")
            dur = str(row[self.COL_R_DURATION]).strip()
            created = row[self.COL_R_CREATED]
            tstamp = row[self.COL_TIME]
            if self._is_permanent_duration(dur):
                return "—"
            if not enabled:
                return QC.translate("stats", "expired")
            if dur == Config.DURATION_ONCE:
                return "<1m"

            secs = to_seconds(dur)
            if secs <= 0:
                return QC.translate("stats", "expired")
            created_dt = _parse_dt(created)
            time_dt = _parse_dt(tstamp)
            # Prefer created; fall back to time only if created is missing
            start_dt = created_dt or time_dt
            if not start_dt:
                return QC.translate("stats", "expired")

            remaining = (start_dt + datetime.timedelta(seconds=secs)) - datetime.datetime.now()
            return self._format_timeleft(int(remaining.total_seconds()))
        except Exception:
            return "—"

    def _update_timeleft_column(self):
        model = self.rulesTable.model()
        try:
            items = getattr(model, "items", [])
        except Exception:
            return
        if items is None or len(items) == 0:
            return
        disabled_any = False
        # ensure sort cache length
        if hasattr(model, "timeleft_sort") and len(model.timeleft_sort) != len(items):
            model.timeleft_sort = [None] * len(items)
        for idx, row in enumerate(items):
            if len(row) <= self.COL_R_TIMELEFT:
                continue
            val = self._compute_timeleft(row)
            row[self.COL_R_TIMELEFT] = val
            # keep numeric sort key
            try:
                secs = None
                if val == QC.translate("stats", "expired"):
                    secs = -1
                elif val == "—":
                    secs = 1_000_000_000
                elif val == "<1m":
                    secs = 30
                else:
                    parts = val.replace("h", "").replace("m", "").split()
                    if len(parts) == 1:
                        secs = int(parts[0]) * 60
                    elif len(parts) == 2:
                        secs = int(parts[0]) * 3600 + int(parts[1]) * 60
                if hasattr(model, "timeleft_sort") and idx < len(model.timeleft_sort):
                    model.timeleft_sort[idx] = secs
            except Exception:
                if hasattr(model, "timeleft_sort") and idx < len(model.timeleft_sort):
                    model.timeleft_sort[idx] = None
            # auto-disable expired temp rules (enabled + non-permanent + expired)
            try:
                dur = str(row[self.COL_R_DURATION]).strip().lower()
                enabled_raw = str(row[self.COL_R_ENABLED]).strip().lower()
                node_addr = row[self.COL_R_NODE]
                rule_name = row[self.COL_R_NAME]
                key = f"{node_addr}:{rule_name}"
                if dur not in ("always", "until restart") and enabled_raw not in ("false", "0", "no") and val == QC.translate("stats", "expired"):
                    if key not in self._expired_processed:
                        node_clean = str(node_addr).strip() if node_addr is not None else ""
                        name_clean = str(rule_name).strip() if rule_name is not None else ""
                        # flip locally and persist, regardless of daemon response
                        row[self.COL_R_ENABLED] = "False"
                        try:
                            self._db.update(
                                "rules",
                                "enabled='False'",
                                (name_clean, node_clean),
                                "name=? AND node=?",
                                action_on_conflict="OR REPLACE"
                            )
                        except Exception:
                            pass
                        self._auto_disable_rule(node_clean, name_clean)
                        self._expired_processed.add(key)
                        disabled_any = True
            except Exception:
                pass
        if len(items) > 0:
            # update both Time left and Enabled columns to refresh the view
            left_col = min(self.COL_R_TIMELEFT, self.COL_R_ENABLED)
            right_col = max(self.COL_R_TIMELEFT, self.COL_R_ENABLED)
            top_left = model.createIndex(0, left_col)
            bottom_right = model.createIndex(len(items)-1, right_col)
            model.dataChanged.emit(top_left, bottom_right)
            try:
                # force a repaint so changes show without user interaction
                self.rulesTable.viewport().update()
            except Exception:
                pass
        if disabled_any:
            try:
                self._rules.updated.emit(0)
            except Exception:
                pass

    def _auto_disable_rule(self, node_addr, rule_name):
        """Disable an expired temporary rule in DB and daemon. Returns True if applied."""
        try:
            node_addr = (node_addr or "").strip()
            rule_name = (rule_name or "").strip()
            rec = self._get_rule(rule_name, node_addr, suppress_ui=True)
            if rec is None:
                return False
            rule = Rule.new_from_records(rec)
            rule.enabled = False
            # update DB
            self._db.update(
                "rules",
                "enabled='False'",
                (rule_name, node_addr),
                "name=? AND node=?",
                action_on_conflict="OR REPLACE"
            )
            # notify daemon with full rule to avoid deserialize errors
            noti = ui_pb2.Notification(type=ui_pb2.CHANGE_RULE, rules=[rule])
            nid = self._nodes.send_notification(node_addr, noti, self._notification_callback)
            if nid is not None:
                self._notifications_sent[nid] = noti
            else:
                # keep trying on future ticks if notify failed
                return False
            return True
        except Exception as e:
            print("auto_disable_rule exception:", e)
        return False

    def _refresh_active_table(self):
        cur_idx = self.tabWidget.currentIndex()
        view = self._get_active_table()
        model = view.model()
        # reset expired tracking per refresh
        self._expired_processed = set()
        if cur_idx == self.TAB_RULES:
            if self.IN_DETAIL_VIEW[self.TAB_RULES]:
                lastQuery = model.query().lastQuery()
                if "LIMIT" not in lastQuery:
                    lastQuery += self._get_limit()
                self.setQuery(model, lastQuery)
                view.refresh()
                return

            if self.rulesTable.isVisible():
                self._reapply_rules_filter(update_timeleft=True)
            else:
                view.refresh()
            return

        lastQuery = model.query().lastQuery()
        if "LIMIT" not in lastQuery:
            lastQuery += self._get_limit()
        self.setQuery(model, lastQuery)
        self.TABLES[cur_idx]['view'].refresh()

    def _get_active_table(self):
        if self.tabWidget.currentIndex() == self.TAB_RULES and self.fwTable.isVisible():
            return self.TABLES[self.TAB_FIREWALL]['view']
        elif self.tabWidget.currentIndex() == self.TAB_RULES and self.alertsTable.isVisible():
            return self.TABLES[self.TAB_ALERTS]['view']

        return self.TABLES[self.tabWidget.currentIndex()]['view']

    def _set_active_widgets(self, prev_idx, state, label_txt=""):
        cur_idx = self.tabWidget.currentIndex()
        self._clear_rows_selection()
        self.TABLES[cur_idx]['label'].setVisible(state)
        self.TABLES[cur_idx]['label'].setText(label_txt)
        self.TABLES[cur_idx]['cmd'].setVisible(state)

        if self.TABLES[cur_idx]['filterLine'] != None:
            self.TABLES[cur_idx]['filterLine'].setVisible(not state)

        if self.TABLES[cur_idx].get('cmdCleanStats') != None:
            if cur_idx == StatsDialog.TAB_RULES or cur_idx == StatsDialog.TAB_NODES:
                self.TABLES[cur_idx]['cmdCleanStats'].setVisible(state)

        if cur_idx == StatsDialog.TAB_NODES:
            self._update_nodes_interception_status(state)
            self.nodeDeleteButton.setVisible(state)
            self.nodeActionsButton.setVisible(state)

        elif cur_idx == StatsDialog.TAB_RULES and self.rulesTable.isVisible():
            # Use COL_TIME as index when in detail view. Otherwise COL_R_NAME
            # (col number 2) will be used, leading to incorrect selections.
            if state:
                self.TABLES[cur_idx]['view'].setTrackingColumn(self.COL_TIME)
            else:
                self.TABLES[cur_idx]['view'].setTrackingColumn(self.COL_R_NAME)

        header = self.TABLES[cur_idx]['view'].horizontalHeader()
        if state == True:
            # going to details state
            self._cfg.setSettings("{0}{1}".format(Config.STATS_VIEW_COL_STATE, prev_idx), header.saveState())
        else:
            # going to normal state
            self._cfg.setSettings("{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx), header.saveState())

    def _restore_last_selected_row(self):
        cur_idx = self.tabWidget.currentIndex()
        col = self.COL_TIME
        if cur_idx == self.TAB_RULES:
            col = self.TAB_RULES
        elif cur_idx == self.TAB_NODES:
            col = self.TAB_RULES

        #self.TABLES[cur_idx]['view'].selectItem(self.LAST_SELECTED_ITEM, col)
        #self.LAST_SELECTED_ITEM = ""

    def _restore_scroll_value(self):
        if self.LAST_SCROLL_VALUE != None:
            cur_idx = self.tabWidget.currentIndex()
            self.TABLES[cur_idx]['view'].vScrollBar.setValue(self.LAST_SCROLL_VALUE)
            self.LAST_SCROLL_VALUE = None

    def _restore_details_view_columns(self, header, settings_key):
        header.blockSignals(True);
        # In order to resize the last column of a view, we firstly force a
        # resizeToContens call.
        # Secondly set resizeMode to Interactive (allow to move columns by
        # users + programmatically)
        header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Interactive)

        col_state = self._cfg.getSettings(settings_key)
        if type(col_state) == QtCore.QByteArray:
            header.restoreState(col_state)

        header.blockSignals(False);

    def _restore_rules_tab_widgets(self, active):
        self.delRuleButton.setVisible(not active)
        self.editRuleButton.setVisible(not active)
        self.nodeRuleLabel.setText("")
        self.rulesTreePanel.setVisible(active)

        if not active:
            return

        self.rulesSplitter.refresh()
        self.comboRulesFilter.setVisible(self.rulesTreePanel.width() == 0)

        items = self.rulesTreePanel.selectedItems()
        if len(items) == 0:
            self._set_rules_filter()
            return

        rindex = item_m = self.rulesTreePanel.indexFromItem(items[0], 0)
        parent = item_m.parent()

        # find current root item of the tree panel
        while rindex.parent().isValid():
            rindex = rindex.parent()
        rnum = rindex.row()

        if parent != None and rnum != self.RULES_TREE_FIREWALL:
            self._set_rules_filter(parent.row(), item_m.row(), item_m.data())
        else:
            # when going back to the rules view, reset selection and select the
            # Apps view.
            index = self.rulesTreePanel.model().index(self.RULES_TREE_APPS, 0)
            self.rulesTreePanel.setCurrentIndex(index)
            self._set_rules_filter()


    def _set_rules_tab_active(self, row, cur_idx, name_idx, node_idx):
        self._restore_rules_tab_widgets(False)
        self.comboRulesFilter.setVisible(False)

        r_name = row.model().index(row.row(), name_idx).data()
        node = row.model().index(row.row(), node_idx).data()
        self.nodeRuleLabel.setText(node)

        self.alertsTable.setVisible(False)
        self.fwTable.setVisible(False)
        self.rulesTable.setVisible(True)
        self.tabWidget.setCurrentIndex(cur_idx)

        return r_name, node

    def _set_events_query(self):
        if self.tabWidget.currentIndex() != self.TAB_MAIN:
            return

        model = self.TABLES[self.TAB_MAIN]['view'].model()
        qstr = self._db.get_query(self.TABLES[self.TAB_MAIN]['name'], self.TABLES[self.TAB_MAIN]['display_fields'])

        filter_text = self.filterLine.text()
        action = ""
        if self.comboAction.currentIndex() == 1:
            action = "action = \"{0}\"".format(Config.ACTION_ALLOW)
        elif self.comboAction.currentIndex() == 2:
            action = "action = \"{0}\"".format(Config.ACTION_DENY)
        elif self.comboAction.currentIndex() == 3:
            action = "action = \"{0}\"".format(Config.ACTION_REJECT)

        # FIXME: use prepared statements
        if filter_text == "":
            if action != "":
                qstr += " WHERE " + action
        else:
            if action != "":
                action += " AND "
            qstr += " WHERE " + action + " (" \
                    " process LIKE '%" + filter_text + "%'" \
                    " OR process_args LIKE '%" + filter_text + "%'" \
                    " OR src_port LIKE '%" + filter_text + "%'" \
                    " OR src_ip LIKE '%" + filter_text + "%'" \
                    " OR dst_ip LIKE '%" + filter_text + "%'" \
                    " OR dst_host LIKE '%" + filter_text + "%'" \
                    " OR dst_port LIKE '%" + filter_text + "%'" \
                    " OR rule LIKE '%" + filter_text + "%'" \
                    " OR node LIKE '%" + filter_text + "%'" \
                    " OR time LIKE '%" + filter_text + "%'" \
                    " OR uid LIKE '%" + filter_text + "%'" \
                    " OR pid LIKE '%" + filter_text + "%'" \
                    " OR protocol LIKE '%" + filter_text + "%')" \

        qstr += self._get_order() + self._get_limit()
        self.setQuery(model, qstr)

    def _set_nodes_query(self, data):
        if data != self.LAST_SELECTED_ITEM:
            self._monitor_selected_node(data, "", "", "", "")

        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "MAX(c.time) as {0}, " \
                "c.action as {1}, " \
                "count(c.process) as {2}, " \
                "c.uid as {3}, " \
                "c.protocol as {4}, " \
                "c.src_port as {5}, " \
                "c.src_ip as {6}, " \
                "c.dst_ip as {7}, " \
                "c.dst_host as {8}, " \
                "c.dst_port as {9}, " \
                "c.pid as {10}, " \
                "c.process as {11}, " \
                "c.process_args as {12}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {13} " \
            "FROM connections as c " \
            "WHERE c.node = '{14}' GROUP BY {15}, c.process_args, c.uid, c.src_ip, c.dst_ip, c.dst_host, c.dst_port, c.protocol {16}".format(
                self.COL_STR_TIME,
                self.COL_STR_ACTION,
                self.COL_STR_HITS,
                self.COL_STR_UID,
                self.COL_STR_PROTOCOL,
                self.COL_STR_SRC_PORT,
                self.COL_STR_SRC_IP,
                self.COL_STR_DST_IP,
                self.COL_STR_DST_HOST,
                self.COL_STR_DST_PORT,
                self.COL_STR_PID,
                self.COL_STR_PROCESS,
                self.COL_STR_PROC_CMDLINE,
                self.COL_STR_RULE,
                data,
                self.COL_STR_PROCESS,
                self._get_order() + self._get_limit()))

    def _get_nodes_filter_query(self, lastQuery, text):
        base_query = lastQuery.split("GROUP BY")
        if not self.IN_DETAIL_VIEW[self.TAB_NODES]:
            base_query = lastQuery.split("ORDER BY")

        qstr = base_query[0]
        if "AND" in qstr:
            # strip out ANDs if any
            os = qstr.split('AND')
            qstr = os[0]

        if text != "":
            if self.IN_DETAIL_VIEW[self.TAB_NODES]:
                qstr += "AND (c.time LIKE '%{0}%' OR " \
                    "c.action LIKE '%{0}%' OR " \
                    "c.uid LIKE '%{0}%' OR " \
                    "c.pid LIKE '%{0}%' OR " \
                    "c.src_port LIKE '%{0}%' OR " \
                    "c.dst_port LIKE '%{0}%' OR " \
                    "c.src_ip LIKE '%{0}%' OR " \
                    "c.dst_ip LIKE '%{0}%' OR " \
                    "c.dst_host LIKE '%{0}%' OR " \
                    "c.process LIKE '%{0}%' OR " \
                    "c.process_cwd LIKE '%{0}%' OR " \
                    "c.process_args LIKE '%{0}%')".format(text)
            else:
                if "WHERE" in qstr:
                    w = qstr.split('WHERE')
                    qstr = w[0]

                qstr += "WHERE (" \
                    "last_connection LIKE '%{0}%' OR " \
                    "addr LIKE '%{0}%' OR " \
                    "status LIKE '%{0}%' OR " \
                    "hostname LIKE '%{0}%' OR " \
                    "version LIKE '%{0}%'" \
                    ")".format(text)

        if self.IN_DETAIL_VIEW[self.TAB_NODES]:
            qstr += " GROUP BY" + base_query[1]
        else:
            qstr += " ORDER BY" + base_query[1]

        return qstr

    def _reset_node_info(self, status=""):
        # value 0 is continuous progress
        self.nodeRAMProgress.setMaximum(1)
        self.nodeRAMProgress.setValue(0)
        self.labelNodeProcs.setText("")
        self.labelNodeLoadAvg.setText("")
        self.labelNodeUptime.setText("")
        self.labelNodeSwap.setText("")
        self.labelNodeRAM.setText(status)

    def _monitor_selected_node(self, node_addr, col_uptime, col_hostname, col_version, col_kernel):
        # TODO:
        #  - create a tasks package, to centralize/normalize tasks' names and
        #  config
        if not self._nodes.is_connected(node_addr):
            self._reset_node_info(QC.translate("stats", "node not connected"))
        else:
            noti = ui_pb2.Notification(
                clientName="",
                serverName="",
                type=ui_pb2.TASK_START,
                data='{"name": "node-monitor", "data": {"node": "%s", "interval": "5s"}}' % node_addr,
                rules=[])
            nid = self._nodes.send_notification(
                node_addr, noti, self._notification_callback
            )
            if nid != None:
                self._notifications_sent[nid] = noti

            self.nodeRAMProgress.setMaximum(0)
            self.nodeSwapProgress.setMaximum(0)
            self.labelNodeName.setText(QC.translate("stats", "loading node information..."))
            self.labelNodeName.setText("<h3>{0}</h3>".format(col_hostname))
            self.labelNodeDetails.setText(
                QC.translate(
                    "stats",
                    "<p><strong>daemon uptime:</strong> {0}</p>".format(col_uptime) + \
                    "<p><strong>Version:</strong> {0}</p>".format(col_version) + \
                    "<p><strong>Kernel:</strong> {0}</p>".format(col_kernel)
                )
            )

    def _unmonitor_deselected_node(self, last_addr):
        if not self._nodes.is_connected(last_addr):
            self._reset_node_info(QC.translate("stats", "node not connected"))
        else:
            noti = ui_pb2.Notification(
                clientName="",
                serverName="",
                type=ui_pb2.TASK_STOP,
                data='{"name": "node-monitor", "data": {"node": "%s", "interval": "5s"}}' % last_addr,
                rules=[])
            nid = self._nodes.send_notification(
                last_addr, noti, self._notification_callback
            )
            if nid != None:
                self._notifications_sent[nid] = noti
            self.labelNodeDetails.setText("")
            print("taskStop, prev node:", last_addr, "nid:", nid)

            # XXX: would be useful to leave latest data?
            #self._reset_node_info()

    def _monitor_node_netstat(self):
        # TODO:
        #  - create a tasks package, to centralize/normalize tasks' names and
        #  config
        self.netstatLabel.show()

        node_addr = self.comboNetstatNodes.currentText()
        if node_addr == "":
            print("monitor_netstat_node: no nodes")
            self.netstatLabel.setText("")
            return
        if not self._nodes.is_connected(node_addr):
            print("monitor_node_netstat, node not connected:", node_addr)
            self.netstatLabel.setText("{0} node is not connected".format(node_addr))
            return

        refreshIndex = self.comboNetstatInterval.currentIndex()
        if refreshIndex == 0:
            self._unmonitor_node_netstat(node_addr)
            return

        refreshInterval = self.comboNetstatInterval.currentText()
        proto = self.comboNetstatProto.currentIndex()
        family = self.comboNetstatFamily.currentIndex()
        state = self.comboNetstatStates.currentIndex()
        config = '{"name": "sockets-monitor", "data": {"interval": "%s", "state": %d, "proto": %d, "family": %d}}' % (
            refreshInterval,
            int(self.comboNetstatStates.itemData(state)),
            int(self.comboNetstatProto.itemData(proto)),
            int(self.comboNetstatFamily.itemData(family))
        )

        self.netstatLabel.setText(QC.translate("stats", "loading in {0}...".format(refreshInterval)))

        noti = ui_pb2.Notification(
            clientName="",
            serverName="",
            type=ui_pb2.TASK_START,
            data=config,
            rules=[])
        nid = self._nodes.send_notification(
            node_addr, noti, self._notification_callback
        )
        if nid != None:
            self._notifications_sent[nid] = noti

        self.LAST_SELECTED_ITEM = node_addr

    def _unmonitor_node_netstat(self, node_addr):
        self.netstatLabel.hide()
        self.netstatLabel.setText("")
        if node_addr == "":
            print("unmonitor_netstat_node: no nodes")
            return

        if not self._nodes.is_connected(node_addr):
            print("unmonitor_node_netstat, node not connected:", node_addr)
        else:
            noti = ui_pb2.Notification(
                clientName="",
                serverName="",
                type=ui_pb2.TASK_STOP,
                data='{"name": "sockets-monitor", "data": {}}',
                rules=[])
            nid = self._nodes.send_notification(
                node_addr, noti, self._notification_callback
            )
            if nid != None:
                self._notifications_sent[nid] = noti

    def _update_netstat_table(self, node_addr, data):
        netstat = json.loads(data)
        fields = []
        values = []
        cols = "(last_seen, node, src_port, src_ip, dst_ip, dst_port, proto, uid, inode, iface, family, state, cookies, rqueue, wqueue, expires, retrans, timer, proc_path, proc_comm, proc_pid)"
        try:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # TODO: make this optional
            self._db.clean(self.TABLES[self.TAB_NETSTAT]['name'])
            self._db.transaction()
            for k in netstat['Table']:
                if k == None:
                    continue
                sck = k['Socket']
                iface = k['Socket']['ID']['Interface']
                if k['Iface'] != "":
                    iface = k['Iface']
                proc_comm = ""
                proc_path = ""
                proc_pid = ""
                if k['PID'] != -1 and str(k['PID']) in netstat['Processes'].keys():
                    proc_pid = str(k['PID'])
                    proc_path = netstat['Processes'][proc_pid]['Path']
                    proc_comm = netstat['Processes'][proc_pid]['Comm']
                self._db.insert(
                    self.TABLES[self.TAB_NETSTAT]['name'],
                    cols,
                    (
                        now,
                        node_addr,
                        k['Socket']['ID']['SourcePort'],
                        k['Socket']['ID']['Source'],
                        k['Socket']['ID']['Destination'],
                        k['Socket']['ID']['DestinationPort'],
                        k['Proto'],
                        k['Socket']['UID'],
                        k['Socket']['INode'],
                        iface,
                        k['Socket']['Family'],
                        k['Socket']['State'],
                        str(k['Socket']['ID']['Cookie']),
                        k['Socket']['RQueue'],
                        k['Socket']['WQueue'],
                        k['Socket']['Expires'],
                        k['Socket']['Retrans'],
                        k['Socket']['Timer'],
                        proc_path,
                        proc_comm,
                        proc_pid
                    )
                )
            self._db.commit()
            self.netstatLabel.setText(QC.translate("stats", "refreshing..."))
            self._refresh_active_table()
        except Exception as e:
            print("_update_netstat_table exception:", e)
            print(data)
            self.netstatLabel.setText("error loading netstat table")
            self.netstatLabel.setText(QC.translate("stats", "error loading: {0}".format(repr(e))))

# create plugins and actions before dialogs

    def _update_node_info(self, data):
        try:
            # TODO: move to .utils
            def formatUptime(uptime):
                hours = uptime / 3600
                minutes = uptime % 3600 / 60
                #seconds = uptime % 60
                days = (uptime / 1440) / 60
                months = 0
                years = 0
                if days > 0:
                    hours = hours % 24
                    minutes = (uptime % 3600) / 60

                if days > 0:
                    uptime = "{0:.0f} days {1:.0f}h {2:.0f}m".format(days, hours, minutes)
                else:
                    uptime = "{0:.0f}h {1:.0f}m".format(hours, minutes)

                return QC.translate(
                    "stats",
                    "<strong>System uptime:</strong> %s" % uptime
                )

            # TODO: move to .utils
            def bytes2units(value):
                units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
                idx = 0
                while value / 1024 > 0:
                    value = value / 1024
                    idx+=1
                    if value < 1024:
                        break

                return "{0:.0f} {1}".format(value, units [idx])

            node_data = json.loads(data)
            load1 = node_data['Loads'][0] / 100000
            totalRam = node_data['Totalram']
            totalSwap = node_data['Totalswap']
            freeRam = totalRam - node_data['Freeram']
            freeSwap = totalSwap - node_data['Freeswap']
            self.nodeRAMProgress.setMaximum(int(totalRam/1000))
            self.nodeRAMProgress.setValue(int(freeRam/1000))
            self.nodeRAMProgress.setFormat("%p%")
            self.nodeSwapProgress.setMaximum(int(totalSwap/1000))
            self.nodeSwapProgress.setFormat("%p%")
            self.nodeSwapProgress.setValue(int(freeSwap/1000))

            # if any of these values is 0, set max progressbar value to 1, to
            # avoid the "busy" effect:
            # https://doc.qt.io/qtforpython-5/PySide2/QtWidgets/QProgressBar.html#detailed-description
            if self.nodeRAMProgress.value() == 0:
                self.nodeRAMProgress.setMaximum(1)
            if self.nodeSwapProgress.value() == 0:
                self.nodeSwapProgress.setMaximum(1)

            ram = bytes2units(totalRam)
            free = bytes2units(node_data['Freeram'])
            swap = bytes2units(totalSwap)
            freeSwap = bytes2units(node_data['Freeswap'])

            self.labelNodeRAM.setText("<strong>RAM:</strong> {0} <strong>Free:</strong> {1}".format(ram, free))
            self.labelNodeSwap.setText("<strong>Swap:</strong> {0} <strong>Free:</strong> {1}".format(swap, freeSwap))
            self.labelNodeProcs.setText(
                QC.translate("stats", "<strong>Processes:</strong> {0}".format(node_data['Procs']))
            )
            self.nodeRAMProgress.setFormat("%p%")
            self.nodeSwapProgress.setFormat("%p%")
            self.labelNodeLoadAvg.setText(
                QC.translate(
                    "stats",
                    "<strong>Load avg:</strong> {0:.2f}, {1:.2f}, {2:.2f}".format(
                        node_data['Loads'][0] / 100000,
                        node_data['Loads'][1] / 100000,
                        node_data['Loads'][2] / 100000
                    )
                )

            )
            self.labelNodeUptime.setText(formatUptime(node_data['Uptime']))
        except Exception as e:
            print("exception parsing taskStart data:", e, data)
        # TODO: update nodes tab

    def _update_nodes_interception_status(self, show=True, disable=False):
        addr = self.TABLES[self.TAB_NODES]['label'].text()
        node_cfg = self._nodes.get_node(addr)
        if node_cfg == None:
            self.nodeStartButton.setVisible(False)
            self.nodePrefsButton.setVisible(False)
            self.nodeDeleteButton.setVisible(False)
            self.nodeActionsButton.setVisible(False)
            return
        self.nodeStartButton.setVisible(show)
        self.nodePrefsButton.setVisible(show)
        self.nodeActionsButton.setVisible(show)
        if not node_cfg['data'].isFirewallRunning or disable:
            self.nodeStartButton.setChecked(False)
            self.nodeStartButton.setDown(False)
            self.nodeStartButton.setIcon(self.iconStart)
        else:
            self.nodeStartButton.setIcon(self.iconPause)
            self.nodeStartButton.setChecked(True)
            self.nodeStartButton.setDown(True)

    def _set_rules_filter(self, parent_row=-1, item_row=0, what="", what1="", what2="", action_filter=None, rule_focus=None):
        self._rules_filter_state_initialized = True
        self._rules_filter_state = {
            "parent_row": parent_row,
            "item_row": item_row,
            "what": "" if what is None else what,
            "what1": "" if what1 is None else what1,
            "what2": "" if what2 is None else what2,
            "action_filter": action_filter,
            "rule_focus": rule_focus
        }
        section = self.FILTER_TREE_APPS
        selection_value = what

        if parent_row == -1:

            if item_row == self.RULES_TREE_NODES:
                section=self.FILTER_TREE_NODES
                what=""
            elif item_row == self.RULES_TREE_ALERTS:
                section=self.FILTER_TREE_NODES
                what=""
                model = self._get_active_table().model()
                alerts_query = "SELECT {0} FROM alerts {1} {2}".format(
                    self.TABLES[self.TAB_ALERTS]['display_fields'],
                    self._get_order(),
                    self._get_limit()
                )
                self.setQuery(model, alerts_query)
                return
            elif item_row == self.RULES_TREE_FIREWALL:
                self.TABLES[self.TAB_FIREWALL]['view'].model().filterAll()
                return
            else:
                section=self.FILTER_TREE_APPS
                what=""

        elif parent_row == self.RULES_TREE_APPS:
            if item_row == self.RULES_TREE_PERMANENT:
                section=self.FILTER_TREE_APPS
                what=self.RULES_TYPE_PERMANENT
            elif item_row == self.RULES_TREE_TEMPORARY:
                section=self.FILTER_TREE_APPS
                what=self.RULES_TYPE_TEMPORARY

        elif parent_row == self.RULES_TREE_NODES:
            section=self.FILTER_TREE_NODES

        elif parent_row == self.RULES_TREE_FIREWALL:
            if item_row == self.FILTER_TREE_FW_NODE:
                self.TABLES[self.TAB_FIREWALL]['view'].filterByNode(what)
            elif item_row == self.FILTER_TREE_FW_TABLE:
                parm = what.split("-")
                if len(parm) < 2:
                    return
                self.TABLES[self.TAB_FIREWALL]['view'].filterByTable(what1, parm[0], parm[1])
            elif item_row == self.FILTER_TREE_FW_CHAIN: # + table
                parm = what.split("-")
                tbl = what1.split("-")
                self.TABLES[self.TAB_FIREWALL]['view'].filterByChain(what2, tbl[0], tbl[1], parm[0], parm[1])
            return

        def _append_condition(base, clause):
            clause = clause.strip()
            if clause == "":
                return base
            if base == "":
                return "WHERE " + clause
            if base.endswith(" "):
                base = base.rstrip()
            return base + " AND " + clause

        def _escape(value):
            return "" if value is None else str(value).replace("'", "''")

        if section == self.FILTER_TREE_APPS:
            if what == self.RULES_TYPE_TEMPORARY:
                what = "WHERE r.duration != '%s'" % Config.DURATION_ALWAYS
            elif what == self.RULES_TYPE_PERMANENT:
                what = "WHERE r.duration = '%s'" % Config.DURATION_ALWAYS
        elif section == self.FILTER_TREE_NODES and what != "":
            what = "WHERE r.node = '%s'" % what

        # apply duration filter from the contextual menu
        mode_clause = ""
        if self._rules_filter_mode == self.FILTER_RULES_PERM:
            mode_clause = "(r.duration IN ('{0}','{1}'))".format(
                Config.DURATION_ALWAYS,
                Config.DURATION_UNTIL_RESTART
            )
        elif self._rules_filter_mode == self.FILTER_RULES_TEMP_ACTIVE:
            mode_clause = "(r.duration NOT IN ('{0}','{1}') AND r.enabled='True')".format(
                Config.DURATION_ALWAYS,
                Config.DURATION_UNTIL_RESTART
            )
        elif self._rules_filter_mode == self.FILTER_RULES_TEMP_EXPIRED:
            mode_clause = "(r.duration NOT IN ('{0}','{1}') AND r.enabled='False')".format(
                Config.DURATION_ALWAYS,
                Config.DURATION_UNTIL_RESTART
            )
        what = _append_condition(what, mode_clause)

        filter_text = self.filterLine.text().strip()
        if filter_text != "":
            filter_clause = "(r.name LIKE '%{0}%' OR r.operator_data LIKE '%{0}%')".format(filter_text)
            what = _append_condition(what, filter_clause)

        if selection_value in (self.RULES_TYPE_PERMANENT, self.RULES_TYPE_TEMPORARY):
            current_action = action_filter or self.RULES_ACTION_ALL
            if current_action == self.RULES_ACTION_ALLOW:
                what = _append_condition(what, "r.action = '{0}'".format(Config.ACTION_ALLOW))
            elif current_action == self.RULES_ACTION_DENY:
                what = _append_condition(
                    what,
                    "r.action IN ('{0}','{1}')".format(Config.ACTION_DENY, Config.ACTION_REJECT)
                )

        if rule_focus:
            focus_name, focus_node = rule_focus
            if focus_name:
                what = _append_condition(what, "r.name = '{0}'".format(_escape(focus_name)))
            if focus_node:
                what = _append_condition(what, "r.node = '{0}'".format(_escape(focus_node)))

        rules_view = self.TABLES[self.TAB_RULES]['view']
        model = rules_view.model()
        self.setQuery(model, "SELECT {0} FROM rules as r {1} {2} {3}".format(
            self.TABLES[self.TAB_RULES]['display_fields'],
            what,
            self._get_order(),
            self._get_limit()
        ))
        rules_view.refresh()
        self._update_rule_focus_indicator(model)

    def _reapply_rules_filter(self, update_timeleft=False):
        if not getattr(self, "_rules_filter_state_initialized", False):
            self._set_rules_filter()
            if update_timeleft:
                self._update_timeleft_column()
            return
        state = getattr(self, "_rules_filter_state", None)
        if state is None:
            state = {
                "parent_row": -1,
                "item_row": self.RULES_TREE_APPS,
                "what": "",
                "what1": "",
                "what2": "",
                "action_filter": None,
                "rule_focus": None
            }
        self._set_rules_filter(
            state["parent_row"],
            state["item_row"],
            state["what"],
            state["what1"],
            state["what2"],
            state.get("action_filter"),
            state.get("rule_focus")
        )
        if update_timeleft:
            self._update_timeleft_column()

    def _set_rules_query(self, rule_name="", node=""):
        if node != "":
            node = "c.node = '%s'" % node
        if rule_name != "":
            rule_name = "c.rule = '%s'" % rule_name

        condition = "%s AND %s" % (rule_name, node) if rule_name != "" and node != "" else ""

        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "MAX(c.time) as {0}, " \
                "c.node as {1}, " \
                "count(c.process) as {2}, " \
                "c.uid as {3}, " \
                "c.protocol as {4}, " \
                "c.src_port as {5}, " \
                "c.src_ip as {6}, " \
                "c.dst_ip as {7}, " \
                "c.dst_host as {8}, " \
                "c.dst_port as {9}, " \
                "c.pid as {10}, " \
                "c.process as {11}, " \
                "c.process_args as {12}, " \
                "c.process_cwd as CWD " \
            "FROM connections as c " \
            "WHERE {13} GROUP BY c.process, c.process_args, c.uid, c.dst_ip, c.dst_host, c.dst_port {14}".format(
                self.COL_STR_TIME,
                self.COL_STR_NODE,
                self.COL_STR_HITS,
                self.COL_STR_UID,
                self.COL_STR_PROTOCOL,
                self.COL_STR_SRC_PORT,
                self.COL_STR_SRC_IP,
                self.COL_STR_DST_IP,
                self.COL_STR_DST_HOST,
                self.COL_STR_DST_PORT,
                self.COL_STR_PID,
                self.COL_STR_PROCESS,
                self.COL_STR_PROC_CMDLINE,
                condition,
                self._get_order() + self._get_limit()
            ))

    def _set_hosts_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "MAX(c.time) as {0}, " \
                "c.node as {1}, " \
                "count(c.process) as {2}, " \
                "c.action as {3}, " \
                "c.uid as {4}, " \
                "c.protocol as {5}, " \
                "c.src_port as {6}, " \
                "c.src_ip as {7}, " \
                "c.dst_ip as {8}, " \
                "c.dst_port as {9}, " \
                "c.pid as {10}, " \
                "c.process as {11}, " \
                "c.process_args as {12}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {13} " \
            "FROM connections as c " \
            "WHERE c.dst_host = '{14}' GROUP BY c.pid, {15}, c.process_args, c.src_ip, c.dst_ip, c.dst_port, c.protocol, c.action, c.node {16}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_UID,
                          self.COL_STR_PROTOCOL,
                          self.COL_STR_SRC_PORT,
                          self.COL_STR_SRC_IP,
                          self.COL_STR_DST_IP,
                          self.COL_STR_DST_PORT,
                          self.COL_STR_PID,
                          self.COL_STR_PROCESS,
                          self.COL_STR_PROC_CMDLINE,
                          self.COL_STR_RULE,
                          data,
                          self.COL_STR_PROCESS,
                self._get_order("1") + self._get_limit()))

    def _set_process_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "MAX(c.time) as {0}, " \
                "c.node as {1}, " \
                "count(c.dst_ip) as {2}, " \
                "c.action as {3}, " \
                "c.uid as {4}, " \
                "c.protocol as {5}, " \
                "c.src_port as {6}, " \
                "c.src_ip as {7}, " \
                "c.dst_ip as {8}, " \
                "c.dst_host as {9}, " \
                "c.dst_port as {10}, " \
                "c.pid as {11}, " \
                "c.process_args as {12}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {13} " \
            "FROM connections as c " \
            "WHERE c.process = '{14}' " \
                      "GROUP BY c.src_ip, c.dst_ip, c.dst_host, c.dst_port, c.uid, c.action, c.node, c.pid, c.process_args {15}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_UID,
                          self.COL_STR_PROTOCOL,
                          self.COL_STR_SRC_PORT,
                          self.COL_STR_SRC_IP,
                          self.COL_STR_DST_IP,
                          self.COL_STR_DST_HOST,
                          self.COL_STR_DST_PORT,
                          self.COL_STR_PID,
                          self.COL_STR_PROC_CMDLINE,
                          self.COL_STR_RULE,
                          data,
                          self._get_order("1") + self._get_limit()))

        nrows = self._get_active_table().model().rowCount()
        self.cmdProcDetails.setVisible(nrows != 0)

    def _set_addrs_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "MAX(c.time) as {0}, " \
                "c.node as {1}, " \
                "count(c.dst_ip) as {2}, " \
                "c.action as {3}, " \
                "c.uid as {4}, " \
                "c.protocol as {5}, " \
                "c.src_port as {6}, " \
                "c.src_ip as {7}, " \
                "c.dst_host as {8}, " \
                "c.dst_port as {9}, " \
                "c.pid as {10}, " \
                "c.process as {11}, " \
                "c.process_args as {12}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {13} " \
            "FROM connections as c " \
            "WHERE c.dst_ip = '{14}' GROUP BY c.pid, {15}, c.process_args, c.src_ip, c.dst_port, {16}, c.protocol, c.action, c.uid, c.node {17}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_UID,
                          self.COL_STR_PROTOCOL,
                          self.COL_STR_SRC_PORT,
                          self.COL_STR_SRC_IP,
                          self.COL_STR_DST_HOST,
                          self.COL_STR_DST_PORT,
                          self.COL_STR_PID,
                          self.COL_STR_PROCESS,
                          self.COL_STR_PROC_CMDLINE,
                          self.COL_STR_RULE,
                          data,
                          self.COL_STR_PROCESS,
                          self.COL_STR_DST_HOST,
                          self._get_order("1") + self._get_limit()))

    def _set_ports_query(self, data):
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "MAX(c.time) as {0}, " \
                "c.node as {1}, " \
                "count(c.dst_ip) as {2}, " \
                "c.action as {3}, " \
                "c.uid as {4}, " \
                "c.protocol as {5}, " \
                "c.src_port as {6}, " \
                "c.src_ip as {7}, " \
                "c.dst_ip as {8}, " \
                "c.dst_host as {9}, " \
                "c.pid as {10}, " \
                "c.process as {11}, " \
                "c.process_args as {12}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {13} " \
            "FROM connections as c " \
            "WHERE c.dst_port = '{14}' GROUP BY c.pid, {15}, c.process_args, {16}, c.src_ip, c.dst_ip, c.protocol, c.action, c.uid, c.node {17}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_UID,
                          self.COL_STR_PROTOCOL,
                          self.COL_STR_SRC_PORT,
                          self.COL_STR_SRC_IP,
                          self.COL_STR_DST_IP,
                          self.COL_STR_DST_HOST,
                          self.COL_STR_PID,
                          self.COL_STR_PROCESS,
                          self.COL_STR_PROC_CMDLINE,
                          self.COL_STR_RULE,
                          data,
                          self.COL_STR_PROCESS,
                          self.COL_STR_DST_HOST,
                          self._get_order("1") + self._get_limit()))

    def _set_users_query(self, data):
        uid = data.split(" ")
        if len(uid) == 2:
            uid = uid[1].strip("()")
        else:
            uid = uid[0]
        model = self._get_active_table().model()
        self.setQuery(model, "SELECT " \
                "MAX(c.time) as {0}, " \
                "c.node as {1}, " \
                "count(c.dst_ip) as {2}, " \
                "c.action as {3}, " \
                "c.protocol as {4}, " \
                "c.src_port as {5}, " \
                "c.src_ip as {6}, " \
                "c.dst_ip as {7}, " \
                "c.dst_host as {8}, " \
                "c.dst_port as {9}, " \
                "c.pid as {10}, " \
                "c.process as {11}, " \
                "c.process_args as {12}, " \
                "c.process_cwd as CWD, " \
                "c.rule as {13} " \
            "FROM connections as c " \
            "WHERE c.uid = '{14}' GROUP BY c.pid, {15}, c.process_args, c.src_ip, c.dst_ip, c.dst_host, c.dst_port, c.protocol, c.action, c.node {16}".format(
                          self.COL_STR_TIME,
                          self.COL_STR_NODE,
                          self.COL_STR_HITS,
                          self.COL_STR_ACTION,
                          self.COL_STR_PROTOCOL,
                          self.COL_STR_SRC_PORT,
                          self.COL_STR_SRC_IP,
                          self.COL_STR_DST_IP,
                          self.COL_STR_DST_HOST,
                          self.COL_STR_DST_PORT,
                          self.COL_STR_PID,
                          self.COL_STR_PROCESS,
                          self.COL_STR_PROC_CMDLINE,
                          self.COL_STR_RULE,
                          uid,
                          self.COL_STR_PROCESS,
                          self._get_order("1") + self._get_limit()))

    # get the query filtering by text when a tab is in the detail view.
    def _get_indetail_filter_query(self, lastQuery, text):
        try:
            cur_idx = self.tabWidget.currentIndex()
            base_query = lastQuery.split("GROUP BY")
            qstr = base_query[0]
            where = qstr.split("WHERE")[1]  # get SELECT ... WHERE (*)
            ands = where.split("AND (")[0] # get WHERE (*) AND (...)
            qstr = qstr.split("WHERE")[0]  # get * WHERE ...
            qstr += "WHERE %s" % ands.lstrip()

            # if there's no text to filter, strip the filter "AND ()", and
            # return the original query.
            if text == "":
                return

            qstr += "AND (c.time LIKE '%{0}%' OR " \
                "c.action LIKE '%{0}%' OR " \
                "c.pid LIKE '%{0}%' OR " \
                "c.protocol LIKE '%{0}%' OR " \
                "c.src_port LIKE '%{0}%' OR " \
                "c.src_ip LIKE '%{0}%' OR " \
                "c.process_cwd LIKE '%{0}%' OR " \
                "c.rule LIKE '%{0}%' OR ".format(text)

            # exclude from query the field of the view we're filtering by
            if self.IN_DETAIL_VIEW[cur_idx] != self.TAB_PORTS:
                qstr += "c.dst_port LIKE '%{0}%' OR ".format(text)
            if self.IN_DETAIL_VIEW[cur_idx] != self.TAB_ADDRS:
                qstr += "c.dst_ip LIKE '%{0}%' OR ".format(text)
            if self.IN_DETAIL_VIEW[cur_idx] != self.TAB_HOSTS:
                qstr += "c.dst_host LIKE '%{0}%' OR ".format(text)
            if self.IN_DETAIL_VIEW[cur_idx] != self.TAB_PROCS:
                qstr += "c.process LIKE '%{0}%' OR ".format(text)
            if self.IN_DETAIL_VIEW[cur_idx] != self.TAB_USERS:
                qstr += "c.uid LIKE '%{0}%' OR ".format(text)

            qstr += "c.process_args LIKE '%{0}%')".format(text)

        finally:
            if len(base_query) > 1:
                qstr += " GROUP BY" + base_query[1]
            return qstr

    @QtCore.pyqtSlot()
    def _on_settings_saved(self):
        self._ui_refresh_interval = self._cfg.getInt(Config.STATS_REFRESH_INTERVAL, 0)
        self._show_columns()
        self.settings_saved.emit()

    def _on_menu_node_export_clicked(self, triggered):
        outdir = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            os.path.expanduser("~"),
            QC.translate("stats", 'Select a directory to export rules'),
            QtWidgets.QFileDialog.Option.ShowDirsOnly | QtWidgets.QFileDialog.Option.DontResolveSymlinks
        )
        if outdir == "":
            return

        node = self.nodesLabel.text()
        if self._nodes.export_rules(node, outdir) == False:
            Message.ok("Rules export error",
                       QC.translate("stats",
                                    "Error exporting rules"
                                    ),
                       QtWidgets.QMessageBox.Icon.Warning)
        else:
            Message.ok("Rules export",
                       QC.translate("stats", "Rules exported to {0}".format(outdir)),
                       QtWidgets.QMessageBox.Icon.Information)


    def _on_menu_node_import_clicked(self, triggered):
        rulesdir = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            os.path.expanduser("~"),
            QC.translate("stats", 'Select a directory with rules to import (JSON files)'),
            QtWidgets.QFileDialog.Option.ShowDirsOnly | QtWidgets.QFileDialog.Option.DontResolveSymlinks
        )
        if rulesdir == '':
                return

        node = self.nodesLabel.text()
        nid, notif, rules = self._nodes.import_rules(addr=node, rulesdir=rulesdir, callback=self._notification_callback)
        if nid != None:
                self._notifications_sent[nid] = notif
                # TODO: add rules per node and after receiving the notification
                for node in self._nodes.get_nodes():
                    self._nodes.add_rules(node, rules)

                Message.ok("Rules import",
                        QC.translate("stats", "Rules imported fine"),
                        QtWidgets.QMessageBox.Icon.Information)
                if self.tabWidget.currentIndex() == self.TAB_RULES:
                    self._refresh_active_table()
        else:
                Message.ok("Rules import error",
                        QC.translate("stats",
                                        "Error importing rules from {0}".format(rulesdir)
                                        ),
                        QtWidgets.QMessageBox.Icon.Warning)



    def _on_menu_exit_clicked(self, triggered):
        self.close_trigger.emit()

    def _on_menu_export_clicked(self, triggered):
        outdir = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            os.path.expanduser("~"),
            QC.translate("stats", 'Select a directory to export rules'),
            QtWidgets.QFileDialog.Option.ShowDirsOnly | QtWidgets.QFileDialog.Option.DontResolveSymlinks
        )
        if outdir == "":
            return

        errors = []
        for node in self._nodes.get_nodes():
            if self._nodes.export_rules(node, outdir) == False:
                errors.append(node)
           # apply_to_node()...

        if len(errors) > 0:
            errorlist = ""
            for e in errors:
                errorlist = errorlist + e + "<br>"
            Message.ok("Rules export error",
                       QC.translate("stats",
                                    "Error exporting rules of the following nodes:<br><br>{0}"
                                    .format(errorlist)
                                    ),
                       QtWidgets.QMessageBox.Icon.Warning)
        else:
            Message.ok("Rules export",
                       QC.translate("stats", "Rules exported to {0}".format(outdir)),
                       QtWidgets.QMessageBox.Icon.Information)

    def _on_menu_import_clicked(self, triggered):
       rulesdir = QtWidgets.QFileDialog.getExistingDirectory(
           self,
           os.path.expanduser("~"),
           QC.translate("stats", 'Select a directory with rules to import (JSON files)'),
           QtWidgets.QFileDialog.Option.ShowDirsOnly | QtWidgets.QFileDialog.Option.DontResolveSymlinks
       )
       if rulesdir == '':
            return

       nid, notif, rules = self._nodes.import_rules(rulesdir=rulesdir, callback=self._notification_callback)
       if nid != None:
            self._notifications_sent[nid] = notif
            # TODO: add rules per node and after receiving the notification
            for node in self._nodes.get_nodes():
                self._nodes.add_rules(node, rules)

            Message.ok("Rules import",
                       QC.translate("stats", "Rules imported fine"),
                       QtWidgets.QMessageBox.Icon.Information)
            if self.tabWidget.currentIndex() == self.TAB_RULES:
                self._refresh_active_table()
       else:
            Message.ok("Rules import error",
                       QC.translate("stats",
                                    "Error importing rules from {0}".format(rulesdir)
                                    ),
                       QtWidgets.QMessageBox.Icon.Warning)

    def _on_menu_export_csv_clicked(self, triggered):
        tab_idx = self.tabWidget.currentIndex()

        filename = QtWidgets.QFileDialog.getSaveFileName(
            self,
            QC.translate("stats", 'Save as CSV'),
            self._file_names[tab_idx],
            'All Files (*);;CSV Files (*.csv)')[0].strip()
        if filename == '':
            return

        with self._lock:
            table = self._tables[tab_idx]
            ncols = table.model().columnCount()
            nrows = table.model().rowCount()
            cols = []

            for col in range(0, ncols):
                cols.append(table.model().headerData(col, QtCore.Qt.Orientation.Horizontal))

            with open(filename, 'w') as csvfile:
                w = csv.writer(csvfile, dialect='excel')
                w.writerow(cols)

                if tab_idx == self.TAB_MAIN:
                    w.writerows(table.model().dumpRows())
                else:
                    for row in range(0, nrows):
                        values = []
                        for col in range(0, ncols):
                            values.append(table.model().index(row, col).data())
                        w.writerow(values)

    def _setup_table(self,
                     widget,
                     tableWidget,
                     table_name,
                     fields="*",
                     group_by="",
                     order_by="2",
                     sort_direction=SORT_ORDER[1],
                     limit="",
                     resize_cols=(),
                     model=None,
                     delegate=None,
                     verticalScrollBar=None,
                     tracking_column=COL_TIME):
        tableWidget.setSortingEnabled(True)
        if model == None:
            model = self._db.get_new_qsql_model()
        if verticalScrollBar != None:
            tableWidget.setVerticalScrollBar(verticalScrollBar)
        tableWidget.verticalScrollBar().sliderPressed.connect(self._cb_scrollbar_pressed)
        tableWidget.verticalScrollBar().sliderReleased.connect(self._cb_scrollbar_released)
        tableWidget.setTrackingColumn(tracking_column)
        try:
            tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        except Exception:
            pass

        self.setQuery(model, "SELECT " + fields + " FROM " + table_name + group_by + " ORDER BY " + order_by + " " + sort_direction + limit)
        tableWidget.setModel(model)

        if delegate != None:
            # configure the personalized delegate from actions, if any
            action = self._actions.get(delegate)
            if action != None:
                tableWidget.setItemDelegate(ColorizedDelegate(tableWidget, actions=action))

        header = tableWidget.horizontalHeader()
        if header != None:
            header.sortIndicatorChanged.connect(self._cb_table_header_clicked)

            for _, col in enumerate(resize_cols):
                header.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)

        cur_idx = self.tabWidget.currentIndex()
        self._cfg.setSettings("{0}{1}".format(Config.STATS_VIEW_DETAILS_COL_STATE, cur_idx), header.saveState())
        return tableWidget

    def update_interception_status(self, enabled):
        self.startButton.setDown(enabled)
        self.startButton.setChecked(enabled)
        if enabled:
            self._update_status_label(running=True, text=self.FIREWALL_RUNNING)
        else:
            self._update_status_label(running=False, text=self.FIREWALL_DISABLED)

    def _needs_refresh(self):
        diff = datetime.datetime.now() - self._last_update
        if diff.seconds < self._ui_refresh_interval:
            return False

        return True

    # launched from a thread
    def update(self, is_local=True, stats=None, need_query_update=True):
        # lock mandatory when there're multiple clients
        with self._lock:
            if stats is not None:
                self._stats = stats
            # do not update any tab if the window is not visible
            if self.isVisible() and self.isMinimized() == False and self._needs_refresh():
                self._trigger.emit(is_local, need_query_update)
                self._last_update = datetime.datetime.now()

    def update_status(self):
        self.startButton.setDown(self.daemon_connected)
        self.startButton.setChecked(self.daemon_connected)
        self.startButton.setDisabled(not self.daemon_connected)
        if self.daemon_connected:
            self._update_status_label(running=True, text=self.FIREWALL_RUNNING)
        else:
            self._update_status_label(running=False, text=self.FIREWALL_STOPPED)
            self.statusLabel.setStyleSheet('color: red; margin: 5px')

    @QtCore.pyqtSlot(bool, bool)
    def _on_update_triggered(self, is_local, need_query_update=False):
        if self._stats is None:
            self.daemonVerLabel.setText("")
            self.uptimeLabel.setText("")
            self.rulesLabel.setText("")
            self.consLabel.setText("")
            self.droppedLabel.setText("")
        else:
            nodes = self._nodes.count()
            self.daemonVerLabel.setText(self._stats.daemon_version)
            if nodes <= 1:
                self.uptimeLabel.setText(str(datetime.timedelta(seconds=self._stats.uptime)))
                self.rulesLabel.setText("%s" % self._stats.rules)
                self.consLabel.setText("%s" % self._stats.connections)
                self.droppedLabel.setText("%s" % self._stats.dropped)
            else:
                self.uptimeLabel.setText("")
                self.rulesLabel.setText("")
                self.consLabel.setText("")
                self.droppedLabel.setText("")

            if need_query_update and not self._are_rows_selected():
                self._refresh_active_table()

    # prevent a click on the window's x
    # from quitting the whole application
    def closeEvent(self, e):
        self._save_settings()
        e.accept()
        self.hide()

    def hideEvent(self, e):
        self._save_settings()

    # https://gis.stackexchange.com/questions/86398/how-to-disable-the-escape-key-for-a-dialog
    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key.Key_Escape:
            modifiers = event.modifiers()
            if modifiers & QtCore.Qt.KeyboardModifier.ShiftModifier:
                self._clear_active_filters()
                self._reset_rule_focus_navigation()
                self._clear_navigation_history()
                return
            if self._pop_rule_focus_breadcrumb():
                return
            if self._pop_navigation_tab():
                return
            if self._maybe_exit_detail_view():
                return
            if self._clear_active_filters():
                return
            return
        super(StatsDialog, self).keyPressEvent(event)

    def setQuery(self, model, q):
        if self._context_menu_active == True or self.scrollbar_active == True:
            return
        with self._lock:
            try:
                model.query().clear()
                model.setQuery(q, self._db_sqlite)
                if model.lastError().isValid():
                    print("setQuery() error: ", model.lastError().text())

                self._update_rule_focus_indicator(model)
            except Exception as e:
                print(self._address, "setQuery() exception: ", e)
    def _clear_active_filters(self):
        """Clear text/rule filters when the user presses ESC."""
        cleared = False
        filter_widgets = []
        try:
            if getattr(self, "filterLine", None) is not None:
                filter_widgets.append(self.filterLine)
        except Exception:
            pass
        try:
            cur_idx = self.tabWidget.currentIndex()
            table_filter = self.TABLES.get(cur_idx, {}).get('filterLine')
            if table_filter and table_filter not in filter_widgets:
                filter_widgets.append(table_filter)
        except Exception:
            pass
        for widget in filter_widgets:
            try:
                if widget is not None and widget.text().strip():
                    widget.clear()
                    cleared = True
            except Exception:
                continue
        state = getattr(self, "_rules_filter_state", None)
        if state and state.get("rule_focus"):
            self._set_rules_filter(
                state.get("parent_row", -1),
                state.get("item_row", self.RULES_TREE_APPS),
                state.get("what", ""),
                state.get("what1", ""),
                state.get("what2", ""),
                state.get("action_filter"),
                None
            )
            cleared = True
        if cleared:
            self._update_rule_focus_indicator()
        return cleared
