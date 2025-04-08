"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WAZUH_SAMPLE_ALERT_PREFIX = exports.WAZUH_SAMPLE_ALERTS_INDEX_SHARDS = exports.WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS = exports.WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING = exports.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS = exports.WAZUH_ROLE_ADMINISTRATOR_ID = exports.WAZUH_QUEUE_CRON_FREQ = exports.WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME = exports.WAZUH_PLUGIN_PLATFORM_SETTING_TIME_FILTER = exports.WAZUH_PLUGIN_PLATFORM_SETTING_METAFIELDS = exports.WAZUH_PLUGIN_PLATFORM_SETTING_MAX_BUCKETS = exports.WAZUH_MONITORING_TEMPLATE_NAME = exports.WAZUH_MONITORING_PREFIX = exports.WAZUH_MONITORING_PATTERN = exports.WAZUH_MONITORING_DEFAULT_INDICES_SHARDS = exports.WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS = exports.WAZUH_MONITORING_DEFAULT_FREQUENCY = exports.WAZUH_MONITORING_DEFAULT_ENABLED = exports.WAZUH_MONITORING_DEFAULT_CRON_FREQ = exports.WAZUH_MONITORING_DEFAULT_CREATION = exports.WAZUH_MODULES_ID = exports.WAZUH_MENU_TOOLS_SECTIONS_ID = exports.WAZUH_MENU_SETTINGS_SECTIONS_ID = exports.WAZUH_MENU_SECURITY_SECTIONS_ID = exports.WAZUH_MENU_MANAGEMENT_SECTIONS_ID = exports.WAZUH_LINK_SLACK = exports.WAZUH_LINK_GOOGLE_GROUPS = exports.WAZUH_LINK_GITHUB = exports.WAZUH_INDEX_TYPE_VULNERABILITIES = exports.WAZUH_INDEX_TYPE_STATISTICS = exports.WAZUH_INDEX_TYPE_MONITORING = exports.WAZUH_INDEX_TYPE_ALERTS = exports.WAZUH_INDEXER_NAME = exports.WAZUH_ERROR_DAEMONS_NOT_READY = exports.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH = exports.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH = exports.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH = exports.WAZUH_DATA_CONFIG_REGISTRY_PATH = exports.WAZUH_DATA_CONFIG_DIRECTORY_PATH = exports.WAZUH_DATA_CONFIG_APP_PATH = exports.WAZUH_DATA_ABSOLUTE_PATH = exports.WAZUH_CORE_ENCRYPTION_PASSWORD = exports.WAZUH_CORE_CONFIGURATION_INSTANCE = exports.WAZUH_CORE_CONFIGURATION_CACHE_SECONDS = exports.WAZUH_CONFIGURATION_CACHE_TIME = exports.WAZUH_API_RESERVED_WUI_SECURITY_RULES = exports.WAZUH_API_RESERVED_ID_LOWER_THAN = exports.WAZUH_ALERTS_PREFIX = exports.WAZUH_ALERTS_PATTERN = exports.WAZUH_AGENTS_OS_TYPE = exports.UI_TOAST_COLOR = exports.UI_ORDER_AGENT_STATUS = exports.UI_LOGGER_LEVELS = exports.UI_LABEL_NAME_AGENT_STATUS = exports.UI_COLOR_STATUS = exports.UI_COLOR_AGENT_STATUS = exports.SettingCategory = exports.SEARCH_BAR_WQL_VALUE_SUGGESTIONS_DISPLAY_COUNT = exports.SEARCH_BAR_WQL_VALUE_SUGGESTIONS_COUNT = exports.SEARCH_BAR_DEBOUNCE_UPDATE_TIME = exports.REPORTS_PRIMARY_COLOR = exports.REPORTS_PAGE_HEADER_TEXT = exports.REPORTS_PAGE_FOOTER_TEXT = exports.REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH = exports.PLUGIN_VERSION_SHORT = exports.PLUGIN_VERSION = exports.PLUGIN_SETTINGS_CATEGORIES = exports.PLUGIN_SETTINGS = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_UPGRADE_PLATFORM = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_TROUBLESHOOTING = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_APP_CONFIGURATION = exports.PLUGIN_PLATFORM_URL_GUIDE_TITLE = exports.PLUGIN_PLATFORM_URL_GUIDE = exports.PLUGIN_PLATFORM_SETTING_NAME_TIME_FILTER = exports.PLUGIN_PLATFORM_SETTING_NAME_METAFIELDS = exports.PLUGIN_PLATFORM_SETTING_NAME_MAX_BUCKETS = exports.PLUGIN_PLATFORM_REQUEST_HEADERS = exports.PLUGIN_PLATFORM_NAME = exports.PLUGIN_PLATFORM_INSTALLATION_USER_GROUP = exports.PLUGIN_PLATFORM_INSTALLATION_USER = exports.PLUGIN_APP_NAME = exports.OSD_URL_STATE_STORAGE_ID = exports.NOT_TIME_FIELD_NAME_INDEX_PATTERN = exports.MODULE_SCA_CHECK_RESULT_LABEL = exports.HTTP_STATUS_CODES = exports.HEALTH_CHECK_REDIRECTION_TIME = exports.HEALTH_CHECK = exports.EpluginSettingType = exports.ELASTIC_NAME = exports.DOCUMENTATION_WEB_BASE_URL = exports.CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES = exports.AUTHORIZED_AGENTS = exports.ASSETS_PUBLIC_URL = exports.ASSETS_BASE_URL_PREFIX = exports.API_NAME_AGENT_STATUS = exports.AGENT_SYNCED_STATUS = exports.AGENT_STATUS_CODE = void 0;
exports.WAZUH_VULNERABILITIES_PATTERN = exports.WAZUH_STATISTICS_TEMPLATE_NAME = exports.WAZUH_STATISTICS_PATTERN = exports.WAZUH_STATISTICS_DEFAULT_STATUS = exports.WAZUH_STATISTICS_DEFAULT_PREFIX = exports.WAZUH_STATISTICS_DEFAULT_NAME = exports.WAZUH_STATISTICS_DEFAULT_INDICES_SHARDS = exports.WAZUH_STATISTICS_DEFAULT_INDICES_REPLICAS = exports.WAZUH_STATISTICS_DEFAULT_FREQUENCY = exports.WAZUH_STATISTICS_DEFAULT_CRON_FREQ = exports.WAZUH_STATISTICS_DEFAULT_CREATION = exports.WAZUH_SECURITY_PLUGIN_OPENSEARCH_DASHBOARDS_SECURITY = exports.WAZUH_SECURITY_PLUGINS = void 0;
var _path = _interopRequireDefault(require("path"));
var _package = require("../package.json");
var _settingsValidator = require("../common/services/settings-validator");
function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }
/*
 * Wazuh app - Wazuh Constants file
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

// import { validate as validateNodeCronInterval } from 'node-cron';

// Plugin
const PLUGIN_VERSION = exports.PLUGIN_VERSION = _package.version;
const PLUGIN_VERSION_SHORT = exports.PLUGIN_VERSION_SHORT = _package.version.split('.').splice(0, 2).join('.');

// Index patterns - Wazuh alerts
const WAZUH_INDEX_TYPE_ALERTS = exports.WAZUH_INDEX_TYPE_ALERTS = 'alerts';
const WAZUH_ALERTS_PREFIX = exports.WAZUH_ALERTS_PREFIX = 'wazuh-alerts-';
const WAZUH_ALERTS_PATTERN = exports.WAZUH_ALERTS_PATTERN = 'wazuh-alerts-*';

// Job - Wazuh monitoring
const WAZUH_INDEX_TYPE_MONITORING = exports.WAZUH_INDEX_TYPE_MONITORING = 'monitoring';
const WAZUH_MONITORING_PREFIX = exports.WAZUH_MONITORING_PREFIX = 'wazuh-monitoring-';
const WAZUH_MONITORING_PATTERN = exports.WAZUH_MONITORING_PATTERN = 'wazuh-monitoring-*';
const WAZUH_MONITORING_TEMPLATE_NAME = exports.WAZUH_MONITORING_TEMPLATE_NAME = 'wazuh-agent';
const WAZUH_MONITORING_DEFAULT_INDICES_SHARDS = exports.WAZUH_MONITORING_DEFAULT_INDICES_SHARDS = 1;
const WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS = exports.WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS = 0;
const WAZUH_MONITORING_DEFAULT_CREATION = exports.WAZUH_MONITORING_DEFAULT_CREATION = 'w';
const WAZUH_MONITORING_DEFAULT_ENABLED = exports.WAZUH_MONITORING_DEFAULT_ENABLED = true;
const WAZUH_MONITORING_DEFAULT_FREQUENCY = exports.WAZUH_MONITORING_DEFAULT_FREQUENCY = 900;
const WAZUH_MONITORING_DEFAULT_CRON_FREQ = exports.WAZUH_MONITORING_DEFAULT_CRON_FREQ = '0 * * * * *';

// Job - Wazuh statistics
const WAZUH_INDEX_TYPE_STATISTICS = exports.WAZUH_INDEX_TYPE_STATISTICS = 'statistics';
const WAZUH_STATISTICS_DEFAULT_PREFIX = exports.WAZUH_STATISTICS_DEFAULT_PREFIX = 'wazuh';
const WAZUH_STATISTICS_DEFAULT_NAME = exports.WAZUH_STATISTICS_DEFAULT_NAME = 'statistics';
const WAZUH_STATISTICS_PATTERN = exports.WAZUH_STATISTICS_PATTERN = `${WAZUH_STATISTICS_DEFAULT_PREFIX}-${WAZUH_STATISTICS_DEFAULT_NAME}-*`;
const WAZUH_STATISTICS_TEMPLATE_NAME = exports.WAZUH_STATISTICS_TEMPLATE_NAME = `${WAZUH_STATISTICS_DEFAULT_PREFIX}-${WAZUH_STATISTICS_DEFAULT_NAME}`;
const WAZUH_STATISTICS_DEFAULT_INDICES_SHARDS = exports.WAZUH_STATISTICS_DEFAULT_INDICES_SHARDS = 1;
const WAZUH_STATISTICS_DEFAULT_INDICES_REPLICAS = exports.WAZUH_STATISTICS_DEFAULT_INDICES_REPLICAS = 0;
const WAZUH_STATISTICS_DEFAULT_CREATION = exports.WAZUH_STATISTICS_DEFAULT_CREATION = 'w';
const WAZUH_STATISTICS_DEFAULT_STATUS = exports.WAZUH_STATISTICS_DEFAULT_STATUS = true;
const WAZUH_STATISTICS_DEFAULT_FREQUENCY = exports.WAZUH_STATISTICS_DEFAULT_FREQUENCY = 900;
const WAZUH_STATISTICS_DEFAULT_CRON_FREQ = exports.WAZUH_STATISTICS_DEFAULT_CRON_FREQ = '0 */5 * * * *';

// Wazuh vulnerabilities
const WAZUH_VULNERABILITIES_PATTERN = exports.WAZUH_VULNERABILITIES_PATTERN = 'wazuh-states-vulnerabilities-*';
const WAZUH_INDEX_TYPE_VULNERABILITIES = exports.WAZUH_INDEX_TYPE_VULNERABILITIES = 'vulnerabilities';

// Job - Wazuh initialize
const WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME = exports.WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME = 'wazuh-kibana';

// Sample data
const WAZUH_SAMPLE_ALERT_PREFIX = exports.WAZUH_SAMPLE_ALERT_PREFIX = 'wazuh-alerts-4.x-';
const WAZUH_SAMPLE_ALERTS_INDEX_SHARDS = exports.WAZUH_SAMPLE_ALERTS_INDEX_SHARDS = 1;
const WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS = exports.WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS = 0;
const WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY = 'security';
const WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING = 'auditing-policy-monitoring';
const WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION = 'threat-detection';
const WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS = exports.WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS = 3000;
const WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS = exports.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS = {
  [WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY]: [{
    syscheck: true
  }, {
    aws: true
  }, {
    office: true
  }, {
    gcp: true
  }, {
    authentication: true
  }, {
    ssh: true
  }, {
    apache: true,
    alerts: 2000
  }, {
    web: true
  }, {
    windows: {
      service_control_manager: true
    },
    alerts: 1000
  }, {
    github: true
  }],
  [WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING]: [{
    rootcheck: true
  }, {
    audit: true
  }, {
    openscap: true
  }, {
    ciscat: true
  }, {
    virustotal: true
  }, {
    yara: true
  }],
  [WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION]: [{
    vulnerabilities: true
  }, {
    osquery: true
  }, {
    docker: true
  }, {
    mitre: true
  }]
};

// Security
const WAZUH_SECURITY_PLUGIN_OPENSEARCH_DASHBOARDS_SECURITY = exports.WAZUH_SECURITY_PLUGIN_OPENSEARCH_DASHBOARDS_SECURITY = 'OpenSearch Dashboards Security';
const WAZUH_SECURITY_PLUGINS = exports.WAZUH_SECURITY_PLUGINS = [WAZUH_SECURITY_PLUGIN_OPENSEARCH_DASHBOARDS_SECURITY];

// App configuration
const WAZUH_CONFIGURATION_CACHE_TIME = exports.WAZUH_CONFIGURATION_CACHE_TIME = 10000; // time in ms;

// Reserved ids for Users/Role mapping
const WAZUH_API_RESERVED_ID_LOWER_THAN = exports.WAZUH_API_RESERVED_ID_LOWER_THAN = 100;
const WAZUH_API_RESERVED_WUI_SECURITY_RULES = exports.WAZUH_API_RESERVED_WUI_SECURITY_RULES = [1, 2];

// Wazuh data path
const WAZUH_DATA_PLUGIN_PLATFORM_BASE_PATH = 'data';
const WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH = exports.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH = _path.default.join(__dirname, '../../../', WAZUH_DATA_PLUGIN_PLATFORM_BASE_PATH);
const WAZUH_DATA_ABSOLUTE_PATH = exports.WAZUH_DATA_ABSOLUTE_PATH = _path.default.join(WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH, 'wazuh');

// Wazuh data path - config
const WAZUH_DATA_CONFIG_DIRECTORY_PATH = exports.WAZUH_DATA_CONFIG_DIRECTORY_PATH = _path.default.join(WAZUH_DATA_ABSOLUTE_PATH, 'config');
const WAZUH_DATA_CONFIG_REGISTRY_PATH = exports.WAZUH_DATA_CONFIG_REGISTRY_PATH = _path.default.join(WAZUH_DATA_CONFIG_DIRECTORY_PATH, 'wazuh-registry.json');
const WAZUH_DATA_CONFIG_APP_PATH = exports.WAZUH_DATA_CONFIG_APP_PATH = _path.default.join(WAZUH_DATA_CONFIG_DIRECTORY_PATH, 'wazuh.yml');

// Wazuh data path - downloads
const WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH = exports.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH = _path.default.join(WAZUH_DATA_ABSOLUTE_PATH, 'downloads');
const WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH = exports.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH = _path.default.join(WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH, 'reports');

// Queue
const WAZUH_QUEUE_CRON_FREQ = exports.WAZUH_QUEUE_CRON_FREQ = '*/15 * * * * *'; // Every 15 seconds

// Wazuh errors
const WAZUH_ERROR_DAEMONS_NOT_READY = exports.WAZUH_ERROR_DAEMONS_NOT_READY = 'ERROR3099';

// Agents
let WAZUH_AGENTS_OS_TYPE = exports.WAZUH_AGENTS_OS_TYPE = /*#__PURE__*/function (WAZUH_AGENTS_OS_TYPE) {
  WAZUH_AGENTS_OS_TYPE["WINDOWS"] = "windows";
  WAZUH_AGENTS_OS_TYPE["LINUX"] = "linux";
  WAZUH_AGENTS_OS_TYPE["SUNOS"] = "sunos";
  WAZUH_AGENTS_OS_TYPE["DARWIN"] = "darwin";
  WAZUH_AGENTS_OS_TYPE["OTHERS"] = "";
  return WAZUH_AGENTS_OS_TYPE;
}({});
let WAZUH_MODULES_ID = exports.WAZUH_MODULES_ID = /*#__PURE__*/function (WAZUH_MODULES_ID) {
  WAZUH_MODULES_ID["SECURITY_EVENTS"] = "general";
  WAZUH_MODULES_ID["INTEGRITY_MONITORING"] = "fim";
  WAZUH_MODULES_ID["AMAZON_WEB_SERVICES"] = "aws";
  WAZUH_MODULES_ID["OFFICE_365"] = "office";
  WAZUH_MODULES_ID["GOOGLE_CLOUD_PLATFORM"] = "gcp";
  WAZUH_MODULES_ID["POLICY_MONITORING"] = "pm";
  WAZUH_MODULES_ID["SECURITY_CONFIGURATION_ASSESSMENT"] = "sca";
  WAZUH_MODULES_ID["AUDITING"] = "audit";
  WAZUH_MODULES_ID["OPEN_SCAP"] = "oscap";
  WAZUH_MODULES_ID["VULNERABILITIES"] = "vuls";
  WAZUH_MODULES_ID["OSQUERY"] = "osquery";
  WAZUH_MODULES_ID["DOCKER"] = "docker";
  WAZUH_MODULES_ID["MITRE_ATTACK"] = "mitre";
  WAZUH_MODULES_ID["PCI_DSS"] = "pci";
  WAZUH_MODULES_ID["HIPAA"] = "hipaa";
  WAZUH_MODULES_ID["NIST_800_53"] = "nist";
  WAZUH_MODULES_ID["TSC"] = "tsc";
  WAZUH_MODULES_ID["CIS_CAT"] = "ciscat";
  WAZUH_MODULES_ID["VIRUSTOTAL"] = "virustotal";
  WAZUH_MODULES_ID["GDPR"] = "gdpr";
  WAZUH_MODULES_ID["GITHUB"] = "github";
  return WAZUH_MODULES_ID;
}({});
let WAZUH_MENU_MANAGEMENT_SECTIONS_ID = exports.WAZUH_MENU_MANAGEMENT_SECTIONS_ID = /*#__PURE__*/function (WAZUH_MENU_MANAGEMENT_SECTIONS_ID) {
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["MANAGEMENT"] = "management";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["ADMINISTRATION"] = "administration";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["RULESET"] = "ruleset";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["RULES"] = "rules";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["DECODERS"] = "decoders";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["CDB_LISTS"] = "lists";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["GROUPS"] = "groups";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["CONFIGURATION"] = "configuration";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["STATUS_AND_REPORTS"] = "statusReports";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["STATUS"] = "status";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["CLUSTER"] = "monitoring";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["LOGS"] = "logs";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["REPORTING"] = "reporting";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["STATISTICS"] = "statistics";
  return WAZUH_MENU_MANAGEMENT_SECTIONS_ID;
}({});
let WAZUH_MENU_TOOLS_SECTIONS_ID = exports.WAZUH_MENU_TOOLS_SECTIONS_ID = /*#__PURE__*/function (WAZUH_MENU_TOOLS_SECTIONS_ID) {
  WAZUH_MENU_TOOLS_SECTIONS_ID["API_CONSOLE"] = "devTools";
  WAZUH_MENU_TOOLS_SECTIONS_ID["RULESET_TEST"] = "logtest";
  return WAZUH_MENU_TOOLS_SECTIONS_ID;
}({});
let WAZUH_MENU_SECURITY_SECTIONS_ID = exports.WAZUH_MENU_SECURITY_SECTIONS_ID = /*#__PURE__*/function (WAZUH_MENU_SECURITY_SECTIONS_ID) {
  WAZUH_MENU_SECURITY_SECTIONS_ID["USERS"] = "users";
  WAZUH_MENU_SECURITY_SECTIONS_ID["ROLES"] = "roles";
  WAZUH_MENU_SECURITY_SECTIONS_ID["POLICIES"] = "policies";
  WAZUH_MENU_SECURITY_SECTIONS_ID["ROLES_MAPPING"] = "roleMapping";
  return WAZUH_MENU_SECURITY_SECTIONS_ID;
}({});
let WAZUH_MENU_SETTINGS_SECTIONS_ID = exports.WAZUH_MENU_SETTINGS_SECTIONS_ID = /*#__PURE__*/function (WAZUH_MENU_SETTINGS_SECTIONS_ID) {
  WAZUH_MENU_SETTINGS_SECTIONS_ID["SETTINGS"] = "settings";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["API_CONFIGURATION"] = "api";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["MODULES"] = "modules";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["SAMPLE_DATA"] = "sample_data";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["CONFIGURATION"] = "configuration";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["LOGS"] = "logs";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["MISCELLANEOUS"] = "miscellaneous";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["ABOUT"] = "about";
  return WAZUH_MENU_SETTINGS_SECTIONS_ID;
}({});
const AUTHORIZED_AGENTS = exports.AUTHORIZED_AGENTS = 'authorized-agents';

// Wazuh links
const WAZUH_LINK_GITHUB = exports.WAZUH_LINK_GITHUB = 'https://github.com/wazuh';
const WAZUH_LINK_GOOGLE_GROUPS = exports.WAZUH_LINK_GOOGLE_GROUPS = 'https://groups.google.com/forum/#!forum/wazuh';
const WAZUH_LINK_SLACK = exports.WAZUH_LINK_SLACK = 'https://wazuh.com/community/join-us-on-slack';
const HEALTH_CHECK = exports.HEALTH_CHECK = 'health-check';

// Health check
const HEALTH_CHECK_REDIRECTION_TIME = exports.HEALTH_CHECK_REDIRECTION_TIME = 300; //ms

// Plugin platform settings
// Default timeFilter set by the app
const WAZUH_PLUGIN_PLATFORM_SETTING_TIME_FILTER = exports.WAZUH_PLUGIN_PLATFORM_SETTING_TIME_FILTER = {
  from: 'now-24h',
  to: 'now'
};
const PLUGIN_PLATFORM_SETTING_NAME_TIME_FILTER = exports.PLUGIN_PLATFORM_SETTING_NAME_TIME_FILTER = 'timepicker:timeDefaults';

// Default maxBuckets set by the app
const WAZUH_PLUGIN_PLATFORM_SETTING_MAX_BUCKETS = exports.WAZUH_PLUGIN_PLATFORM_SETTING_MAX_BUCKETS = 200000;
const PLUGIN_PLATFORM_SETTING_NAME_MAX_BUCKETS = exports.PLUGIN_PLATFORM_SETTING_NAME_MAX_BUCKETS = 'timeline:max_buckets';

// Default metaFields set by the app
const WAZUH_PLUGIN_PLATFORM_SETTING_METAFIELDS = exports.WAZUH_PLUGIN_PLATFORM_SETTING_METAFIELDS = ['_source', '_index'];
const PLUGIN_PLATFORM_SETTING_NAME_METAFIELDS = exports.PLUGIN_PLATFORM_SETTING_NAME_METAFIELDS = 'metaFields';

// Logger
const UI_LOGGER_LEVELS = exports.UI_LOGGER_LEVELS = {
  WARNING: 'WARNING',
  INFO: 'INFO',
  ERROR: 'ERROR'
};
const UI_TOAST_COLOR = exports.UI_TOAST_COLOR = {
  SUCCESS: 'success',
  WARNING: 'warning',
  DANGER: 'danger'
};

// Assets
const ASSETS_BASE_URL_PREFIX = exports.ASSETS_BASE_URL_PREFIX = '/plugins/wazuh/assets/';
const ASSETS_PUBLIC_URL = exports.ASSETS_PUBLIC_URL = '/plugins/wazuh/public/assets/';

// Reports
const REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH = exports.REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH = 'images/logo_reports.png';
const REPORTS_PRIMARY_COLOR = exports.REPORTS_PRIMARY_COLOR = '#256BD1';
const REPORTS_PAGE_FOOTER_TEXT = exports.REPORTS_PAGE_FOOTER_TEXT = 'Copyright © Wazuh, Inc.';
const REPORTS_PAGE_HEADER_TEXT = exports.REPORTS_PAGE_HEADER_TEXT = 'info@wazuh.com\nhttps://wazuh.com';

// Plugin platform
const PLUGIN_PLATFORM_NAME = exports.PLUGIN_PLATFORM_NAME = 'dashboard';
const PLUGIN_PLATFORM_INSTALLATION_USER = exports.PLUGIN_PLATFORM_INSTALLATION_USER = 'wazuh-dashboard';
const PLUGIN_PLATFORM_INSTALLATION_USER_GROUP = exports.PLUGIN_PLATFORM_INSTALLATION_USER_GROUP = 'wazuh-dashboard';
const PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_UPGRADE_PLATFORM = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_UPGRADE_PLATFORM = 'upgrade-guide';
const PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_TROUBLESHOOTING = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_TROUBLESHOOTING = 'user-manual/wazuh-dashboard/troubleshooting.html';
const PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_APP_CONFIGURATION = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_APP_CONFIGURATION = 'user-manual/wazuh-dashboard/config-file.html';
const PLUGIN_PLATFORM_URL_GUIDE = exports.PLUGIN_PLATFORM_URL_GUIDE = 'https://opensearch.org/docs/2.10/about';
const PLUGIN_PLATFORM_URL_GUIDE_TITLE = exports.PLUGIN_PLATFORM_URL_GUIDE_TITLE = 'OpenSearch guide';
const PLUGIN_PLATFORM_REQUEST_HEADERS = exports.PLUGIN_PLATFORM_REQUEST_HEADERS = {
  'osd-xsrf': 'kibana'
};

// Plugin app
const PLUGIN_APP_NAME = exports.PLUGIN_APP_NAME = 'Dashboard';

// UI
const UI_COLOR_STATUS = exports.UI_COLOR_STATUS = {
  success: '#007871',
  danger: '#BD271E',
  warning: '#FEC514',
  disabled: '#646A77',
  info: '#6092C0',
  default: '#000000'
};
const API_NAME_AGENT_STATUS = exports.API_NAME_AGENT_STATUS = {
  ACTIVE: 'active',
  DISCONNECTED: 'disconnected',
  PENDING: 'pending',
  NEVER_CONNECTED: 'never_connected'
};
const UI_COLOR_AGENT_STATUS = exports.UI_COLOR_AGENT_STATUS = {
  [API_NAME_AGENT_STATUS.ACTIVE]: UI_COLOR_STATUS.success,
  [API_NAME_AGENT_STATUS.DISCONNECTED]: UI_COLOR_STATUS.danger,
  [API_NAME_AGENT_STATUS.PENDING]: UI_COLOR_STATUS.warning,
  [API_NAME_AGENT_STATUS.NEVER_CONNECTED]: UI_COLOR_STATUS.disabled,
  default: UI_COLOR_STATUS.default
};
const UI_LABEL_NAME_AGENT_STATUS = exports.UI_LABEL_NAME_AGENT_STATUS = {
  [API_NAME_AGENT_STATUS.ACTIVE]: 'Active',
  [API_NAME_AGENT_STATUS.DISCONNECTED]: 'Disconnected',
  [API_NAME_AGENT_STATUS.PENDING]: 'Pending',
  [API_NAME_AGENT_STATUS.NEVER_CONNECTED]: 'Never connected',
  default: 'Unknown'
};
const UI_ORDER_AGENT_STATUS = exports.UI_ORDER_AGENT_STATUS = [API_NAME_AGENT_STATUS.ACTIVE, API_NAME_AGENT_STATUS.DISCONNECTED, API_NAME_AGENT_STATUS.PENDING, API_NAME_AGENT_STATUS.NEVER_CONNECTED];
const AGENT_SYNCED_STATUS = exports.AGENT_SYNCED_STATUS = {
  SYNCED: 'synced',
  NOT_SYNCED: 'not synced'
};

// The status code can be seen here https://github.com/wazuh/wazuh/blob/686068a1f05d806b2e3b3d633a765320ae7ae114/src/wazuh_db/wdb.h#L55-L61

const AGENT_STATUS_CODE = exports.AGENT_STATUS_CODE = [{
  STATUS_CODE: 0,
  STATUS_DESCRIPTION: 'Agent is connected'
}, {
  STATUS_CODE: 1,
  STATUS_DESCRIPTION: 'Invalid agent version'
}, {
  STATUS_CODE: 2,
  STATUS_DESCRIPTION: 'Error retrieving version'
}, {
  STATUS_CODE: 3,
  STATUS_DESCRIPTION: 'Shutdown message received'
}, {
  STATUS_CODE: 4,
  STATUS_DESCRIPTION: 'Disconnected because no keepalive received'
}, {
  STATUS_CODE: 5,
  STATUS_DESCRIPTION: 'Connection reset by manager'
}];

// Documentation
const DOCUMENTATION_WEB_BASE_URL = exports.DOCUMENTATION_WEB_BASE_URL = 'https://documentation.wazuh.com';

// Default Elasticsearch user name context
const ELASTIC_NAME = exports.ELASTIC_NAME = 'elastic';

// Default Wazuh indexer name
const WAZUH_INDEXER_NAME = exports.WAZUH_INDEXER_NAME = 'indexer';

// Not timeFieldName on index pattern
const NOT_TIME_FIELD_NAME_INDEX_PATTERN = exports.NOT_TIME_FIELD_NAME_INDEX_PATTERN = 'not_time_field_name_index_pattern';

// Customization
const CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES = exports.CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES = 1048576;

// Plugin settings
let SettingCategory = exports.SettingCategory = /*#__PURE__*/function (SettingCategory) {
  SettingCategory[SettingCategory["GENERAL"] = 0] = "GENERAL";
  SettingCategory[SettingCategory["HEALTH_CHECK"] = 1] = "HEALTH_CHECK";
  SettingCategory[SettingCategory["MONITORING"] = 2] = "MONITORING";
  SettingCategory[SettingCategory["STATISTICS"] = 3] = "STATISTICS";
  SettingCategory[SettingCategory["VULNERABILITIES"] = 4] = "VULNERABILITIES";
  SettingCategory[SettingCategory["SECURITY"] = 5] = "SECURITY";
  SettingCategory[SettingCategory["CUSTOMIZATION"] = 6] = "CUSTOMIZATION";
  SettingCategory[SettingCategory["API_CONNECTION"] = 7] = "API_CONNECTION";
  return SettingCategory;
}({});
let EpluginSettingType = exports.EpluginSettingType = /*#__PURE__*/function (EpluginSettingType) {
  EpluginSettingType["text"] = "text";
  EpluginSettingType["textarea"] = "textarea";
  EpluginSettingType["switch"] = "switch";
  EpluginSettingType["number"] = "number";
  EpluginSettingType["editor"] = "editor";
  EpluginSettingType["select"] = "select";
  EpluginSettingType["filepicker"] = "filepicker";
  EpluginSettingType["password"] = "password";
  EpluginSettingType["arrayOf"] = "arrayOf";
  EpluginSettingType["custom"] = "custom";
  return EpluginSettingType;
}({});
const PLUGIN_SETTINGS_CATEGORIES = exports.PLUGIN_SETTINGS_CATEGORIES = {
  [SettingCategory.HEALTH_CHECK]: {
    title: 'Health check',
    description: "Checks will be executed by the app's Healthcheck.",
    renderOrder: SettingCategory.HEALTH_CHECK
  },
  [SettingCategory.GENERAL]: {
    title: 'General',
    description: 'Basic app settings related to alerts index pattern, hide the manager alerts in the dashboards, logs level and more.',
    renderOrder: SettingCategory.GENERAL
  },
  [SettingCategory.SECURITY]: {
    title: 'Security',
    description: 'Application security options such as unauthorized roles.',
    renderOrder: SettingCategory.SECURITY
  },
  [SettingCategory.MONITORING]: {
    title: 'Task:Monitoring',
    description: 'Options related to the agent status monitoring job and its storage in indexes.',
    renderOrder: SettingCategory.MONITORING
  },
  [SettingCategory.STATISTICS]: {
    title: 'Task:Statistics',
    description: 'Options related to the daemons manager monitoring job and their storage in indexes.',
    renderOrder: SettingCategory.STATISTICS
  },
  [SettingCategory.VULNERABILITIES]: {
    title: 'Vulnerabilities',
    description: 'Options related to the agent vulnerabilities monitoring job and its storage in indexes.',
    renderOrder: SettingCategory.VULNERABILITIES
  },
  [SettingCategory.CUSTOMIZATION]: {
    title: 'Custom branding',
    description: 'If you want to use custom branding elements such as logos, you can do so by editing the settings below.',
    documentationLink: 'user-manual/wazuh-dashboard/white-labeling.html',
    renderOrder: SettingCategory.CUSTOMIZATION
  },
  [SettingCategory.API_CONNECTION]: {
    title: 'API connections',
    description: 'Options related to the API connections.',
    renderOrder: SettingCategory.API_CONNECTION
  }
};
const PLUGIN_SETTINGS = exports.PLUGIN_SETTINGS = {
  'alerts.sample.prefix': {
    title: 'Sample alerts prefix',
    description: 'Define the index name prefix of sample alerts. It must match the template used by the index pattern to avoid unknown fields in dashboards.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_SAMPLE_ALERT_PREFIX,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    validateUIForm: function (value) {
      return this.validate(value);
    },
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#', '*'))
  },
  'checks.api': {
    title: 'API connection',
    description: 'Enable or disable the API health check when opening the app.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'checks.fields': {
    title: 'Known fields',
    description: 'Enable or disable the known fields health check when opening the app.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'checks.maxBuckets': {
    title: 'Set max buckets to 200000',
    description: 'Change the default value of the plugin platform max buckets configuration.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'checks.metaFields': {
    title: 'Remove meta fields',
    description: 'Change the default value of the plugin platform metaField configuration.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'checks.pattern': {
    title: 'Index pattern',
    description: 'Enable or disable the index pattern health check when opening the app.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'checks.setup': {
    title: 'API version',
    description: 'Enable or disable the setup health check when opening the app.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'checks.template': {
    title: 'Index template',
    description: 'Enable or disable the template health check when opening the app.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'checks.timeFilter': {
    title: 'Set time filter to 24h',
    description: 'Change the default value of the plugin platform timeFilter configuration.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'configuration.ui_api_editable': {
    title: 'Configuration UI editable',
    description: 'Enable or disable the ability to edit the configuration from UI or API endpoints. When disabled, this can only be edited from the configuration file, the related API endpoints are disabled, and the UI is inaccessible.',
    store: {
      file: {
        configurableManaged: false
      }
    },
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: false,
    requiresRestartingPluginPlatform: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'cron.prefix': {
    title: 'Cron prefix',
    description: 'Define the index prefix of predefined jobs.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_STATISTICS_DEFAULT_PREFIX,
    isConfigurableFromSettings: true,
    validateUIForm: function (value) {
      return this.validate(value);
    },
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#', '*'))
  },
  'cron.statistics.apis': {
    title: 'Includes APIs',
    description: 'Enter the ID of the hosts you want to save data from, leave this empty to run the task on every host.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.editor,
    defaultValue: [],
    isConfigurableFromSettings: true,
    options: {
      editor: {
        language: 'json'
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return JSON.stringify(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      try {
        return JSON.parse(value);
      } catch (error) {
        return value;
      }
    },
    validateUIForm: function (value) {
      return _settingsValidator.SettingsValidator.json(this.validate)(value);
    },
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.array(_settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces)))
  },
  'cron.statistics.index.creation': {
    title: 'Index creation',
    description: 'Define the interval in which a new index will be created.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.select,
    options: {
      select: [{
        text: 'Hourly',
        value: 'h'
      }, {
        text: 'Daily',
        value: 'd'
      }, {
        text: 'Weekly',
        value: 'w'
      }, {
        text: 'Monthly',
        value: 'm'
      }]
    },
    defaultValue: WAZUH_STATISTICS_DEFAULT_CREATION,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.literal(this.options.select.map(({
        value
      }) => value))(value);
    }
  },
  'cron.statistics.index.name': {
    title: 'Index name',
    description: 'Define the name of the index in which the documents will be saved.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_STATISTICS_DEFAULT_NAME,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    validateUIForm: function (value) {
      return this.validate(value);
    },
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#', '*'))
  },
  'cron.statistics.index.replicas': {
    title: 'Index replicas',
    description: 'Define the number of replicas to use for the statistics indices.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_STATISTICS_DEFAULT_INDICES_REPLICAS,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    options: {
      number: {
        min: 0,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validateUIForm: function (value) {
      return this.validate(this.uiFormTransformInputValueToConfigurationValue(value));
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    }
  },
  'cron.statistics.index.shards': {
    title: 'Index shards',
    description: 'Define the number of shards to use for the statistics indices.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_STATISTICS_DEFAULT_INDICES_SHARDS,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    options: {
      number: {
        min: 1,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validateUIForm: function (value) {
      return this.validate(this.uiFormTransformInputValueToConfigurationValue(value));
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    }
  },
  'cron.statistics.interval': {
    title: 'Interval',
    description: 'Define the frequency of task execution using cron schedule expressions.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_STATISTICS_DEFAULT_CRON_FREQ,
    isConfigurableFromSettings: true,
    requiresRestartingPluginPlatform: true
    // Workaround: this need to be defined in the frontend side and backend side because an optimization error in the frontend side related to some module can not be loaded.
    // validateUIForm: function (value) {
    // },
    // validate: function (value) {
    // },
  },

  'cron.statistics.status': {
    title: 'Status',
    description: 'Enable or disable the statistics tasks.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.switch,
    defaultValue: WAZUH_STATISTICS_DEFAULT_STATUS,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'customization.enabled': {
    title: 'Status',
    description: 'Enable or disable the customization.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    requiresReloadingBrowserTab: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'customization.logo.app': {
    title: 'App main logo',
    description: `This logo is used as loading indicator while the user is logging into Wazuh API.`,
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.filepicker,
    defaultValue: '',
    isConfigurableFromSettings: true,
    options: {
      file: {
        type: 'image',
        extensions: ['.jpeg', '.jpg', '.png', '.svg'],
        size: {
          maxBytes: CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES
        },
        recommended: {
          dimensions: {
            width: 300,
            height: 70,
            unit: 'px'
          }
        },
        store: {
          relativePathFileSystem: 'public/assets/custom/images',
          filename: 'customization.logo.app',
          resolveStaticURL: filename => `custom/images/${filename}?v=${Date.now()}`
          // ?v=${Date.now()} is used to force the browser to reload the image when a new file is uploaded
        }
      }
    },

    validateUIForm: function (value) {
      return _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.filePickerFileSize({
        ...this.options.file.size,
        meaningfulUnit: true
      }), _settingsValidator.SettingsValidator.filePickerSupportedExtensions(this.options.file.extensions))(value);
    }
  },
  'customization.logo.healthcheck': {
    title: 'Healthcheck logo',
    description: `This logo is displayed during the Healthcheck routine of the app.`,
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.filepicker,
    defaultValue: '',
    isConfigurableFromSettings: true,
    options: {
      file: {
        type: 'image',
        extensions: ['.jpeg', '.jpg', '.png', '.svg'],
        size: {
          maxBytes: CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES
        },
        recommended: {
          dimensions: {
            width: 300,
            height: 70,
            unit: 'px'
          }
        },
        store: {
          relativePathFileSystem: 'public/assets/custom/images',
          filename: 'customization.logo.healthcheck',
          resolveStaticURL: filename => `custom/images/${filename}?v=${Date.now()}`
          // ?v=${Date.now()} is used to force the browser to reload the image when a new file is uploaded
        }
      }
    },

    validateUIForm: function (value) {
      return _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.filePickerFileSize({
        ...this.options.file.size,
        meaningfulUnit: true
      }), _settingsValidator.SettingsValidator.filePickerSupportedExtensions(this.options.file.extensions))(value);
    }
  },
  'customization.logo.reports': {
    title: 'PDF reports logo',
    description: `This logo is used in the PDF reports generated by the app. It's placed at the top left corner of every page of the PDF.`,
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.filepicker,
    defaultValue: '',
    defaultValueIfNotSet: REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH,
    isConfigurableFromSettings: true,
    options: {
      file: {
        type: 'image',
        extensions: ['.jpeg', '.jpg', '.png'],
        size: {
          maxBytes: CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES
        },
        recommended: {
          dimensions: {
            width: 190,
            height: 40,
            unit: 'px'
          }
        },
        store: {
          relativePathFileSystem: 'public/assets/custom/images',
          filename: 'customization.logo.reports',
          resolveStaticURL: filename => `custom/images/${filename}`
        }
      }
    },
    validateUIForm: function (value) {
      return _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.filePickerFileSize({
        ...this.options.file.size,
        meaningfulUnit: true
      }), _settingsValidator.SettingsValidator.filePickerSupportedExtensions(this.options.file.extensions))(value);
    }
  },
  'customization.reports.footer': {
    title: 'Reports footer',
    description: 'Set the footer of the reports.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.textarea,
    defaultValue: '',
    defaultValueIfNotSet: REPORTS_PAGE_FOOTER_TEXT,
    isConfigurableFromSettings: true,
    options: {
      maxRows: 2,
      maxLength: 50
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: function (value) {
      var _this$options, _this$options2;
      return _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.multipleLinesString({
        maxRows: (_this$options = this.options) === null || _this$options === void 0 ? void 0 : _this$options.maxRows,
        maxLength: (_this$options2 = this.options) === null || _this$options2 === void 0 ? void 0 : _this$options2.maxLength
      }))(value);
    }
  },
  'customization.reports.header': {
    title: 'Reports header',
    description: 'Set the header of the reports.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.textarea,
    defaultValue: '',
    defaultValueIfNotSet: REPORTS_PAGE_HEADER_TEXT,
    isConfigurableFromSettings: true,
    options: {
      maxRows: 3,
      maxLength: 40
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: function (value) {
      var _this$options3, _this$options4;
      return _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.multipleLinesString({
        maxRows: (_this$options3 = this.options) === null || _this$options3 === void 0 ? void 0 : _this$options3.maxRows,
        maxLength: (_this$options4 = this.options) === null || _this$options4 === void 0 ? void 0 : _this$options4.maxLength
      }))(value);
    }
  },
  'enrollment.dns': {
    title: 'Enrollment DNS',
    description: 'Specifies the Wazuh registration server, used for the agent enrollment.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: '',
    isConfigurableFromSettings: true,
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.serverAddressHostnameFQDNIPv4IPv6)
  },
  'enrollment.password': {
    title: 'Enrollment password',
    description: 'Specifies the password used to authenticate during the agent enrollment.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: '',
    isConfigurableFromSettings: false,
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString)
  },
  hideManagerAlerts: {
    title: 'Hide manager alerts',
    description: 'Hide the alerts of the manager in every dashboard.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.switch,
    defaultValue: false,
    isConfigurableFromSettings: true,
    requiresReloadingBrowserTab: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  hosts: {
    title: 'Server hosts',
    description: 'Configure the API connections.',
    category: SettingCategory.API_CONNECTION,
    type: EpluginSettingType.arrayOf,
    defaultValue: [],
    store: {
      file: {
        configurableManaged: false,
        defaultBlock: `# The following configuration is the default structure to define a host.
#
# hosts:
#   # Host ID / name,
#   - env-1:
#       # Host URL
#       url: https://env-1.example
#       # Host / API port
#       port: 55000
#       # Host / API username
#       username: wazuh-wui
#       # Host / API password
#       password: wazuh-wui
#       # Use RBAC or not. If set to true, the username must be "wazuh-wui".
#       run_as: true
#   - env-2:
#       url: https://env-2.example
#       port: 55000
#       username: wazuh-wui
#       password: wazuh-wui
#       run_as: true

hosts:
  - default:
      url: https://localhost
      port: 55000
      username: wazuh-wui
      password: wazuh-wui
      run_as: false`,
        transformFrom: value => {
          return value.map(hostData => {
            var _Object$keys;
            const key = (_Object$keys = Object.keys(hostData)) === null || _Object$keys === void 0 ? void 0 : _Object$keys[0];
            return {
              ...hostData[key],
              id: key
            };
          });
        }
      }
    },
    options: {
      arrayOf: {
        id: {
          title: 'Identifier',
          description: 'Identifier of the API connection. This must be unique.',
          type: EpluginSettingType.text,
          defaultValue: 'default',
          isConfigurableFromSettings: true,
          validateUIForm: function (value) {
            return this.validate(value);
          },
          validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString)
        },
        url: {
          title: 'URL',
          description: 'Server URL address',
          type: EpluginSettingType.text,
          defaultValue: 'https://localhost',
          isConfigurableFromSettings: true,
          validateUIForm: function (value) {
            return this.validate(value);
          },
          validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString)
        },
        port: {
          title: 'Port',
          description: 'Port',
          type: EpluginSettingType.number,
          defaultValue: 55000,
          isConfigurableFromSettings: true,
          options: {
            number: {
              min: 0,
              max: 65535,
              integer: true
            }
          },
          uiFormTransformConfigurationValueToInputValue: function (value) {
            return String(value);
          },
          uiFormTransformInputValueToConfigurationValue: function (value) {
            return Number(value);
          },
          validateUIForm: function (value) {
            return this.validate(this.uiFormTransformInputValueToConfigurationValue(value));
          },
          validate: function (value) {
            return _settingsValidator.SettingsValidator.number(this.options.number)(value);
          }
        },
        username: {
          title: 'Username',
          description: 'Server API username',
          type: EpluginSettingType.text,
          defaultValue: 'wazuh-wui',
          isConfigurableFromSettings: true,
          validateUIForm: function (value) {
            return this.validate(value);
          },
          validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString)
        },
        password: {
          title: 'Password',
          description: "User's Password",
          type: EpluginSettingType.password,
          defaultValue: 'wazuh-wui',
          isConfigurableFromSettings: true,
          validateUIForm: function (value) {
            return this.validate(value);
          },
          validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString)
        },
        run_as: {
          title: 'Run as',
          description: 'Use the authentication context.',
          type: EpluginSettingType.switch,
          defaultValue: false,
          isConfigurableFromSettings: true,
          options: {
            switch: {
              values: {
                disabled: {
                  label: 'false',
                  value: false
                },
                enabled: {
                  label: 'true',
                  value: true
                }
              }
            }
          },
          uiFormTransformChangedInputValue: function (value) {
            return Boolean(value);
          },
          validateUIForm: function (value) {
            return this.validate(value);
          },
          validate: _settingsValidator.SettingsValidator.isBoolean
        }
      }
    },
    isConfigurableFromSettings: false,
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    }
    // TODO: add validation
    // validate: SettingsValidator.isBoolean,
    // validate: function (schema) {
    //   return schema.boolean();
    // },
  },

  'ip.ignore': {
    title: 'Index pattern ignore',
    description: 'Disable certain index pattern names from being available in index pattern selector.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.editor,
    defaultValue: [],
    isConfigurableFromSettings: true,
    options: {
      editor: {
        language: 'json'
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return JSON.stringify(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      try {
        return JSON.parse(value);
      } catch (error) {
        return value;
      }
    },
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validateUIForm: function (value) {
      return _settingsValidator.SettingsValidator.json(this.validate)(value);
    },
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.array(_settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noLiteralString('.', '..'), _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#'))))
  },
  'ip.selector': {
    title: 'IP selector',
    description: 'Define if the user is allowed to change the selected index pattern directly from the top menu bar.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'wazuh.updates.disabled': {
    title: 'Check updates',
    description: 'Define if the check updates service is disabled.',
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.switch,
    defaultValue: false,
    store: {
      file: {
        configurableManaged: true
      }
    },
    isConfigurableFromSettings: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  pattern: {
    title: 'Index pattern',
    store: {
      file: {
        configurableManaged: true
      }
    },
    description: "Default index pattern to use on the app. If there's no valid index pattern, the app will automatically create one with the name indicated in this option.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_ALERTS_PATTERN,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noLiteralString('.', '..'), _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#'))
  },
  timeout: {
    title: 'Request timeout',
    store: {
      file: {
        configurableManaged: true
      }
    },
    description: 'Maximum time, in milliseconds, the app will wait for an API response when making requests to it. It will be ignored if the value is set under 1500 milliseconds.',
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.number,
    defaultValue: 20000,
    isConfigurableFromSettings: true,
    options: {
      number: {
        min: 1500,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validateUIForm: function (value) {
      return this.validate(this.uiFormTransformInputValueToConfigurationValue(value));
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    }
  },
  'wazuh.monitoring.creation': {
    title: 'Index creation',
    description: 'Define the interval in which a new wazuh-monitoring index will be created.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.select,
    options: {
      select: [{
        text: 'Hourly',
        value: 'h'
      }, {
        text: 'Daily',
        value: 'd'
      }, {
        text: 'Weekly',
        value: 'w'
      }, {
        text: 'Monthly',
        value: 'm'
      }]
    },
    defaultValue: WAZUH_MONITORING_DEFAULT_CREATION,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.literal(this.options.select.map(({
        value
      }) => value))(value);
    }
  },
  'wazuh.monitoring.enabled': {
    title: 'Status',
    description: 'Enable or disable the wazuh-monitoring index creation and/or visualization.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.switch,
    defaultValue: WAZUH_MONITORING_DEFAULT_ENABLED,
    isConfigurableFromSettings: true,
    requiresRestartingPluginPlatform: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean
  },
  'wazuh.monitoring.frequency': {
    title: 'Frequency',
    description: 'Frequency, in seconds, of API requests to get the state of the agents and create a new document in the wazuh-monitoring index with this data.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_MONITORING_DEFAULT_FREQUENCY,
    isConfigurableFromSettings: true,
    requiresRestartingPluginPlatform: true,
    options: {
      number: {
        min: 60,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validateUIForm: function (value) {
      return this.validate(this.uiFormTransformInputValueToConfigurationValue(value));
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    }
  },
  'wazuh.monitoring.pattern': {
    title: 'Index pattern',
    description: 'Default index pattern to use for Wazuh monitoring.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_MONITORING_PATTERN,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noLiteralString('.', '..'), _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#'))
  },
  'wazuh.monitoring.replicas': {
    title: 'Index replicas',
    description: 'Define the number of replicas to use for the wazuh-monitoring-* indices.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    options: {
      number: {
        min: 0,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validateUIForm: function (value) {
      return this.validate(this.uiFormTransformInputValueToConfigurationValue(value));
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    }
  },
  'wazuh.monitoring.shards': {
    title: 'Index shards',
    description: 'Define the number of shards to use for the wazuh-monitoring-* indices.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_MONITORING_DEFAULT_INDICES_SHARDS,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: true,
    options: {
      number: {
        min: 1,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validateUIForm: function (value) {
      return this.validate(this.uiFormTransformInputValueToConfigurationValue(value));
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    }
  },
  'vulnerabilities.pattern': {
    title: 'Index pattern',
    description: 'Default index pattern to use for vulnerabilities.',
    store: {
      file: {
        configurableManaged: true
      }
    },
    category: SettingCategory.VULNERABILITIES,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_VULNERABILITIES_PATTERN,
    isConfigurableFromSettings: true,
    requiresRunningHealthCheck: false,
    validateUIForm: function (value) {
      return this.validate(value);
    },
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noLiteralString('.', '..'), _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#'))
  }
};
let HTTP_STATUS_CODES = exports.HTTP_STATUS_CODES = /*#__PURE__*/function (HTTP_STATUS_CODES) {
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["CONTINUE"] = 100] = "CONTINUE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["SWITCHING_PROTOCOLS"] = 101] = "SWITCHING_PROTOCOLS";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PROCESSING"] = 102] = "PROCESSING";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["OK"] = 200] = "OK";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["CREATED"] = 201] = "CREATED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["ACCEPTED"] = 202] = "ACCEPTED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NON_AUTHORITATIVE_INFORMATION"] = 203] = "NON_AUTHORITATIVE_INFORMATION";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NO_CONTENT"] = 204] = "NO_CONTENT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["RESET_CONTENT"] = 205] = "RESET_CONTENT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PARTIAL_CONTENT"] = 206] = "PARTIAL_CONTENT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MULTI_STATUS"] = 207] = "MULTI_STATUS";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MULTIPLE_CHOICES"] = 300] = "MULTIPLE_CHOICES";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MOVED_PERMANENTLY"] = 301] = "MOVED_PERMANENTLY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MOVED_TEMPORARILY"] = 302] = "MOVED_TEMPORARILY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["SEE_OTHER"] = 303] = "SEE_OTHER";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NOT_MODIFIED"] = 304] = "NOT_MODIFIED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["USE_PROXY"] = 305] = "USE_PROXY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["TEMPORARY_REDIRECT"] = 307] = "TEMPORARY_REDIRECT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PERMANENT_REDIRECT"] = 308] = "PERMANENT_REDIRECT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["BAD_REQUEST"] = 400] = "BAD_REQUEST";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["UNAUTHORIZED"] = 401] = "UNAUTHORIZED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PAYMENT_REQUIRED"] = 402] = "PAYMENT_REQUIRED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["FORBIDDEN"] = 403] = "FORBIDDEN";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NOT_FOUND"] = 404] = "NOT_FOUND";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["METHOD_NOT_ALLOWED"] = 405] = "METHOD_NOT_ALLOWED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NOT_ACCEPTABLE"] = 406] = "NOT_ACCEPTABLE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PROXY_AUTHENTICATION_REQUIRED"] = 407] = "PROXY_AUTHENTICATION_REQUIRED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUEST_TIMEOUT"] = 408] = "REQUEST_TIMEOUT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["CONFLICT"] = 409] = "CONFLICT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["GONE"] = 410] = "GONE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["LENGTH_REQUIRED"] = 411] = "LENGTH_REQUIRED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PRECONDITION_FAILED"] = 412] = "PRECONDITION_FAILED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUEST_TOO_LONG"] = 413] = "REQUEST_TOO_LONG";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUEST_URI_TOO_LONG"] = 414] = "REQUEST_URI_TOO_LONG";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["UNSUPPORTED_MEDIA_TYPE"] = 415] = "UNSUPPORTED_MEDIA_TYPE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUESTED_RANGE_NOT_SATISFIABLE"] = 416] = "REQUESTED_RANGE_NOT_SATISFIABLE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["EXPECTATION_FAILED"] = 417] = "EXPECTATION_FAILED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["IM_A_TEAPOT"] = 418] = "IM_A_TEAPOT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["INSUFFICIENT_SPACE_ON_RESOURCE"] = 419] = "INSUFFICIENT_SPACE_ON_RESOURCE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["METHOD_FAILURE"] = 420] = "METHOD_FAILURE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MISDIRECTED_REQUEST"] = 421] = "MISDIRECTED_REQUEST";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["UNPROCESSABLE_ENTITY"] = 422] = "UNPROCESSABLE_ENTITY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["LOCKED"] = 423] = "LOCKED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["FAILED_DEPENDENCY"] = 424] = "FAILED_DEPENDENCY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PRECONDITION_REQUIRED"] = 428] = "PRECONDITION_REQUIRED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["TOO_MANY_REQUESTS"] = 429] = "TOO_MANY_REQUESTS";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUEST_HEADER_FIELDS_TOO_LARGE"] = 431] = "REQUEST_HEADER_FIELDS_TOO_LARGE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["UNAVAILABLE_FOR_LEGAL_REASONS"] = 451] = "UNAVAILABLE_FOR_LEGAL_REASONS";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NOT_IMPLEMENTED"] = 501] = "NOT_IMPLEMENTED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["BAD_GATEWAY"] = 502] = "BAD_GATEWAY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["SERVICE_UNAVAILABLE"] = 503] = "SERVICE_UNAVAILABLE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["GATEWAY_TIMEOUT"] = 504] = "GATEWAY_TIMEOUT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["HTTP_VERSION_NOT_SUPPORTED"] = 505] = "HTTP_VERSION_NOT_SUPPORTED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["INSUFFICIENT_STORAGE"] = 507] = "INSUFFICIENT_STORAGE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NETWORK_AUTHENTICATION_REQUIRED"] = 511] = "NETWORK_AUTHENTICATION_REQUIRED";
  return HTTP_STATUS_CODES;
}({}); // Module Security configuration assessment
const MODULE_SCA_CHECK_RESULT_LABEL = exports.MODULE_SCA_CHECK_RESULT_LABEL = {
  passed: 'Passed',
  failed: 'Failed',
  'not applicable': 'Not applicable'
};

// Search bar

// This limits the results in the API request
const SEARCH_BAR_WQL_VALUE_SUGGESTIONS_COUNT = exports.SEARCH_BAR_WQL_VALUE_SUGGESTIONS_COUNT = 30;
// This limits the suggestions for the token of type value displayed in the search bar
const SEARCH_BAR_WQL_VALUE_SUGGESTIONS_DISPLAY_COUNT = exports.SEARCH_BAR_WQL_VALUE_SUGGESTIONS_DISPLAY_COUNT = 10;
/* Time in milliseconds to debounce the analysis of search bar. This mitigates some problems related
to changes running in parallel */
const SEARCH_BAR_DEBOUNCE_UPDATE_TIME = exports.SEARCH_BAR_DEBOUNCE_UPDATE_TIME = 400;

// Plugin settings
const WAZUH_CORE_ENCRYPTION_PASSWORD = exports.WAZUH_CORE_ENCRYPTION_PASSWORD = 'secretencryptionkey!';

// Configuration backend service
const WAZUH_CORE_CONFIGURATION_INSTANCE = exports.WAZUH_CORE_CONFIGURATION_INSTANCE = 'wazuh-dashboard';
const WAZUH_CORE_CONFIGURATION_CACHE_SECONDS = exports.WAZUH_CORE_CONFIGURATION_CACHE_SECONDS = 10;

// API connection permissions
const WAZUH_ROLE_ADMINISTRATOR_ID = exports.WAZUH_ROLE_ADMINISTRATOR_ID = 1;

// ID used to refer the createOsdUrlStateStorage state
const OSD_URL_STATE_STORAGE_ID = exports.OSD_URL_STATE_STORAGE_ID = 'state:storeInSessionStorage';
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJuYW1lcyI6WyJfcGF0aCIsIl9pbnRlcm9wUmVxdWlyZURlZmF1bHQiLCJyZXF1aXJlIiwiX3BhY2thZ2UiLCJfc2V0dGluZ3NWYWxpZGF0b3IiLCJvYmoiLCJfX2VzTW9kdWxlIiwiZGVmYXVsdCIsIlBMVUdJTl9WRVJTSU9OIiwiZXhwb3J0cyIsInZlcnNpb24iLCJQTFVHSU5fVkVSU0lPTl9TSE9SVCIsInNwbGl0Iiwic3BsaWNlIiwiam9pbiIsIldBWlVIX0lOREVYX1RZUEVfQUxFUlRTIiwiV0FaVUhfQUxFUlRTX1BSRUZJWCIsIldBWlVIX0FMRVJUU19QQVRURVJOIiwiV0FaVUhfSU5ERVhfVFlQRV9NT05JVE9SSU5HIiwiV0FaVUhfTU9OSVRPUklOR19QUkVGSVgiLCJXQVpVSF9NT05JVE9SSU5HX1BBVFRFUk4iLCJXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUUiLCJXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfSU5ESUNFU19TSEFSRFMiLCJXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfSU5ESUNFU19SRVBMSUNBUyIsIldBWlVIX01PTklUT1JJTkdfREVGQVVMVF9DUkVBVElPTiIsIldBWlVIX01PTklUT1JJTkdfREVGQVVMVF9FTkFCTEVEIiwiV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0ZSRVFVRU5DWSIsIldBWlVIX01PTklUT1JJTkdfREVGQVVMVF9DUk9OX0ZSRVEiLCJXQVpVSF9JTkRFWF9UWVBFX1NUQVRJU1RJQ1MiLCJXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfUFJFRklYIiwiV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX05BTUUiLCJXQVpVSF9TVEFUSVNUSUNTX1BBVFRFUk4iLCJXQVpVSF9TVEFUSVNUSUNTX1RFTVBMQVRFX05BTUUiLCJXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfSU5ESUNFU19TSEFSRFMiLCJXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfSU5ESUNFU19SRVBMSUNBUyIsIldBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9DUkVBVElPTiIsIldBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9TVEFUVVMiLCJXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfRlJFUVVFTkNZIiwiV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX0NST05fRlJFUSIsIldBWlVIX1ZVTE5FUkFCSUxJVElFU19QQVRURVJOIiwiV0FaVUhfSU5ERVhfVFlQRV9WVUxORVJBQklMSVRJRVMiLCJXQVpVSF9QTFVHSU5fUExBVEZPUk1fVEVNUExBVEVfTkFNRSIsIldBWlVIX1NBTVBMRV9BTEVSVF9QUkVGSVgiLCJXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1NIQVJEUyIsIldBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfUkVQTElDQVMiLCJXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JZX1NFQ1VSSVRZIiwiV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SWV9BVURJVElOR19QT0xJQ1lfTU9OSVRPUklORyIsIldBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUllfVEhSRUFUX0RFVEVDVElPTiIsIldBWlVIX1NBTVBMRV9BTEVSVFNfREVGQVVMVF9OVU1CRVJfQUxFUlRTIiwiV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SSUVTX1RZUEVfQUxFUlRTIiwic3lzY2hlY2siLCJhd3MiLCJvZmZpY2UiLCJnY3AiLCJhdXRoZW50aWNhdGlvbiIsInNzaCIsImFwYWNoZSIsImFsZXJ0cyIsIndlYiIsIndpbmRvd3MiLCJzZXJ2aWNlX2NvbnRyb2xfbWFuYWdlciIsImdpdGh1YiIsInJvb3RjaGVjayIsImF1ZGl0Iiwib3BlbnNjYXAiLCJjaXNjYXQiLCJ2aXJ1c3RvdGFsIiwieWFyYSIsInZ1bG5lcmFiaWxpdGllcyIsIm9zcXVlcnkiLCJkb2NrZXIiLCJtaXRyZSIsIldBWlVIX1NFQ1VSSVRZX1BMVUdJTl9PUEVOU0VBUkNIX0RBU0hCT0FSRFNfU0VDVVJJVFkiLCJXQVpVSF9TRUNVUklUWV9QTFVHSU5TIiwiV0FaVUhfQ09ORklHVVJBVElPTl9DQUNIRV9USU1FIiwiV0FaVUhfQVBJX1JFU0VSVkVEX0lEX0xPV0VSX1RIQU4iLCJXQVpVSF9BUElfUkVTRVJWRURfV1VJX1NFQ1VSSVRZX1JVTEVTIiwiV0FaVUhfREFUQV9QTFVHSU5fUExBVEZPUk1fQkFTRV9QQVRIIiwiV0FaVUhfREFUQV9QTFVHSU5fUExBVEZPUk1fQkFTRV9BQlNPTFVURV9QQVRIIiwicGF0aCIsIl9fZGlybmFtZSIsIldBWlVIX0RBVEFfQUJTT0xVVEVfUEFUSCIsIldBWlVIX0RBVEFfQ09ORklHX0RJUkVDVE9SWV9QQVRIIiwiV0FaVUhfREFUQV9DT05GSUdfUkVHSVNUUllfUEFUSCIsIldBWlVIX0RBVEFfQ09ORklHX0FQUF9QQVRIIiwiV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgiLCJXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRIIiwiV0FaVUhfUVVFVUVfQ1JPTl9GUkVRIiwiV0FaVUhfRVJST1JfREFFTU9OU19OT1RfUkVBRFkiLCJXQVpVSF9BR0VOVFNfT1NfVFlQRSIsIldBWlVIX01PRFVMRVNfSUQiLCJXQVpVSF9NRU5VX01BTkFHRU1FTlRfU0VDVElPTlNfSUQiLCJXQVpVSF9NRU5VX1RPT0xTX1NFQ1RJT05TX0lEIiwiV0FaVUhfTUVOVV9TRUNVUklUWV9TRUNUSU9OU19JRCIsIldBWlVIX01FTlVfU0VUVElOR1NfU0VDVElPTlNfSUQiLCJBVVRIT1JJWkVEX0FHRU5UUyIsIldBWlVIX0xJTktfR0lUSFVCIiwiV0FaVUhfTElOS19HT09HTEVfR1JPVVBTIiwiV0FaVUhfTElOS19TTEFDSyIsIkhFQUxUSF9DSEVDSyIsIkhFQUxUSF9DSEVDS19SRURJUkVDVElPTl9USU1FIiwiV0FaVUhfUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfVElNRV9GSUxURVIiLCJmcm9tIiwidG8iLCJQTFVHSU5fUExBVEZPUk1fU0VUVElOR19OQU1FX1RJTUVfRklMVEVSIiwiV0FaVUhfUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfTUFYX0JVQ0tFVFMiLCJQTFVHSU5fUExBVEZPUk1fU0VUVElOR19OQU1FX01BWF9CVUNLRVRTIiwiV0FaVUhfUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfTUVUQUZJRUxEUyIsIlBMVUdJTl9QTEFURk9STV9TRVRUSU5HX05BTUVfTUVUQUZJRUxEUyIsIlVJX0xPR0dFUl9MRVZFTFMiLCJXQVJOSU5HIiwiSU5GTyIsIkVSUk9SIiwiVUlfVE9BU1RfQ09MT1IiLCJTVUNDRVNTIiwiREFOR0VSIiwiQVNTRVRTX0JBU0VfVVJMX1BSRUZJWCIsIkFTU0VUU19QVUJMSUNfVVJMIiwiUkVQT1JUU19MT0dPX0lNQUdFX0FTU0VUU19SRUxBVElWRV9QQVRIIiwiUkVQT1JUU19QUklNQVJZX0NPTE9SIiwiUkVQT1JUU19QQUdFX0ZPT1RFUl9URVhUIiwiUkVQT1JUU19QQUdFX0hFQURFUl9URVhUIiwiUExVR0lOX1BMQVRGT1JNX05BTUUiLCJQTFVHSU5fUExBVEZPUk1fSU5TVEFMTEFUSU9OX1VTRVIiLCJQTFVHSU5fUExBVEZPUk1fSU5TVEFMTEFUSU9OX1VTRVJfR1JPVVAiLCJQTFVHSU5fUExBVEZPUk1fV0FaVUhfRE9DVU1FTlRBVElPTl9VUkxfUEFUSF9VUEdSQURFX1BMQVRGT1JNIiwiUExVR0lOX1BMQVRGT1JNX1dBWlVIX0RPQ1VNRU5UQVRJT05fVVJMX1BBVEhfVFJPVUJMRVNIT09USU5HIiwiUExVR0lOX1BMQVRGT1JNX1dBWlVIX0RPQ1VNRU5UQVRJT05fVVJMX1BBVEhfQVBQX0NPTkZJR1VSQVRJT04iLCJQTFVHSU5fUExBVEZPUk1fVVJMX0dVSURFIiwiUExVR0lOX1BMQVRGT1JNX1VSTF9HVUlERV9USVRMRSIsIlBMVUdJTl9QTEFURk9STV9SRVFVRVNUX0hFQURFUlMiLCJQTFVHSU5fQVBQX05BTUUiLCJVSV9DT0xPUl9TVEFUVVMiLCJzdWNjZXNzIiwiZGFuZ2VyIiwid2FybmluZyIsImRpc2FibGVkIiwiaW5mbyIsIkFQSV9OQU1FX0FHRU5UX1NUQVRVUyIsIkFDVElWRSIsIkRJU0NPTk5FQ1RFRCIsIlBFTkRJTkciLCJORVZFUl9DT05ORUNURUQiLCJVSV9DT0xPUl9BR0VOVF9TVEFUVVMiLCJVSV9MQUJFTF9OQU1FX0FHRU5UX1NUQVRVUyIsIlVJX09SREVSX0FHRU5UX1NUQVRVUyIsIkFHRU5UX1NZTkNFRF9TVEFUVVMiLCJTWU5DRUQiLCJOT1RfU1lOQ0VEIiwiQUdFTlRfU1RBVFVTX0NPREUiLCJTVEFUVVNfQ09ERSIsIlNUQVRVU19ERVNDUklQVElPTiIsIkRPQ1VNRU5UQVRJT05fV0VCX0JBU0VfVVJMIiwiRUxBU1RJQ19OQU1FIiwiV0FaVUhfSU5ERVhFUl9OQU1FIiwiTk9UX1RJTUVfRklFTERfTkFNRV9JTkRFWF9QQVRURVJOIiwiQ1VTVE9NSVpBVElPTl9FTkRQT0lOVF9QQVlMT0FEX1VQTE9BRF9DVVNUT01fRklMRV9NQVhJTVVNX0JZVEVTIiwiU2V0dGluZ0NhdGVnb3J5IiwiRXBsdWdpblNldHRpbmdUeXBlIiwiUExVR0lOX1NFVFRJTkdTX0NBVEVHT1JJRVMiLCJ0aXRsZSIsImRlc2NyaXB0aW9uIiwicmVuZGVyT3JkZXIiLCJHRU5FUkFMIiwiU0VDVVJJVFkiLCJNT05JVE9SSU5HIiwiU1RBVElTVElDUyIsIlZVTE5FUkFCSUxJVElFUyIsIkNVU1RPTUlaQVRJT04iLCJkb2N1bWVudGF0aW9uTGluayIsIkFQSV9DT05ORUNUSU9OIiwiUExVR0lOX1NFVFRJTkdTIiwic3RvcmUiLCJmaWxlIiwiY29uZmlndXJhYmxlTWFuYWdlZCIsImNhdGVnb3J5IiwidHlwZSIsInRleHQiLCJkZWZhdWx0VmFsdWUiLCJpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5ncyIsInJlcXVpcmVzUnVubmluZ0hlYWx0aENoZWNrIiwidmFsaWRhdGVVSUZvcm0iLCJ2YWx1ZSIsInZhbGlkYXRlIiwiU2V0dGluZ3NWYWxpZGF0b3IiLCJjb21wb3NlIiwiaXNTdHJpbmciLCJpc05vdEVtcHR5U3RyaW5nIiwiaGFzTm9TcGFjZXMiLCJub1N0YXJ0c1dpdGhTdHJpbmciLCJoYXNOb3RJbnZhbGlkQ2hhcmFjdGVycyIsInN3aXRjaCIsIm9wdGlvbnMiLCJ2YWx1ZXMiLCJsYWJlbCIsImVuYWJsZWQiLCJ1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZSIsIkJvb2xlYW4iLCJpc0Jvb2xlYW4iLCJyZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybSIsImVkaXRvciIsImxhbmd1YWdlIiwidWlGb3JtVHJhbnNmb3JtQ29uZmlndXJhdGlvblZhbHVlVG9JbnB1dFZhbHVlIiwiSlNPTiIsInN0cmluZ2lmeSIsInVpRm9ybVRyYW5zZm9ybUlucHV0VmFsdWVUb0NvbmZpZ3VyYXRpb25WYWx1ZSIsInBhcnNlIiwiZXJyb3IiLCJqc29uIiwiYXJyYXkiLCJzZWxlY3QiLCJsaXRlcmFsIiwibWFwIiwibnVtYmVyIiwibWluIiwiaW50ZWdlciIsIlN0cmluZyIsIk51bWJlciIsInJlcXVpcmVzUmVsb2FkaW5nQnJvd3NlclRhYiIsImZpbGVwaWNrZXIiLCJleHRlbnNpb25zIiwic2l6ZSIsIm1heEJ5dGVzIiwicmVjb21tZW5kZWQiLCJkaW1lbnNpb25zIiwid2lkdGgiLCJoZWlnaHQiLCJ1bml0IiwicmVsYXRpdmVQYXRoRmlsZVN5c3RlbSIsImZpbGVuYW1lIiwicmVzb2x2ZVN0YXRpY1VSTCIsIkRhdGUiLCJub3ciLCJmaWxlUGlja2VyRmlsZVNpemUiLCJtZWFuaW5nZnVsVW5pdCIsImZpbGVQaWNrZXJTdXBwb3J0ZWRFeHRlbnNpb25zIiwiZGVmYXVsdFZhbHVlSWZOb3RTZXQiLCJ0ZXh0YXJlYSIsIm1heFJvd3MiLCJtYXhMZW5ndGgiLCJfdGhpcyRvcHRpb25zIiwiX3RoaXMkb3B0aW9uczIiLCJtdWx0aXBsZUxpbmVzU3RyaW5nIiwiX3RoaXMkb3B0aW9uczMiLCJfdGhpcyRvcHRpb25zNCIsInNlcnZlckFkZHJlc3NIb3N0bmFtZUZRRE5JUHY0SVB2NiIsImhpZGVNYW5hZ2VyQWxlcnRzIiwiaG9zdHMiLCJhcnJheU9mIiwiZGVmYXVsdEJsb2NrIiwidHJhbnNmb3JtRnJvbSIsImhvc3REYXRhIiwiX09iamVjdCRrZXlzIiwia2V5IiwiT2JqZWN0Iiwia2V5cyIsImlkIiwidXJsIiwicG9ydCIsIm1heCIsInVzZXJuYW1lIiwicGFzc3dvcmQiLCJydW5fYXMiLCJub0xpdGVyYWxTdHJpbmciLCJwYXR0ZXJuIiwidGltZW91dCIsIkhUVFBfU1RBVFVTX0NPREVTIiwiTU9EVUxFX1NDQV9DSEVDS19SRVNVTFRfTEFCRUwiLCJwYXNzZWQiLCJmYWlsZWQiLCJTRUFSQ0hfQkFSX1dRTF9WQUxVRV9TVUdHRVNUSU9OU19DT1VOVCIsIlNFQVJDSF9CQVJfV1FMX1ZBTFVFX1NVR0dFU1RJT05TX0RJU1BMQVlfQ09VTlQiLCJTRUFSQ0hfQkFSX0RFQk9VTkNFX1VQREFURV9USU1FIiwiV0FaVUhfQ09SRV9FTkNSWVBUSU9OX1BBU1NXT1JEIiwiV0FaVUhfQ09SRV9DT05GSUdVUkFUSU9OX0lOU1RBTkNFIiwiV0FaVUhfQ09SRV9DT05GSUdVUkFUSU9OX0NBQ0hFX1NFQ09ORFMiLCJXQVpVSF9ST0xFX0FETUlOSVNUUkFUT1JfSUQiLCJPU0RfVVJMX1NUQVRFX1NUT1JBR0VfSUQiXSwic291cmNlcyI6WyJjb25zdGFudHMudHMiXSwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIFdhenVoIENvbnN0YW50cyBmaWxlXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IHBhdGggZnJvbSAncGF0aCc7XG5pbXBvcnQgeyB2ZXJzaW9uIH0gZnJvbSAnLi4vcGFja2FnZS5qc29uJztcbi8vIGltcG9ydCB7IHZhbGlkYXRlIGFzIHZhbGlkYXRlTm9kZUNyb25JbnRlcnZhbCB9IGZyb20gJ25vZGUtY3Jvbic7XG5pbXBvcnQgeyBTZXR0aW5nc1ZhbGlkYXRvciB9IGZyb20gJy4uL2NvbW1vbi9zZXJ2aWNlcy9zZXR0aW5ncy12YWxpZGF0b3InO1xuXG4vLyBQbHVnaW5cbmV4cG9ydCBjb25zdCBQTFVHSU5fVkVSU0lPTiA9IHZlcnNpb247XG5leHBvcnQgY29uc3QgUExVR0lOX1ZFUlNJT05fU0hPUlQgPSB2ZXJzaW9uLnNwbGl0KCcuJykuc3BsaWNlKDAsIDIpLmpvaW4oJy4nKTtcblxuLy8gSW5kZXggcGF0dGVybnMgLSBXYXp1aCBhbGVydHNcbmV4cG9ydCBjb25zdCBXQVpVSF9JTkRFWF9UWVBFX0FMRVJUUyA9ICdhbGVydHMnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0FMRVJUU19QUkVGSVggPSAnd2F6dWgtYWxlcnRzLSc7XG5leHBvcnQgY29uc3QgV0FaVUhfQUxFUlRTX1BBVFRFUk4gPSAnd2F6dWgtYWxlcnRzLSonO1xuXG4vLyBKb2IgLSBXYXp1aCBtb25pdG9yaW5nXG5leHBvcnQgY29uc3QgV0FaVUhfSU5ERVhfVFlQRV9NT05JVE9SSU5HID0gJ21vbml0b3JpbmcnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX01PTklUT1JJTkdfUFJFRklYID0gJ3dhenVoLW1vbml0b3JpbmctJztcbmV4cG9ydCBjb25zdCBXQVpVSF9NT05JVE9SSU5HX1BBVFRFUk4gPSAnd2F6dWgtbW9uaXRvcmluZy0qJztcbmV4cG9ydCBjb25zdCBXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUUgPSAnd2F6dWgtYWdlbnQnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9JTkRJQ0VTX1NIQVJEUyA9IDE7XG5leHBvcnQgY29uc3QgV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0lORElDRVNfUkVQTElDQVMgPSAwO1xuZXhwb3J0IGNvbnN0IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9DUkVBVElPTiA9ICd3JztcbmV4cG9ydCBjb25zdCBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfRU5BQkxFRCA9IHRydWU7XG5leHBvcnQgY29uc3QgV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0ZSRVFVRU5DWSA9IDkwMDtcbmV4cG9ydCBjb25zdCBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfQ1JPTl9GUkVRID0gJzAgKiAqICogKiAqJztcblxuLy8gSm9iIC0gV2F6dWggc3RhdGlzdGljc1xuZXhwb3J0IGNvbnN0IFdBWlVIX0lOREVYX1RZUEVfU1RBVElTVElDUyA9ICdzdGF0aXN0aWNzJztcbmV4cG9ydCBjb25zdCBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfUFJFRklYID0gJ3dhenVoJztcbmV4cG9ydCBjb25zdCBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfTkFNRSA9ICdzdGF0aXN0aWNzJztcbmV4cG9ydCBjb25zdCBXQVpVSF9TVEFUSVNUSUNTX1BBVFRFUk4gPSBgJHtXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfUFJFRklYfS0ke1dBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9OQU1FfS0qYDtcbmV4cG9ydCBjb25zdCBXQVpVSF9TVEFUSVNUSUNTX1RFTVBMQVRFX05BTUUgPSBgJHtXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfUFJFRklYfS0ke1dBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9OQU1FfWA7XG5leHBvcnQgY29uc3QgV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX0lORElDRVNfU0hBUkRTID0gMTtcbmV4cG9ydCBjb25zdCBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfSU5ESUNFU19SRVBMSUNBUyA9IDA7XG5leHBvcnQgY29uc3QgV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX0NSRUFUSU9OID0gJ3cnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9TVEFUVVMgPSB0cnVlO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9GUkVRVUVOQ1kgPSA5MDA7XG5leHBvcnQgY29uc3QgV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX0NST05fRlJFUSA9ICcwICovNSAqICogKiAqJztcblxuLy8gV2F6dWggdnVsbmVyYWJpbGl0aWVzXG5leHBvcnQgY29uc3QgV0FaVUhfVlVMTkVSQUJJTElUSUVTX1BBVFRFUk4gPSAnd2F6dWgtc3RhdGVzLXZ1bG5lcmFiaWxpdGllcy0qJztcbmV4cG9ydCBjb25zdCBXQVpVSF9JTkRFWF9UWVBFX1ZVTE5FUkFCSUxJVElFUyA9ICd2dWxuZXJhYmlsaXRpZXMnO1xuXG4vLyBKb2IgLSBXYXp1aCBpbml0aWFsaXplXG5leHBvcnQgY29uc3QgV0FaVUhfUExVR0lOX1BMQVRGT1JNX1RFTVBMQVRFX05BTUUgPSAnd2F6dWgta2liYW5hJztcblxuLy8gU2FtcGxlIGRhdGFcbmV4cG9ydCBjb25zdCBXQVpVSF9TQU1QTEVfQUxFUlRfUFJFRklYID0gJ3dhenVoLWFsZXJ0cy00LngtJztcbmV4cG9ydCBjb25zdCBXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1NIQVJEUyA9IDE7XG5leHBvcnQgY29uc3QgV0FaVUhfU0FNUExFX0FMRVJUU19JTkRFWF9SRVBMSUNBUyA9IDA7XG5leHBvcnQgY29uc3QgV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SWV9TRUNVUklUWSA9ICdzZWN1cml0eSc7XG5leHBvcnQgY29uc3QgV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SWV9BVURJVElOR19QT0xJQ1lfTU9OSVRPUklORyA9XG4gICdhdWRpdGluZy1wb2xpY3ktbW9uaXRvcmluZyc7XG5leHBvcnQgY29uc3QgV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SWV9USFJFQVRfREVURUNUSU9OID0gJ3RocmVhdC1kZXRlY3Rpb24nO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1NBTVBMRV9BTEVSVFNfREVGQVVMVF9OVU1CRVJfQUxFUlRTID0gMzAwMDtcbmV4cG9ydCBjb25zdCBXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JJRVNfVFlQRV9BTEVSVFMgPSB7XG4gIFtXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JZX1NFQ1VSSVRZXTogW1xuICAgIHsgc3lzY2hlY2s6IHRydWUgfSxcbiAgICB7IGF3czogdHJ1ZSB9LFxuICAgIHsgb2ZmaWNlOiB0cnVlIH0sXG4gICAgeyBnY3A6IHRydWUgfSxcbiAgICB7IGF1dGhlbnRpY2F0aW9uOiB0cnVlIH0sXG4gICAgeyBzc2g6IHRydWUgfSxcbiAgICB7IGFwYWNoZTogdHJ1ZSwgYWxlcnRzOiAyMDAwIH0sXG4gICAgeyB3ZWI6IHRydWUgfSxcbiAgICB7IHdpbmRvd3M6IHsgc2VydmljZV9jb250cm9sX21hbmFnZXI6IHRydWUgfSwgYWxlcnRzOiAxMDAwIH0sXG4gICAgeyBnaXRodWI6IHRydWUgfSxcbiAgXSxcbiAgW1dBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUllfQVVESVRJTkdfUE9MSUNZX01PTklUT1JJTkddOiBbXG4gICAgeyByb290Y2hlY2s6IHRydWUgfSxcbiAgICB7IGF1ZGl0OiB0cnVlIH0sXG4gICAgeyBvcGVuc2NhcDogdHJ1ZSB9LFxuICAgIHsgY2lzY2F0OiB0cnVlIH0sXG4gICAgeyB2aXJ1c3RvdGFsOiB0cnVlIH0sXG4gICAgeyB5YXJhOiB0cnVlIH0sXG4gIF0sXG4gIFtXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JZX1RIUkVBVF9ERVRFQ1RJT05dOiBbXG4gICAgeyB2dWxuZXJhYmlsaXRpZXM6IHRydWUgfSxcbiAgICB7IG9zcXVlcnk6IHRydWUgfSxcbiAgICB7IGRvY2tlcjogdHJ1ZSB9LFxuICAgIHsgbWl0cmU6IHRydWUgfSxcbiAgXSxcbn07XG5cbi8vIFNlY3VyaXR5XG5leHBvcnQgY29uc3QgV0FaVUhfU0VDVVJJVFlfUExVR0lOX09QRU5TRUFSQ0hfREFTSEJPQVJEU19TRUNVUklUWSA9XG4gICdPcGVuU2VhcmNoIERhc2hib2FyZHMgU2VjdXJpdHknO1xuXG5leHBvcnQgY29uc3QgV0FaVUhfU0VDVVJJVFlfUExVR0lOUyA9IFtcbiAgV0FaVUhfU0VDVVJJVFlfUExVR0lOX09QRU5TRUFSQ0hfREFTSEJPQVJEU19TRUNVUklUWSxcbl07XG5cbi8vIEFwcCBjb25maWd1cmF0aW9uXG5leHBvcnQgY29uc3QgV0FaVUhfQ09ORklHVVJBVElPTl9DQUNIRV9USU1FID0gMTAwMDA7IC8vIHRpbWUgaW4gbXM7XG5cbi8vIFJlc2VydmVkIGlkcyBmb3IgVXNlcnMvUm9sZSBtYXBwaW5nXG5leHBvcnQgY29uc3QgV0FaVUhfQVBJX1JFU0VSVkVEX0lEX0xPV0VSX1RIQU4gPSAxMDA7XG5leHBvcnQgY29uc3QgV0FaVUhfQVBJX1JFU0VSVkVEX1dVSV9TRUNVUklUWV9SVUxFUyA9IFsxLCAyXTtcblxuLy8gV2F6dWggZGF0YSBwYXRoXG5jb25zdCBXQVpVSF9EQVRBX1BMVUdJTl9QTEFURk9STV9CQVNFX1BBVEggPSAnZGF0YSc7XG5leHBvcnQgY29uc3QgV0FaVUhfREFUQV9QTFVHSU5fUExBVEZPUk1fQkFTRV9BQlNPTFVURV9QQVRIID0gcGF0aC5qb2luKFxuICBfX2Rpcm5hbWUsXG4gICcuLi8uLi8uLi8nLFxuICBXQVpVSF9EQVRBX1BMVUdJTl9QTEFURk9STV9CQVNFX1BBVEgsXG4pO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfQUJTT0xVVEVfUEFUSCA9IHBhdGguam9pbihcbiAgV0FaVUhfREFUQV9QTFVHSU5fUExBVEZPUk1fQkFTRV9BQlNPTFVURV9QQVRILFxuICAnd2F6dWgnLFxuKTtcblxuLy8gV2F6dWggZGF0YSBwYXRoIC0gY29uZmlnXG5leHBvcnQgY29uc3QgV0FaVUhfREFUQV9DT05GSUdfRElSRUNUT1JZX1BBVEggPSBwYXRoLmpvaW4oXG4gIFdBWlVIX0RBVEFfQUJTT0xVVEVfUEFUSCxcbiAgJ2NvbmZpZycsXG4pO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfQ09ORklHX1JFR0lTVFJZX1BBVEggPSBwYXRoLmpvaW4oXG4gIFdBWlVIX0RBVEFfQ09ORklHX0RJUkVDVE9SWV9QQVRILFxuICAnd2F6dWgtcmVnaXN0cnkuanNvbicsXG4pO1xuXG5leHBvcnQgY29uc3QgV0FaVUhfREFUQV9DT05GSUdfQVBQX1BBVEggPSBwYXRoLmpvaW4oXG4gIFdBWlVIX0RBVEFfQ09ORklHX0RJUkVDVE9SWV9QQVRILFxuICAnd2F6dWgueW1sJyxcbik7XG5cbi8vIFdhenVoIGRhdGEgcGF0aCAtIGRvd25sb2Fkc1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRIID0gcGF0aC5qb2luKFxuICBXQVpVSF9EQVRBX0FCU09MVVRFX1BBVEgsXG4gICdkb3dubG9hZHMnLFxuKTtcbmV4cG9ydCBjb25zdCBXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRIID0gcGF0aC5qb2luKFxuICBXQVpVSF9EQVRBX0RPV05MT0FEU19ESVJFQ1RPUllfUEFUSCxcbiAgJ3JlcG9ydHMnLFxuKTtcblxuLy8gUXVldWVcbmV4cG9ydCBjb25zdCBXQVpVSF9RVUVVRV9DUk9OX0ZSRVEgPSAnKi8xNSAqICogKiAqIConOyAvLyBFdmVyeSAxNSBzZWNvbmRzXG5cbi8vIFdhenVoIGVycm9yc1xuZXhwb3J0IGNvbnN0IFdBWlVIX0VSUk9SX0RBRU1PTlNfTk9UX1JFQURZID0gJ0VSUk9SMzA5OSc7XG5cbi8vIEFnZW50c1xuZXhwb3J0IGVudW0gV0FaVUhfQUdFTlRTX09TX1RZUEUge1xuICBXSU5ET1dTID0gJ3dpbmRvd3MnLFxuICBMSU5VWCA9ICdsaW51eCcsXG4gIFNVTk9TID0gJ3N1bm9zJyxcbiAgREFSV0lOID0gJ2RhcndpbicsXG4gIE9USEVSUyA9ICcnLFxufVxuXG5leHBvcnQgZW51bSBXQVpVSF9NT0RVTEVTX0lEIHtcbiAgU0VDVVJJVFlfRVZFTlRTID0gJ2dlbmVyYWwnLFxuICBJTlRFR1JJVFlfTU9OSVRPUklORyA9ICdmaW0nLFxuICBBTUFaT05fV0VCX1NFUlZJQ0VTID0gJ2F3cycsXG4gIE9GRklDRV8zNjUgPSAnb2ZmaWNlJyxcbiAgR09PR0xFX0NMT1VEX1BMQVRGT1JNID0gJ2djcCcsXG4gIFBPTElDWV9NT05JVE9SSU5HID0gJ3BtJyxcbiAgU0VDVVJJVFlfQ09ORklHVVJBVElPTl9BU1NFU1NNRU5UID0gJ3NjYScsXG4gIEFVRElUSU5HID0gJ2F1ZGl0JyxcbiAgT1BFTl9TQ0FQID0gJ29zY2FwJyxcbiAgVlVMTkVSQUJJTElUSUVTID0gJ3Z1bHMnLFxuICBPU1FVRVJZID0gJ29zcXVlcnknLFxuICBET0NLRVIgPSAnZG9ja2VyJyxcbiAgTUlUUkVfQVRUQUNLID0gJ21pdHJlJyxcbiAgUENJX0RTUyA9ICdwY2knLFxuICBISVBBQSA9ICdoaXBhYScsXG4gIE5JU1RfODAwXzUzID0gJ25pc3QnLFxuICBUU0MgPSAndHNjJyxcbiAgQ0lTX0NBVCA9ICdjaXNjYXQnLFxuICBWSVJVU1RPVEFMID0gJ3ZpcnVzdG90YWwnLFxuICBHRFBSID0gJ2dkcHInLFxuICBHSVRIVUIgPSAnZ2l0aHViJyxcbn1cblxuZXhwb3J0IGVudW0gV0FaVUhfTUVOVV9NQU5BR0VNRU5UX1NFQ1RJT05TX0lEIHtcbiAgTUFOQUdFTUVOVCA9ICdtYW5hZ2VtZW50JyxcbiAgQURNSU5JU1RSQVRJT04gPSAnYWRtaW5pc3RyYXRpb24nLFxuICBSVUxFU0VUID0gJ3J1bGVzZXQnLFxuICBSVUxFUyA9ICdydWxlcycsXG4gIERFQ09ERVJTID0gJ2RlY29kZXJzJyxcbiAgQ0RCX0xJU1RTID0gJ2xpc3RzJyxcbiAgR1JPVVBTID0gJ2dyb3VwcycsXG4gIENPTkZJR1VSQVRJT04gPSAnY29uZmlndXJhdGlvbicsXG4gIFNUQVRVU19BTkRfUkVQT1JUUyA9ICdzdGF0dXNSZXBvcnRzJyxcbiAgU1RBVFVTID0gJ3N0YXR1cycsXG4gIENMVVNURVIgPSAnbW9uaXRvcmluZycsXG4gIExPR1MgPSAnbG9ncycsXG4gIFJFUE9SVElORyA9ICdyZXBvcnRpbmcnLFxuICBTVEFUSVNUSUNTID0gJ3N0YXRpc3RpY3MnLFxufVxuXG5leHBvcnQgZW51bSBXQVpVSF9NRU5VX1RPT0xTX1NFQ1RJT05TX0lEIHtcbiAgQVBJX0NPTlNPTEUgPSAnZGV2VG9vbHMnLFxuICBSVUxFU0VUX1RFU1QgPSAnbG9ndGVzdCcsXG59XG5cbmV4cG9ydCBlbnVtIFdBWlVIX01FTlVfU0VDVVJJVFlfU0VDVElPTlNfSUQge1xuICBVU0VSUyA9ICd1c2VycycsXG4gIFJPTEVTID0gJ3JvbGVzJyxcbiAgUE9MSUNJRVMgPSAncG9saWNpZXMnLFxuICBST0xFU19NQVBQSU5HID0gJ3JvbGVNYXBwaW5nJyxcbn1cblxuZXhwb3J0IGVudW0gV0FaVUhfTUVOVV9TRVRUSU5HU19TRUNUSU9OU19JRCB7XG4gIFNFVFRJTkdTID0gJ3NldHRpbmdzJyxcbiAgQVBJX0NPTkZJR1VSQVRJT04gPSAnYXBpJyxcbiAgTU9EVUxFUyA9ICdtb2R1bGVzJyxcbiAgU0FNUExFX0RBVEEgPSAnc2FtcGxlX2RhdGEnLFxuICBDT05GSUdVUkFUSU9OID0gJ2NvbmZpZ3VyYXRpb24nLFxuICBMT0dTID0gJ2xvZ3MnLFxuICBNSVNDRUxMQU5FT1VTID0gJ21pc2NlbGxhbmVvdXMnLFxuICBBQk9VVCA9ICdhYm91dCcsXG59XG5cbmV4cG9ydCBjb25zdCBBVVRIT1JJWkVEX0FHRU5UUyA9ICdhdXRob3JpemVkLWFnZW50cyc7XG5cbi8vIFdhenVoIGxpbmtzXG5leHBvcnQgY29uc3QgV0FaVUhfTElOS19HSVRIVUIgPSAnaHR0cHM6Ly9naXRodWIuY29tL3dhenVoJztcbmV4cG9ydCBjb25zdCBXQVpVSF9MSU5LX0dPT0dMRV9HUk9VUFMgPVxuICAnaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9mb3J1bS8jIWZvcnVtL3dhenVoJztcbmV4cG9ydCBjb25zdCBXQVpVSF9MSU5LX1NMQUNLID0gJ2h0dHBzOi8vd2F6dWguY29tL2NvbW11bml0eS9qb2luLXVzLW9uLXNsYWNrJztcblxuZXhwb3J0IGNvbnN0IEhFQUxUSF9DSEVDSyA9ICdoZWFsdGgtY2hlY2snO1xuXG4vLyBIZWFsdGggY2hlY2tcbmV4cG9ydCBjb25zdCBIRUFMVEhfQ0hFQ0tfUkVESVJFQ1RJT05fVElNRSA9IDMwMDsgLy9tc1xuXG4vLyBQbHVnaW4gcGxhdGZvcm0gc2V0dGluZ3Ncbi8vIERlZmF1bHQgdGltZUZpbHRlciBzZXQgYnkgdGhlIGFwcFxuZXhwb3J0IGNvbnN0IFdBWlVIX1BMVUdJTl9QTEFURk9STV9TRVRUSU5HX1RJTUVfRklMVEVSID0ge1xuICBmcm9tOiAnbm93LTI0aCcsXG4gIHRvOiAnbm93Jyxcbn07XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfTkFNRV9USU1FX0ZJTFRFUiA9XG4gICd0aW1lcGlja2VyOnRpbWVEZWZhdWx0cyc7XG5cbi8vIERlZmF1bHQgbWF4QnVja2V0cyBzZXQgYnkgdGhlIGFwcFxuZXhwb3J0IGNvbnN0IFdBWlVIX1BMVUdJTl9QTEFURk9STV9TRVRUSU5HX01BWF9CVUNLRVRTID0gMjAwMDAwO1xuZXhwb3J0IGNvbnN0IFBMVUdJTl9QTEFURk9STV9TRVRUSU5HX05BTUVfTUFYX0JVQ0tFVFMgPSAndGltZWxpbmU6bWF4X2J1Y2tldHMnO1xuXG4vLyBEZWZhdWx0IG1ldGFGaWVsZHMgc2V0IGJ5IHRoZSBhcHBcbmV4cG9ydCBjb25zdCBXQVpVSF9QTFVHSU5fUExBVEZPUk1fU0VUVElOR19NRVRBRklFTERTID0gWydfc291cmNlJywgJ19pbmRleCddO1xuZXhwb3J0IGNvbnN0IFBMVUdJTl9QTEFURk9STV9TRVRUSU5HX05BTUVfTUVUQUZJRUxEUyA9ICdtZXRhRmllbGRzJztcblxuLy8gTG9nZ2VyXG5leHBvcnQgY29uc3QgVUlfTE9HR0VSX0xFVkVMUyA9IHtcbiAgV0FSTklORzogJ1dBUk5JTkcnLFxuICBJTkZPOiAnSU5GTycsXG4gIEVSUk9SOiAnRVJST1InLFxufTtcblxuZXhwb3J0IGNvbnN0IFVJX1RPQVNUX0NPTE9SID0ge1xuICBTVUNDRVNTOiAnc3VjY2VzcycsXG4gIFdBUk5JTkc6ICd3YXJuaW5nJyxcbiAgREFOR0VSOiAnZGFuZ2VyJyxcbn07XG5cbi8vIEFzc2V0c1xuZXhwb3J0IGNvbnN0IEFTU0VUU19CQVNFX1VSTF9QUkVGSVggPSAnL3BsdWdpbnMvd2F6dWgvYXNzZXRzLyc7XG5leHBvcnQgY29uc3QgQVNTRVRTX1BVQkxJQ19VUkwgPSAnL3BsdWdpbnMvd2F6dWgvcHVibGljL2Fzc2V0cy8nO1xuXG4vLyBSZXBvcnRzXG5leHBvcnQgY29uc3QgUkVQT1JUU19MT0dPX0lNQUdFX0FTU0VUU19SRUxBVElWRV9QQVRIID1cbiAgJ2ltYWdlcy9sb2dvX3JlcG9ydHMucG5nJztcbmV4cG9ydCBjb25zdCBSRVBPUlRTX1BSSU1BUllfQ09MT1IgPSAnIzI1NkJEMSc7XG5leHBvcnQgY29uc3QgUkVQT1JUU19QQUdFX0ZPT1RFUl9URVhUID0gJ0NvcHlyaWdodCDCqSBXYXp1aCwgSW5jLic7XG5leHBvcnQgY29uc3QgUkVQT1JUU19QQUdFX0hFQURFUl9URVhUID0gJ2luZm9Ad2F6dWguY29tXFxuaHR0cHM6Ly93YXp1aC5jb20nO1xuXG4vLyBQbHVnaW4gcGxhdGZvcm1cbmV4cG9ydCBjb25zdCBQTFVHSU5fUExBVEZPUk1fTkFNRSA9ICdkYXNoYm9hcmQnO1xuZXhwb3J0IGNvbnN0IFBMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUiA9ICd3YXp1aC1kYXNoYm9hcmQnO1xuZXhwb3J0IGNvbnN0IFBMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUl9HUk9VUCA9ICd3YXp1aC1kYXNoYm9hcmQnO1xuZXhwb3J0IGNvbnN0IFBMVUdJTl9QTEFURk9STV9XQVpVSF9ET0NVTUVOVEFUSU9OX1VSTF9QQVRIX1VQR1JBREVfUExBVEZPUk0gPVxuICAndXBncmFkZS1ndWlkZSc7XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX1dBWlVIX0RPQ1VNRU5UQVRJT05fVVJMX1BBVEhfVFJPVUJMRVNIT09USU5HID1cbiAgJ3VzZXItbWFudWFsL3dhenVoLWRhc2hib2FyZC90cm91Ymxlc2hvb3RpbmcuaHRtbCc7XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX1dBWlVIX0RPQ1VNRU5UQVRJT05fVVJMX1BBVEhfQVBQX0NPTkZJR1VSQVRJT04gPVxuICAndXNlci1tYW51YWwvd2F6dWgtZGFzaGJvYXJkL2NvbmZpZy1maWxlLmh0bWwnO1xuZXhwb3J0IGNvbnN0IFBMVUdJTl9QTEFURk9STV9VUkxfR1VJREUgPVxuICAnaHR0cHM6Ly9vcGVuc2VhcmNoLm9yZy9kb2NzLzIuMTAvYWJvdXQnO1xuZXhwb3J0IGNvbnN0IFBMVUdJTl9QTEFURk9STV9VUkxfR1VJREVfVElUTEUgPSAnT3BlblNlYXJjaCBndWlkZSc7XG5cbmV4cG9ydCBjb25zdCBQTFVHSU5fUExBVEZPUk1fUkVRVUVTVF9IRUFERVJTID0ge1xuICAnb3NkLXhzcmYnOiAna2liYW5hJyxcbn07XG5cbi8vIFBsdWdpbiBhcHBcbmV4cG9ydCBjb25zdCBQTFVHSU5fQVBQX05BTUUgPSAnRGFzaGJvYXJkJztcblxuLy8gVUlcbmV4cG9ydCBjb25zdCBVSV9DT0xPUl9TVEFUVVMgPSB7XG4gIHN1Y2Nlc3M6ICcjMDA3ODcxJyxcbiAgZGFuZ2VyOiAnI0JEMjcxRScsXG4gIHdhcm5pbmc6ICcjRkVDNTE0JyxcbiAgZGlzYWJsZWQ6ICcjNjQ2QTc3JyxcbiAgaW5mbzogJyM2MDkyQzAnLFxuICBkZWZhdWx0OiAnIzAwMDAwMCcsXG59IGFzIGNvbnN0O1xuXG5leHBvcnQgY29uc3QgQVBJX05BTUVfQUdFTlRfU1RBVFVTID0ge1xuICBBQ1RJVkU6ICdhY3RpdmUnLFxuICBESVNDT05ORUNURUQ6ICdkaXNjb25uZWN0ZWQnLFxuICBQRU5ESU5HOiAncGVuZGluZycsXG4gIE5FVkVSX0NPTk5FQ1RFRDogJ25ldmVyX2Nvbm5lY3RlZCcsXG59IGFzIGNvbnN0O1xuXG5leHBvcnQgY29uc3QgVUlfQ09MT1JfQUdFTlRfU1RBVFVTID0ge1xuICBbQVBJX05BTUVfQUdFTlRfU1RBVFVTLkFDVElWRV06IFVJX0NPTE9SX1NUQVRVUy5zdWNjZXNzLFxuICBbQVBJX05BTUVfQUdFTlRfU1RBVFVTLkRJU0NPTk5FQ1RFRF06IFVJX0NPTE9SX1NUQVRVUy5kYW5nZXIsXG4gIFtBUElfTkFNRV9BR0VOVF9TVEFUVVMuUEVORElOR106IFVJX0NPTE9SX1NUQVRVUy53YXJuaW5nLFxuICBbQVBJX05BTUVfQUdFTlRfU1RBVFVTLk5FVkVSX0NPTk5FQ1RFRF06IFVJX0NPTE9SX1NUQVRVUy5kaXNhYmxlZCxcbiAgZGVmYXVsdDogVUlfQ09MT1JfU1RBVFVTLmRlZmF1bHQsXG59IGFzIGNvbnN0O1xuXG5leHBvcnQgY29uc3QgVUlfTEFCRUxfTkFNRV9BR0VOVF9TVEFUVVMgPSB7XG4gIFtBUElfTkFNRV9BR0VOVF9TVEFUVVMuQUNUSVZFXTogJ0FjdGl2ZScsXG4gIFtBUElfTkFNRV9BR0VOVF9TVEFUVVMuRElTQ09OTkVDVEVEXTogJ0Rpc2Nvbm5lY3RlZCcsXG4gIFtBUElfTkFNRV9BR0VOVF9TVEFUVVMuUEVORElOR106ICdQZW5kaW5nJyxcbiAgW0FQSV9OQU1FX0FHRU5UX1NUQVRVUy5ORVZFUl9DT05ORUNURURdOiAnTmV2ZXIgY29ubmVjdGVkJyxcbiAgZGVmYXVsdDogJ1Vua25vd24nLFxufSBhcyBjb25zdDtcblxuZXhwb3J0IGNvbnN0IFVJX09SREVSX0FHRU5UX1NUQVRVUyA9IFtcbiAgQVBJX05BTUVfQUdFTlRfU1RBVFVTLkFDVElWRSxcbiAgQVBJX05BTUVfQUdFTlRfU1RBVFVTLkRJU0NPTk5FQ1RFRCxcbiAgQVBJX05BTUVfQUdFTlRfU1RBVFVTLlBFTkRJTkcsXG4gIEFQSV9OQU1FX0FHRU5UX1NUQVRVUy5ORVZFUl9DT05ORUNURUQsXG5dO1xuXG5leHBvcnQgY29uc3QgQUdFTlRfU1lOQ0VEX1NUQVRVUyA9IHtcbiAgU1lOQ0VEOiAnc3luY2VkJyxcbiAgTk9UX1NZTkNFRDogJ25vdCBzeW5jZWQnLFxufTtcblxuLy8gVGhlIHN0YXR1cyBjb2RlIGNhbiBiZSBzZWVuIGhlcmUgaHR0cHM6Ly9naXRodWIuY29tL3dhenVoL3dhenVoL2Jsb2IvNjg2MDY4YTFmMDVkODA2YjJlM2IzZDYzM2E3NjUzMjBhZTdhZTExNC9zcmMvd2F6dWhfZGIvd2RiLmgjTDU1LUw2MVxuXG5leHBvcnQgY29uc3QgQUdFTlRfU1RBVFVTX0NPREUgPSBbXG4gIHtcbiAgICBTVEFUVVNfQ09ERTogMCxcbiAgICBTVEFUVVNfREVTQ1JJUFRJT046ICdBZ2VudCBpcyBjb25uZWN0ZWQnLFxuICB9LFxuICB7XG4gICAgU1RBVFVTX0NPREU6IDEsXG4gICAgU1RBVFVTX0RFU0NSSVBUSU9OOiAnSW52YWxpZCBhZ2VudCB2ZXJzaW9uJyxcbiAgfSxcbiAge1xuICAgIFNUQVRVU19DT0RFOiAyLFxuICAgIFNUQVRVU19ERVNDUklQVElPTjogJ0Vycm9yIHJldHJpZXZpbmcgdmVyc2lvbicsXG4gIH0sXG4gIHtcbiAgICBTVEFUVVNfQ09ERTogMyxcbiAgICBTVEFUVVNfREVTQ1JJUFRJT046ICdTaHV0ZG93biBtZXNzYWdlIHJlY2VpdmVkJyxcbiAgfSxcbiAge1xuICAgIFNUQVRVU19DT0RFOiA0LFxuICAgIFNUQVRVU19ERVNDUklQVElPTjogJ0Rpc2Nvbm5lY3RlZCBiZWNhdXNlIG5vIGtlZXBhbGl2ZSByZWNlaXZlZCcsXG4gIH0sXG4gIHtcbiAgICBTVEFUVVNfQ09ERTogNSxcbiAgICBTVEFUVVNfREVTQ1JJUFRJT046ICdDb25uZWN0aW9uIHJlc2V0IGJ5IG1hbmFnZXInLFxuICB9LFxuXTtcblxuLy8gRG9jdW1lbnRhdGlvblxuZXhwb3J0IGNvbnN0IERPQ1VNRU5UQVRJT05fV0VCX0JBU0VfVVJMID0gJ2h0dHBzOi8vZG9jdW1lbnRhdGlvbi53YXp1aC5jb20nO1xuXG4vLyBEZWZhdWx0IEVsYXN0aWNzZWFyY2ggdXNlciBuYW1lIGNvbnRleHRcbmV4cG9ydCBjb25zdCBFTEFTVElDX05BTUUgPSAnZWxhc3RpYyc7XG5cbi8vIERlZmF1bHQgV2F6dWggaW5kZXhlciBuYW1lXG5leHBvcnQgY29uc3QgV0FaVUhfSU5ERVhFUl9OQU1FID0gJ2luZGV4ZXInO1xuXG4vLyBOb3QgdGltZUZpZWxkTmFtZSBvbiBpbmRleCBwYXR0ZXJuXG5leHBvcnQgY29uc3QgTk9UX1RJTUVfRklFTERfTkFNRV9JTkRFWF9QQVRURVJOID1cbiAgJ25vdF90aW1lX2ZpZWxkX25hbWVfaW5kZXhfcGF0dGVybic7XG5cbi8vIEN1c3RvbWl6YXRpb25cbmV4cG9ydCBjb25zdCBDVVNUT01JWkFUSU9OX0VORFBPSU5UX1BBWUxPQURfVVBMT0FEX0NVU1RPTV9GSUxFX01BWElNVU1fQllURVMgPSAxMDQ4NTc2O1xuXG4vLyBQbHVnaW4gc2V0dGluZ3NcbmV4cG9ydCBlbnVtIFNldHRpbmdDYXRlZ29yeSB7XG4gIEdFTkVSQUwsXG4gIEhFQUxUSF9DSEVDSyxcbiAgTU9OSVRPUklORyxcbiAgU1RBVElTVElDUyxcbiAgVlVMTkVSQUJJTElUSUVTLFxuICBTRUNVUklUWSxcbiAgQ1VTVE9NSVpBVElPTixcbiAgQVBJX0NPTk5FQ1RJT04sXG59XG5cbnR5cGUgVFBsdWdpblNldHRpbmdPcHRpb25zVGV4dEFyZWEgPSB7XG4gIG1heFJvd3M/OiBudW1iZXI7XG4gIG1pblJvd3M/OiBudW1iZXI7XG4gIG1heExlbmd0aD86IG51bWJlcjtcbn07XG5cbnR5cGUgVFBsdWdpblNldHRpbmdPcHRpb25zU2VsZWN0ID0ge1xuICBzZWxlY3Q6IHsgdGV4dDogc3RyaW5nOyB2YWx1ZTogYW55IH1bXTtcbn07XG5cbnR5cGUgVFBsdWdpblNldHRpbmdPcHRpb25zRWRpdG9yID0ge1xuICBlZGl0b3I6IHtcbiAgICBsYW5ndWFnZTogc3RyaW5nO1xuICB9O1xufTtcblxudHlwZSBUUGx1Z2luU2V0dGluZ09wdGlvbnNGaWxlID0ge1xuICBmaWxlOiB7XG4gICAgdHlwZTogJ2ltYWdlJztcbiAgICBleHRlbnNpb25zPzogc3RyaW5nW107XG4gICAgc2l6ZT86IHtcbiAgICAgIG1heEJ5dGVzPzogbnVtYmVyO1xuICAgICAgbWluQnl0ZXM/OiBudW1iZXI7XG4gICAgfTtcbiAgICByZWNvbW1lbmRlZD86IHtcbiAgICAgIGRpbWVuc2lvbnM/OiB7XG4gICAgICAgIHdpZHRoOiBudW1iZXI7XG4gICAgICAgIGhlaWdodDogbnVtYmVyO1xuICAgICAgICB1bml0OiBzdHJpbmc7XG4gICAgICB9O1xuICAgIH07XG4gICAgc3RvcmU/OiB7XG4gICAgICByZWxhdGl2ZVBhdGhGaWxlU3lzdGVtOiBzdHJpbmc7XG4gICAgICBmaWxlbmFtZTogc3RyaW5nO1xuICAgICAgcmVzb2x2ZVN0YXRpY1VSTDogKGZpbGVuYW1lOiBzdHJpbmcpID0+IHN0cmluZztcbiAgICB9O1xuICB9O1xufTtcblxudHlwZSBUUGx1Z2luU2V0dGluZ09wdGlvbnNOdW1iZXIgPSB7XG4gIG51bWJlcjoge1xuICAgIG1pbj86IG51bWJlcjtcbiAgICBtYXg/OiBudW1iZXI7XG4gICAgaW50ZWdlcj86IGJvb2xlYW47XG4gIH07XG59O1xuXG50eXBlIFRQbHVnaW5TZXR0aW5nT3B0aW9uc1N3aXRjaCA9IHtcbiAgc3dpdGNoOiB7XG4gICAgdmFsdWVzOiB7XG4gICAgICBkaXNhYmxlZDogeyBsYWJlbD86IHN0cmluZzsgdmFsdWU6IGFueSB9O1xuICAgICAgZW5hYmxlZDogeyBsYWJlbD86IHN0cmluZzsgdmFsdWU6IGFueSB9O1xuICAgIH07XG4gIH07XG59O1xuXG5leHBvcnQgZW51bSBFcGx1Z2luU2V0dGluZ1R5cGUge1xuICB0ZXh0ID0gJ3RleHQnLFxuICB0ZXh0YXJlYSA9ICd0ZXh0YXJlYScsXG4gIHN3aXRjaCA9ICdzd2l0Y2gnLFxuICBudW1iZXIgPSAnbnVtYmVyJyxcbiAgZWRpdG9yID0gJ2VkaXRvcicsXG4gIHNlbGVjdCA9ICdzZWxlY3QnLFxuICBmaWxlcGlja2VyID0gJ2ZpbGVwaWNrZXInLFxuICBwYXNzd29yZCA9ICdwYXNzd29yZCcsXG4gIGFycmF5T2YgPSAnYXJyYXlPZicsXG4gIGN1c3RvbSA9ICdjdXN0b20nLFxufVxuXG5leHBvcnQgdHlwZSBUUGx1Z2luU2V0dGluZyA9IHtcbiAgLy8gRGVmaW5lIHRoZSB0ZXh0IGRpc3BsYXllZCBpbiB0aGUgVUkuXG4gIHRpdGxlOiBzdHJpbmc7XG4gIC8vIERlc2NyaXB0aW9uLlxuICBkZXNjcmlwdGlvbjogc3RyaW5nO1xuICAvLyBDYXRlZ29yeS5cbiAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeTtcbiAgLy8gVHlwZS5cbiAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlO1xuICAvLyBTdG9yZVxuICBzdG9yZToge1xuICAgIGZpbGU6IHtcbiAgICAgIC8vIERlZmluZSBpZiB0aGUgc2V0dGluZyBpcyBtYW5hZ2VkIGJ5IHRoZSBDb25maWd1cmF0aW9uU3RvcmUgc2VydmljZVxuICAgICAgY29uZmlndXJhYmxlTWFuYWdlZD86IGJvb2xlYW47XG4gICAgICAvLyBEZWZpbmUgYSB0ZXh0IHRvIHByaW50IGFzIHRoZSBkZWZhdWx0IGluIHRoZSBjb25maWd1cmF0aW9uIGJsb2NrXG4gICAgICBkZWZhdWx0QmxvY2s/OiBzdHJpbmc7XG4gICAgICAvKiBUcmFuc2Zvcm0gdGhlIHZhbHVlIGRlZmluZWQgaW4gdGhlIGNvbmZpZ3VyYXRpb24gZmlsZSB0byBiZSBjb25zdW1lZCBieSB0aGUgQ29uZmlndXJhdGlvblxuICAgICAgICBzZXJ2aWNlICovXG4gICAgICB0cmFuc2Zvcm1Gcm9tPzogKHZhbHVlOiBhbnkpID0+IGFueTtcbiAgICB9O1xuICB9O1xuICAvLyBEZWZhdWx0IHZhbHVlLlxuICBkZWZhdWx0VmFsdWU6IGFueTtcbiAgLyogU3BlY2lhbDogVGhpcyBpcyB1c2VkIGZvciB0aGUgc2V0dGluZ3Mgb2YgY3VzdG9taXphdGlvbiB0byBnZXQgdGhlIGhpZGRlbiBkZWZhdWx0IHZhbHVlLCBiZWNhdXNlIHRoZSBkZWZhdWx0IHZhbHVlIGlzIGVtcHR5IHRvIG5vdCB0byBiZSBkaXNwbGF5ZWQgb24gdGhlIEFwcCBTZXR0aW5ncy4gKi9cbiAgZGVmYXVsdFZhbHVlSWZOb3RTZXQ/OiBhbnk7XG4gIC8vIENvbmZpZ3VyYWJsZSBmcm9tIHRoZSBBcHAgU2V0dGluZ3MgYXBwLlxuICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogYm9vbGVhbjtcbiAgLy8gTW9kaWZ5IHRoZSBzZXR0aW5nIHJlcXVpcmVzIHJ1bm5pbmcgdGhlIHBsdWdpbiBoZWFsdGggY2hlY2sgKGZyb250ZW5kKS5cbiAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s/OiBib29sZWFuO1xuICAvLyBNb2RpZnkgdGhlIHNldHRpbmcgcmVxdWlyZXMgcmVsb2FkaW5nIHRoZSBicm93c2VyIHRhYiAoZnJvbnRlbmQpLlxuICByZXF1aXJlc1JlbG9hZGluZ0Jyb3dzZXJUYWI/OiBib29sZWFuO1xuICAvLyBNb2RpZnkgdGhlIHNldHRpbmcgcmVxdWlyZXMgcmVzdGFydGluZyB0aGUgcGx1Z2luIHBsYXRmb3JtIHRvIHRha2UgZWZmZWN0LlxuICByZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybT86IGJvb2xlYW47XG4gIC8vIERlZmluZSBvcHRpb25zIHJlbGF0ZWQgdG8gdGhlIGB0eXBlYC5cbiAgb3B0aW9ucz86XG4gICAgfCBUUGx1Z2luU2V0dGluZ09wdGlvbnNFZGl0b3JcbiAgICB8IFRQbHVnaW5TZXR0aW5nT3B0aW9uc0ZpbGVcbiAgICB8IFRQbHVnaW5TZXR0aW5nT3B0aW9uc051bWJlclxuICAgIHwgVFBsdWdpblNldHRpbmdPcHRpb25zU2VsZWN0XG4gICAgfCBUUGx1Z2luU2V0dGluZ09wdGlvbnNTd2l0Y2hcbiAgICB8IFRQbHVnaW5TZXR0aW5nT3B0aW9uc1RleHRBcmVhO1xuICAvLyBUcmFuc2Zvcm0gdGhlIGlucHV0IHZhbHVlLiBUaGUgcmVzdWx0IGlzIHNhdmVkIGluIHRoZSBmb3JtIGdsb2JhbCBzdGF0ZSBvZiBTZXR0aW5ncy9Db25maWd1cmF0aW9uXG4gIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlPzogKHZhbHVlOiBhbnkpID0+IGFueTtcbiAgLy8gVHJhbnNmb3JtIHRoZSBjb25maWd1cmF0aW9uIHZhbHVlIG9yIGRlZmF1bHQgYXMgaW5pdGlhbCB2YWx1ZSBmb3IgdGhlIGlucHV0IGluIFNldHRpbmdzL0NvbmZpZ3VyYXRpb25cbiAgdWlGb3JtVHJhbnNmb3JtQ29uZmlndXJhdGlvblZhbHVlVG9JbnB1dFZhbHVlPzogKHZhbHVlOiBhbnkpID0+IGFueTtcbiAgLy8gVHJhbnNmb3JtIHRoZSBpbnB1dCB2YWx1ZSBjaGFuZ2VkIGluIHRoZSBmb3JtIG9mIFNldHRpbmdzL0NvbmZpZ3VyYXRpb24gYW5kIHJldHVybmVkIGluIHRoZSBgY2hhbmdlZGAgcHJvcGVydHkgb2YgdGhlIGhvb2sgdXNlRm9ybVxuICB1aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWU/OiAodmFsdWU6IGFueSkgPT4gYW55O1xuICAvLyBWYWxpZGF0ZSB0aGUgdmFsdWUgaW4gdGhlIGZvcm0gb2YgU2V0dGluZ3MvQ29uZmlndXJhdGlvbi4gSXQgcmV0dXJucyBhIHN0cmluZyBpZiB0aGVyZSBpcyBzb21lIHZhbGlkYXRpb24gZXJyb3IuXG4gIHZhbGlkYXRlVUlGb3JtPzogKHZhbHVlOiBhbnkpID0+IHN0cmluZyB8IHVuZGVmaW5lZDtcbiAgLy8gVmFsaWRhdGUgZnVuY3Rpb24gY3JlYXRvciB0byB2YWxpZGF0ZSB0aGUgc2V0dGluZyBpbiB0aGUgYmFja2VuZC5cbiAgdmFsaWRhdGU/OiAodmFsdWU6IHVua25vd24pID0+IHN0cmluZyB8IHVuZGVmaW5lZDtcbn07XG5cbmV4cG9ydCB0eXBlIFRQbHVnaW5TZXR0aW5nV2l0aEtleSA9IFRQbHVnaW5TZXR0aW5nICYgeyBrZXk6IFRQbHVnaW5TZXR0aW5nS2V5IH07XG5leHBvcnQgdHlwZSBUUGx1Z2luU2V0dGluZ0NhdGVnb3J5ID0ge1xuICB0aXRsZTogc3RyaW5nO1xuICBkZXNjcmlwdGlvbj86IHN0cmluZztcbiAgZG9jdW1lbnRhdGlvbkxpbms/OiBzdHJpbmc7XG4gIHJlbmRlck9yZGVyPzogbnVtYmVyO1xufTtcblxuZXhwb3J0IGNvbnN0IFBMVUdJTl9TRVRUSU5HU19DQVRFR09SSUVTOiB7XG4gIFtjYXRlZ29yeTogbnVtYmVyXTogVFBsdWdpblNldHRpbmdDYXRlZ29yeTtcbn0gPSB7XG4gIFtTZXR0aW5nQ2F0ZWdvcnkuSEVBTFRIX0NIRUNLXToge1xuICAgIHRpdGxlOiAnSGVhbHRoIGNoZWNrJyxcbiAgICBkZXNjcmlwdGlvbjogXCJDaGVja3Mgd2lsbCBiZSBleGVjdXRlZCBieSB0aGUgYXBwJ3MgSGVhbHRoY2hlY2suXCIsXG4gICAgcmVuZGVyT3JkZXI6IFNldHRpbmdDYXRlZ29yeS5IRUFMVEhfQ0hFQ0ssXG4gIH0sXG4gIFtTZXR0aW5nQ2F0ZWdvcnkuR0VORVJBTF06IHtcbiAgICB0aXRsZTogJ0dlbmVyYWwnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ0Jhc2ljIGFwcCBzZXR0aW5ncyByZWxhdGVkIHRvIGFsZXJ0cyBpbmRleCBwYXR0ZXJuLCBoaWRlIHRoZSBtYW5hZ2VyIGFsZXJ0cyBpbiB0aGUgZGFzaGJvYXJkcywgbG9ncyBsZXZlbCBhbmQgbW9yZS4nLFxuICAgIHJlbmRlck9yZGVyOiBTZXR0aW5nQ2F0ZWdvcnkuR0VORVJBTCxcbiAgfSxcbiAgW1NldHRpbmdDYXRlZ29yeS5TRUNVUklUWV06IHtcbiAgICB0aXRsZTogJ1NlY3VyaXR5JyxcbiAgICBkZXNjcmlwdGlvbjogJ0FwcGxpY2F0aW9uIHNlY3VyaXR5IG9wdGlvbnMgc3VjaCBhcyB1bmF1dGhvcml6ZWQgcm9sZXMuJyxcbiAgICByZW5kZXJPcmRlcjogU2V0dGluZ0NhdGVnb3J5LlNFQ1VSSVRZLFxuICB9LFxuICBbU2V0dGluZ0NhdGVnb3J5Lk1PTklUT1JJTkddOiB7XG4gICAgdGl0bGU6ICdUYXNrOk1vbml0b3JpbmcnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ09wdGlvbnMgcmVsYXRlZCB0byB0aGUgYWdlbnQgc3RhdHVzIG1vbml0b3Jpbmcgam9iIGFuZCBpdHMgc3RvcmFnZSBpbiBpbmRleGVzLicsXG4gICAgcmVuZGVyT3JkZXI6IFNldHRpbmdDYXRlZ29yeS5NT05JVE9SSU5HLFxuICB9LFxuICBbU2V0dGluZ0NhdGVnb3J5LlNUQVRJU1RJQ1NdOiB7XG4gICAgdGl0bGU6ICdUYXNrOlN0YXRpc3RpY3MnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ09wdGlvbnMgcmVsYXRlZCB0byB0aGUgZGFlbW9ucyBtYW5hZ2VyIG1vbml0b3Jpbmcgam9iIGFuZCB0aGVpciBzdG9yYWdlIGluIGluZGV4ZXMuJyxcbiAgICByZW5kZXJPcmRlcjogU2V0dGluZ0NhdGVnb3J5LlNUQVRJU1RJQ1MsXG4gIH0sXG4gIFtTZXR0aW5nQ2F0ZWdvcnkuVlVMTkVSQUJJTElUSUVTXToge1xuICAgIHRpdGxlOiAnVnVsbmVyYWJpbGl0aWVzJyxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdPcHRpb25zIHJlbGF0ZWQgdG8gdGhlIGFnZW50IHZ1bG5lcmFiaWxpdGllcyBtb25pdG9yaW5nIGpvYiBhbmQgaXRzIHN0b3JhZ2UgaW4gaW5kZXhlcy4nLFxuICAgIHJlbmRlck9yZGVyOiBTZXR0aW5nQ2F0ZWdvcnkuVlVMTkVSQUJJTElUSUVTLFxuICB9LFxuICBbU2V0dGluZ0NhdGVnb3J5LkNVU1RPTUlaQVRJT05dOiB7XG4gICAgdGl0bGU6ICdDdXN0b20gYnJhbmRpbmcnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ0lmIHlvdSB3YW50IHRvIHVzZSBjdXN0b20gYnJhbmRpbmcgZWxlbWVudHMgc3VjaCBhcyBsb2dvcywgeW91IGNhbiBkbyBzbyBieSBlZGl0aW5nIHRoZSBzZXR0aW5ncyBiZWxvdy4nLFxuICAgIGRvY3VtZW50YXRpb25MaW5rOiAndXNlci1tYW51YWwvd2F6dWgtZGFzaGJvYXJkL3doaXRlLWxhYmVsaW5nLmh0bWwnLFxuICAgIHJlbmRlck9yZGVyOiBTZXR0aW5nQ2F0ZWdvcnkuQ1VTVE9NSVpBVElPTixcbiAgfSxcbiAgW1NldHRpbmdDYXRlZ29yeS5BUElfQ09OTkVDVElPTl06IHtcbiAgICB0aXRsZTogJ0FQSSBjb25uZWN0aW9ucycsXG4gICAgZGVzY3JpcHRpb246ICdPcHRpb25zIHJlbGF0ZWQgdG8gdGhlIEFQSSBjb25uZWN0aW9ucy4nLFxuICAgIHJlbmRlck9yZGVyOiBTZXR0aW5nQ2F0ZWdvcnkuQVBJX0NPTk5FQ1RJT04sXG4gIH0sXG59O1xuXG5leHBvcnQgY29uc3QgUExVR0lOX1NFVFRJTkdTOiB7IFtrZXk6IHN0cmluZ106IFRQbHVnaW5TZXR0aW5nIH0gPSB7XG4gICdhbGVydHMuc2FtcGxlLnByZWZpeCc6IHtcbiAgICB0aXRsZTogJ1NhbXBsZSBhbGVydHMgcHJlZml4JyxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdEZWZpbmUgdGhlIGluZGV4IG5hbWUgcHJlZml4IG9mIHNhbXBsZSBhbGVydHMuIEl0IG11c3QgbWF0Y2ggdGhlIHRlbXBsYXRlIHVzZWQgYnkgdGhlIGluZGV4IHBhdHRlcm4gdG8gYXZvaWQgdW5rbm93biBmaWVsZHMgaW4gZGFzaGJvYXJkcy4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5HRU5FUkFMLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS50ZXh0LFxuICAgIGRlZmF1bHRWYWx1ZTogV0FaVUhfU0FNUExFX0FMRVJUX1BSRUZJWCxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICByZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjazogdHJ1ZSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICAvLyBWYWxpZGF0aW9uOiBodHRwczovL2dpdGh1Yi5jb20vZWxhc3RpYy9lbGFzdGljc2VhcmNoL2Jsb2IvdjcuMTAuMi9kb2NzL3JlZmVyZW5jZS9pbmRpY2VzL2NyZWF0ZS1pbmRleC5hc2NpaWRvY1xuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNTdHJpbmcsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc05vdEVtcHR5U3RyaW5nLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm9TcGFjZXMsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5ub1N0YXJ0c1dpdGhTdHJpbmcoJy0nLCAnXycsICcrJywgJy4nKSxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmhhc05vdEludmFsaWRDaGFyYWN0ZXJzKFxuICAgICAgICAnXFxcXCcsXG4gICAgICAgICcvJyxcbiAgICAgICAgJz8nLFxuICAgICAgICAnXCInLFxuICAgICAgICAnPCcsXG4gICAgICAgICc+JyxcbiAgICAgICAgJ3wnLFxuICAgICAgICAnLCcsXG4gICAgICAgICcjJyxcbiAgICAgICAgJyonLFxuICAgICAgKSxcbiAgICApLFxuICB9LFxuICAnY2hlY2tzLmFwaSc6IHtcbiAgICB0aXRsZTogJ0FQSSBjb25uZWN0aW9uJyxcbiAgICBkZXNjcmlwdGlvbjogJ0VuYWJsZSBvciBkaXNhYmxlIHRoZSBBUEkgaGVhbHRoIGNoZWNrIHdoZW4gb3BlbmluZyB0aGUgYXBwLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkhFQUxUSF9DSEVDSyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzd2l0Y2g6IHtcbiAgICAgICAgdmFsdWVzOiB7XG4gICAgICAgICAgZGlzYWJsZWQ6IHsgbGFiZWw6ICdmYWxzZScsIHZhbHVlOiBmYWxzZSB9LFxuICAgICAgICAgIGVuYWJsZWQ6IHsgbGFiZWw6ICd0cnVlJywgdmFsdWU6IHRydWUgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcsXG4gICAgKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuICB9LFxuICAnY2hlY2tzLmZpZWxkcyc6IHtcbiAgICB0aXRsZTogJ0tub3duIGZpZWxkcycsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnRW5hYmxlIG9yIGRpc2FibGUgdGhlIGtub3duIGZpZWxkcyBoZWFsdGggY2hlY2sgd2hlbiBvcGVuaW5nIHRoZSBhcHAuJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuSEVBTFRIX0NIRUNLLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAoXG4gICAgICB2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyxcbiAgICApOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG4gIH0sXG4gICdjaGVja3MubWF4QnVja2V0cyc6IHtcbiAgICB0aXRsZTogJ1NldCBtYXggYnVja2V0cyB0byAyMDAwMDAnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ0NoYW5nZSB0aGUgZGVmYXVsdCB2YWx1ZSBvZiB0aGUgcGx1Z2luIHBsYXRmb3JtIG1heCBidWNrZXRzIGNvbmZpZ3VyYXRpb24uJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuSEVBTFRIX0NIRUNLLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAoXG4gICAgICB2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyxcbiAgICApOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG4gIH0sXG4gICdjaGVja3MubWV0YUZpZWxkcyc6IHtcbiAgICB0aXRsZTogJ1JlbW92ZSBtZXRhIGZpZWxkcycsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnQ2hhbmdlIHRoZSBkZWZhdWx0IHZhbHVlIG9mIHRoZSBwbHVnaW4gcGxhdGZvcm0gbWV0YUZpZWxkIGNvbmZpZ3VyYXRpb24uJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuSEVBTFRIX0NIRUNLLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAoXG4gICAgICB2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyxcbiAgICApOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG4gIH0sXG4gICdjaGVja3MucGF0dGVybic6IHtcbiAgICB0aXRsZTogJ0luZGV4IHBhdHRlcm4nLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ0VuYWJsZSBvciBkaXNhYmxlIHRoZSBpbmRleCBwYXR0ZXJuIGhlYWx0aCBjaGVjayB3aGVuIG9wZW5pbmcgdGhlIGFwcC4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5IRUFMVEhfQ0hFQ0ssXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ2hhbmdlZElucHV0VmFsdWU6IGZ1bmN0aW9uIChcbiAgICAgIHZhbHVlOiBib29sZWFuIHwgc3RyaW5nLFxuICAgICk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIEJvb2xlYW4odmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcbiAgfSxcbiAgJ2NoZWNrcy5zZXR1cCc6IHtcbiAgICB0aXRsZTogJ0FQSSB2ZXJzaW9uJyxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdFbmFibGUgb3IgZGlzYWJsZSB0aGUgc2V0dXAgaGVhbHRoIGNoZWNrIHdoZW4gb3BlbmluZyB0aGUgYXBwLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkhFQUxUSF9DSEVDSyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzd2l0Y2g6IHtcbiAgICAgICAgdmFsdWVzOiB7XG4gICAgICAgICAgZGlzYWJsZWQ6IHsgbGFiZWw6ICdmYWxzZScsIHZhbHVlOiBmYWxzZSB9LFxuICAgICAgICAgIGVuYWJsZWQ6IHsgbGFiZWw6ICd0cnVlJywgdmFsdWU6IHRydWUgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcsXG4gICAgKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuICB9LFxuICAnY2hlY2tzLnRlbXBsYXRlJzoge1xuICAgIHRpdGxlOiAnSW5kZXggdGVtcGxhdGUnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ0VuYWJsZSBvciBkaXNhYmxlIHRoZSB0ZW1wbGF0ZSBoZWFsdGggY2hlY2sgd2hlbiBvcGVuaW5nIHRoZSBhcHAuJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuSEVBTFRIX0NIRUNLLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAoXG4gICAgICB2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyxcbiAgICApOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG4gIH0sXG4gICdjaGVja3MudGltZUZpbHRlcic6IHtcbiAgICB0aXRsZTogJ1NldCB0aW1lIGZpbHRlciB0byAyNGgnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ0NoYW5nZSB0aGUgZGVmYXVsdCB2YWx1ZSBvZiB0aGUgcGx1Z2luIHBsYXRmb3JtIHRpbWVGaWx0ZXIgY29uZmlndXJhdGlvbi4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5IRUFMVEhfQ0hFQ0ssXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ2hhbmdlZElucHV0VmFsdWU6IGZ1bmN0aW9uIChcbiAgICAgIHZhbHVlOiBib29sZWFuIHwgc3RyaW5nLFxuICAgICk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIEJvb2xlYW4odmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcbiAgfSxcbiAgJ2NvbmZpZ3VyYXRpb24udWlfYXBpX2VkaXRhYmxlJzoge1xuICAgIHRpdGxlOiAnQ29uZmlndXJhdGlvbiBVSSBlZGl0YWJsZScsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnRW5hYmxlIG9yIGRpc2FibGUgdGhlIGFiaWxpdHkgdG8gZWRpdCB0aGUgY29uZmlndXJhdGlvbiBmcm9tIFVJIG9yIEFQSSBlbmRwb2ludHMuIFdoZW4gZGlzYWJsZWQsIHRoaXMgY2FuIG9ubHkgYmUgZWRpdGVkIGZyb20gdGhlIGNvbmZpZ3VyYXRpb24gZmlsZSwgdGhlIHJlbGF0ZWQgQVBJIGVuZHBvaW50cyBhcmUgZGlzYWJsZWQsIGFuZCB0aGUgVUkgaXMgaW5hY2Nlc3NpYmxlLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogZmFsc2UsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5HRU5FUkFMLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiBmYWxzZSxcbiAgICByZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybTogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzd2l0Y2g6IHtcbiAgICAgICAgdmFsdWVzOiB7XG4gICAgICAgICAgZGlzYWJsZWQ6IHsgbGFiZWw6ICdmYWxzZScsIHZhbHVlOiBmYWxzZSB9LFxuICAgICAgICAgIGVuYWJsZWQ6IHsgbGFiZWw6ICd0cnVlJywgdmFsdWU6IHRydWUgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcsXG4gICAgKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuICB9LFxuICAnY3Jvbi5wcmVmaXgnOiB7XG4gICAgdGl0bGU6ICdDcm9uIHByZWZpeCcsXG4gICAgZGVzY3JpcHRpb246ICdEZWZpbmUgdGhlIGluZGV4IHByZWZpeCBvZiBwcmVkZWZpbmVkIGpvYnMuJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuR0VORVJBTCxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUudGV4dCxcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9QUkVGSVgsXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgIH0sXG4gICAgLy8gVmFsaWRhdGlvbjogaHR0cHM6Ly9naXRodWIuY29tL2VsYXN0aWMvZWxhc3RpY3NlYXJjaC9ibG9iL3Y3LjEwLjIvZG9jcy9yZWZlcmVuY2UvaW5kaWNlcy9jcmVhdGUtaW5kZXguYXNjaWlkb2NcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzU3RyaW5nLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNOb3RFbXB0eVN0cmluZyxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmhhc05vU3BhY2VzLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3Iubm9TdGFydHNXaXRoU3RyaW5nKCctJywgJ18nLCAnKycsICcuJyksXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb3RJbnZhbGlkQ2hhcmFjdGVycyhcbiAgICAgICAgJ1xcXFwnLFxuICAgICAgICAnLycsXG4gICAgICAgICc/JyxcbiAgICAgICAgJ1wiJyxcbiAgICAgICAgJzwnLFxuICAgICAgICAnPicsXG4gICAgICAgICd8JyxcbiAgICAgICAgJywnLFxuICAgICAgICAnIycsXG4gICAgICAgICcqJyxcbiAgICAgICksXG4gICAgKSxcbiAgfSxcbiAgJ2Nyb24uc3RhdGlzdGljcy5hcGlzJzoge1xuICAgIHRpdGxlOiAnSW5jbHVkZXMgQVBJcycsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnRW50ZXIgdGhlIElEIG9mIHRoZSBob3N0cyB5b3Ugd2FudCB0byBzYXZlIGRhdGEgZnJvbSwgbGVhdmUgdGhpcyBlbXB0eSB0byBydW4gdGhlIHRhc2sgb24gZXZlcnkgaG9zdC4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5TVEFUSVNUSUNTLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5lZGl0b3IsXG4gICAgZGVmYXVsdFZhbHVlOiBbXSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBlZGl0b3I6IHtcbiAgICAgICAgbGFuZ3VhZ2U6ICdqc29uJyxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1Db25maWd1cmF0aW9uVmFsdWVUb0lucHV0VmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogYW55KTogYW55IHtcbiAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh2YWx1ZSk7XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWU6IGZ1bmN0aW9uIChcbiAgICAgIHZhbHVlOiBzdHJpbmcsXG4gICAgKTogYW55IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIHJldHVybiBKU09OLnBhcnNlKHZhbHVlKTtcbiAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIHJldHVybiB2YWx1ZTtcbiAgICAgIH1cbiAgICB9LFxuICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5qc29uKHRoaXMudmFsaWRhdGUpKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuYXJyYXkoXG4gICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG4gICAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNTdHJpbmcsXG4gICAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNOb3RFbXB0eVN0cmluZyxcbiAgICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb1NwYWNlcyxcbiAgICAgICAgKSxcbiAgICAgICksXG4gICAgKSxcbiAgfSxcbiAgJ2Nyb24uc3RhdGlzdGljcy5pbmRleC5jcmVhdGlvbic6IHtcbiAgICB0aXRsZTogJ0luZGV4IGNyZWF0aW9uJyxcbiAgICBkZXNjcmlwdGlvbjogJ0RlZmluZSB0aGUgaW50ZXJ2YWwgaW4gd2hpY2ggYSBuZXcgaW5kZXggd2lsbCBiZSBjcmVhdGVkLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LlNUQVRJU1RJQ1MsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnNlbGVjdCxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzZWxlY3Q6IFtcbiAgICAgICAge1xuICAgICAgICAgIHRleHQ6ICdIb3VybHknLFxuICAgICAgICAgIHZhbHVlOiAnaCcsXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiAnRGFpbHknLFxuICAgICAgICAgIHZhbHVlOiAnZCcsXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiAnV2Vla2x5JyxcbiAgICAgICAgICB2YWx1ZTogJ3cnLFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogJ01vbnRobHknLFxuICAgICAgICAgIHZhbHVlOiAnbScsXG4gICAgICAgIH0sXG4gICAgICBdLFxuICAgIH0sXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfQ1JFQVRJT04sXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIFNldHRpbmdzVmFsaWRhdG9yLmxpdGVyYWwoXG4gICAgICAgIHRoaXMub3B0aW9ucy5zZWxlY3QubWFwKCh7IHZhbHVlIH0pID0+IHZhbHVlKSxcbiAgICAgICkodmFsdWUpO1xuICAgIH0sXG4gIH0sXG4gICdjcm9uLnN0YXRpc3RpY3MuaW5kZXgubmFtZSc6IHtcbiAgICB0aXRsZTogJ0luZGV4IG5hbWUnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ0RlZmluZSB0aGUgbmFtZSBvZiB0aGUgaW5kZXggaW4gd2hpY2ggdGhlIGRvY3VtZW50cyB3aWxsIGJlIHNhdmVkLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LlNUQVRJU1RJQ1MsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnRleHQsXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfTkFNRSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICByZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjazogdHJ1ZSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICAvLyBWYWxpZGF0aW9uOiBodHRwczovL2dpdGh1Yi5jb20vZWxhc3RpYy9lbGFzdGljc2VhcmNoL2Jsb2IvdjcuMTAuMi9kb2NzL3JlZmVyZW5jZS9pbmRpY2VzL2NyZWF0ZS1pbmRleC5hc2NpaWRvY1xuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNTdHJpbmcsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc05vdEVtcHR5U3RyaW5nLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm9TcGFjZXMsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5ub1N0YXJ0c1dpdGhTdHJpbmcoJy0nLCAnXycsICcrJywgJy4nKSxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmhhc05vdEludmFsaWRDaGFyYWN0ZXJzKFxuICAgICAgICAnXFxcXCcsXG4gICAgICAgICcvJyxcbiAgICAgICAgJz8nLFxuICAgICAgICAnXCInLFxuICAgICAgICAnPCcsXG4gICAgICAgICc+JyxcbiAgICAgICAgJ3wnLFxuICAgICAgICAnLCcsXG4gICAgICAgICcjJyxcbiAgICAgICAgJyonLFxuICAgICAgKSxcbiAgICApLFxuICB9LFxuICAnY3Jvbi5zdGF0aXN0aWNzLmluZGV4LnJlcGxpY2FzJzoge1xuICAgIHRpdGxlOiAnSW5kZXggcmVwbGljYXMnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ0RlZmluZSB0aGUgbnVtYmVyIG9mIHJlcGxpY2FzIHRvIHVzZSBmb3IgdGhlIHN0YXRpc3RpY3MgaW5kaWNlcy4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5TVEFUSVNUSUNTLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5udW1iZXIsXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfSU5ESUNFU19SRVBMSUNBUyxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICByZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjazogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBudW1iZXI6IHtcbiAgICAgICAgbWluOiAwLFxuICAgICAgICBpbnRlZ2VyOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNvbmZpZ3VyYXRpb25WYWx1ZVRvSW5wdXRWYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IG51bWJlcixcbiAgICApOiBzdHJpbmcge1xuICAgICAgcmV0dXJuIFN0cmluZyh2YWx1ZSk7XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWU6IGZ1bmN0aW9uIChcbiAgICAgIHZhbHVlOiBzdHJpbmcsXG4gICAgKTogbnVtYmVyIHtcbiAgICAgIHJldHVybiBOdW1iZXIodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUoXG4gICAgICAgIHRoaXMudWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlKHZhbHVlKSxcbiAgICAgICk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gU2V0dGluZ3NWYWxpZGF0b3IubnVtYmVyKHRoaXMub3B0aW9ucy5udW1iZXIpKHZhbHVlKTtcbiAgICB9LFxuICB9LFxuICAnY3Jvbi5zdGF0aXN0aWNzLmluZGV4LnNoYXJkcyc6IHtcbiAgICB0aXRsZTogJ0luZGV4IHNoYXJkcycsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnRGVmaW5lIHRoZSBudW1iZXIgb2Ygc2hhcmRzIHRvIHVzZSBmb3IgdGhlIHN0YXRpc3RpY3MgaW5kaWNlcy4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5TVEFUSVNUSUNTLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5udW1iZXIsXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfSU5ESUNFU19TSEFSRFMsXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgbnVtYmVyOiB7XG4gICAgICAgIG1pbjogMSxcbiAgICAgICAgaW50ZWdlcjogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1Db25maWd1cmF0aW9uVmFsdWVUb0lucHV0VmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogbnVtYmVyKSB7XG4gICAgICByZXR1cm4gU3RyaW5nKHZhbHVlKTtcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUlucHV0VmFsdWVUb0NvbmZpZ3VyYXRpb25WYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IHN0cmluZyxcbiAgICApOiBudW1iZXIge1xuICAgICAgcmV0dXJuIE51bWJlcih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZShcbiAgICAgICAgdGhpcy51aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWUodmFsdWUpLFxuICAgICAgKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5udW1iZXIodGhpcy5vcHRpb25zLm51bWJlcikodmFsdWUpO1xuICAgIH0sXG4gIH0sXG4gICdjcm9uLnN0YXRpc3RpY3MuaW50ZXJ2YWwnOiB7XG4gICAgdGl0bGU6ICdJbnRlcnZhbCcsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnRGVmaW5lIHRoZSBmcmVxdWVuY3kgb2YgdGFzayBleGVjdXRpb24gdXNpbmcgY3JvbiBzY2hlZHVsZSBleHByZXNzaW9ucy4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5TVEFUSVNUSUNTLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS50ZXh0LFxuICAgIGRlZmF1bHRWYWx1ZTogV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX0NST05fRlJFUSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICByZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybTogdHJ1ZSxcbiAgICAvLyBXb3JrYXJvdW5kOiB0aGlzIG5lZWQgdG8gYmUgZGVmaW5lZCBpbiB0aGUgZnJvbnRlbmQgc2lkZSBhbmQgYmFja2VuZCBzaWRlIGJlY2F1c2UgYW4gb3B0aW1pemF0aW9uIGVycm9yIGluIHRoZSBmcm9udGVuZCBzaWRlIHJlbGF0ZWQgdG8gc29tZSBtb2R1bGUgY2FuIG5vdCBiZSBsb2FkZWQuXG4gICAgLy8gdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgIC8vIH0sXG4gICAgLy8gdmFsaWRhdGU6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgIC8vIH0sXG4gIH0sXG4gICdjcm9uLnN0YXRpc3RpY3Muc3RhdHVzJzoge1xuICAgIHRpdGxlOiAnU3RhdHVzJyxcbiAgICBkZXNjcmlwdGlvbjogJ0VuYWJsZSBvciBkaXNhYmxlIHRoZSBzdGF0aXN0aWNzIHRhc2tzLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LlNUQVRJU1RJQ1MsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9TVEFUVVMsXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ2hhbmdlZElucHV0VmFsdWU6IGZ1bmN0aW9uIChcbiAgICAgIHZhbHVlOiBib29sZWFuIHwgc3RyaW5nLFxuICAgICk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIEJvb2xlYW4odmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcbiAgfSxcbiAgJ2N1c3RvbWl6YXRpb24uZW5hYmxlZCc6IHtcbiAgICB0aXRsZTogJ1N0YXR1cycsXG4gICAgZGVzY3JpcHRpb246ICdFbmFibGUgb3IgZGlzYWJsZSB0aGUgY3VzdG9taXphdGlvbi4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5DVVNUT01JWkFUSU9OLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIHJlcXVpcmVzUmVsb2FkaW5nQnJvd3NlclRhYjogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzd2l0Y2g6IHtcbiAgICAgICAgdmFsdWVzOiB7XG4gICAgICAgICAgZGlzYWJsZWQ6IHsgbGFiZWw6ICdmYWxzZScsIHZhbHVlOiBmYWxzZSB9LFxuICAgICAgICAgIGVuYWJsZWQ6IHsgbGFiZWw6ICd0cnVlJywgdmFsdWU6IHRydWUgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcsXG4gICAgKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuICB9LFxuICAnY3VzdG9taXphdGlvbi5sb2dvLmFwcCc6IHtcbiAgICB0aXRsZTogJ0FwcCBtYWluIGxvZ28nLFxuICAgIGRlc2NyaXB0aW9uOiBgVGhpcyBsb2dvIGlzIHVzZWQgYXMgbG9hZGluZyBpbmRpY2F0b3Igd2hpbGUgdGhlIHVzZXIgaXMgbG9nZ2luZyBpbnRvIFdhenVoIEFQSS5gLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5DVVNUT01JWkFUSU9OLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5maWxlcGlja2VyLFxuICAgIGRlZmF1bHRWYWx1ZTogJycsXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgZmlsZToge1xuICAgICAgICB0eXBlOiAnaW1hZ2UnLFxuICAgICAgICBleHRlbnNpb25zOiBbJy5qcGVnJywgJy5qcGcnLCAnLnBuZycsICcuc3ZnJ10sXG4gICAgICAgIHNpemU6IHtcbiAgICAgICAgICBtYXhCeXRlczpcbiAgICAgICAgICAgIENVU1RPTUlaQVRJT05fRU5EUE9JTlRfUEFZTE9BRF9VUExPQURfQ1VTVE9NX0ZJTEVfTUFYSU1VTV9CWVRFUyxcbiAgICAgICAgfSxcbiAgICAgICAgcmVjb21tZW5kZWQ6IHtcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB3aWR0aDogMzAwLFxuICAgICAgICAgICAgaGVpZ2h0OiA3MCxcbiAgICAgICAgICAgIHVuaXQ6ICdweCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgc3RvcmU6IHtcbiAgICAgICAgICByZWxhdGl2ZVBhdGhGaWxlU3lzdGVtOiAncHVibGljL2Fzc2V0cy9jdXN0b20vaW1hZ2VzJyxcbiAgICAgICAgICBmaWxlbmFtZTogJ2N1c3RvbWl6YXRpb24ubG9nby5hcHAnLFxuICAgICAgICAgIHJlc29sdmVTdGF0aWNVUkw6IChmaWxlbmFtZTogc3RyaW5nKSA9PlxuICAgICAgICAgICAgYGN1c3RvbS9pbWFnZXMvJHtmaWxlbmFtZX0/dj0ke0RhdGUubm93KCl9YCxcbiAgICAgICAgICAvLyA/dj0ke0RhdGUubm93KCl9IGlzIHVzZWQgdG8gZm9yY2UgdGhlIGJyb3dzZXIgdG8gcmVsb2FkIHRoZSBpbWFnZSB3aGVuIGEgbmV3IGZpbGUgaXMgdXBsb2FkZWRcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuZmlsZVBpY2tlckZpbGVTaXplKHtcbiAgICAgICAgICAuLi50aGlzLm9wdGlvbnMuZmlsZS5zaXplLFxuICAgICAgICAgIG1lYW5pbmdmdWxVbml0OiB0cnVlLFxuICAgICAgICB9KSxcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuZmlsZVBpY2tlclN1cHBvcnRlZEV4dGVuc2lvbnMoXG4gICAgICAgICAgdGhpcy5vcHRpb25zLmZpbGUuZXh0ZW5zaW9ucyxcbiAgICAgICAgKSxcbiAgICAgICkodmFsdWUpO1xuICAgIH0sXG4gIH0sXG4gICdjdXN0b21pemF0aW9uLmxvZ28uaGVhbHRoY2hlY2snOiB7XG4gICAgdGl0bGU6ICdIZWFsdGhjaGVjayBsb2dvJyxcbiAgICBkZXNjcmlwdGlvbjogYFRoaXMgbG9nbyBpcyBkaXNwbGF5ZWQgZHVyaW5nIHRoZSBIZWFsdGhjaGVjayByb3V0aW5lIG9mIHRoZSBhcHAuYCxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuQ1VTVE9NSVpBVElPTixcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuZmlsZXBpY2tlcixcbiAgICBkZWZhdWx0VmFsdWU6ICcnLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgdHlwZTogJ2ltYWdlJyxcbiAgICAgICAgZXh0ZW5zaW9uczogWycuanBlZycsICcuanBnJywgJy5wbmcnLCAnLnN2ZyddLFxuICAgICAgICBzaXplOiB7XG4gICAgICAgICAgbWF4Qnl0ZXM6XG4gICAgICAgICAgICBDVVNUT01JWkFUSU9OX0VORFBPSU5UX1BBWUxPQURfVVBMT0FEX0NVU1RPTV9GSUxFX01BWElNVU1fQllURVMsXG4gICAgICAgIH0sXG4gICAgICAgIHJlY29tbWVuZGVkOiB7XG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgd2lkdGg6IDMwMCxcbiAgICAgICAgICAgIGhlaWdodDogNzAsXG4gICAgICAgICAgICB1bml0OiAncHgnLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIHN0b3JlOiB7XG4gICAgICAgICAgcmVsYXRpdmVQYXRoRmlsZVN5c3RlbTogJ3B1YmxpYy9hc3NldHMvY3VzdG9tL2ltYWdlcycsXG4gICAgICAgICAgZmlsZW5hbWU6ICdjdXN0b21pemF0aW9uLmxvZ28uaGVhbHRoY2hlY2snLFxuICAgICAgICAgIHJlc29sdmVTdGF0aWNVUkw6IChmaWxlbmFtZTogc3RyaW5nKSA9PlxuICAgICAgICAgICAgYGN1c3RvbS9pbWFnZXMvJHtmaWxlbmFtZX0/dj0ke0RhdGUubm93KCl9YCxcbiAgICAgICAgICAvLyA/dj0ke0RhdGUubm93KCl9IGlzIHVzZWQgdG8gZm9yY2UgdGhlIGJyb3dzZXIgdG8gcmVsb2FkIHRoZSBpbWFnZSB3aGVuIGEgbmV3IGZpbGUgaXMgdXBsb2FkZWRcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuZmlsZVBpY2tlckZpbGVTaXplKHtcbiAgICAgICAgICAuLi50aGlzLm9wdGlvbnMuZmlsZS5zaXplLFxuICAgICAgICAgIG1lYW5pbmdmdWxVbml0OiB0cnVlLFxuICAgICAgICB9KSxcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuZmlsZVBpY2tlclN1cHBvcnRlZEV4dGVuc2lvbnMoXG4gICAgICAgICAgdGhpcy5vcHRpb25zLmZpbGUuZXh0ZW5zaW9ucyxcbiAgICAgICAgKSxcbiAgICAgICkodmFsdWUpO1xuICAgIH0sXG4gIH0sXG4gICdjdXN0b21pemF0aW9uLmxvZ28ucmVwb3J0cyc6IHtcbiAgICB0aXRsZTogJ1BERiByZXBvcnRzIGxvZ28nLFxuICAgIGRlc2NyaXB0aW9uOiBgVGhpcyBsb2dvIGlzIHVzZWQgaW4gdGhlIFBERiByZXBvcnRzIGdlbmVyYXRlZCBieSB0aGUgYXBwLiBJdCdzIHBsYWNlZCBhdCB0aGUgdG9wIGxlZnQgY29ybmVyIG9mIGV2ZXJ5IHBhZ2Ugb2YgdGhlIFBERi5gLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5DVVNUT01JWkFUSU9OLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5maWxlcGlja2VyLFxuICAgIGRlZmF1bHRWYWx1ZTogJycsXG4gICAgZGVmYXVsdFZhbHVlSWZOb3RTZXQ6IFJFUE9SVFNfTE9HT19JTUFHRV9BU1NFVFNfUkVMQVRJVkVfUEFUSCxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIHR5cGU6ICdpbWFnZScsXG4gICAgICAgIGV4dGVuc2lvbnM6IFsnLmpwZWcnLCAnLmpwZycsICcucG5nJ10sXG4gICAgICAgIHNpemU6IHtcbiAgICAgICAgICBtYXhCeXRlczpcbiAgICAgICAgICAgIENVU1RPTUlaQVRJT05fRU5EUE9JTlRfUEFZTE9BRF9VUExPQURfQ1VTVE9NX0ZJTEVfTUFYSU1VTV9CWVRFUyxcbiAgICAgICAgfSxcbiAgICAgICAgcmVjb21tZW5kZWQ6IHtcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB3aWR0aDogMTkwLFxuICAgICAgICAgICAgaGVpZ2h0OiA0MCxcbiAgICAgICAgICAgIHVuaXQ6ICdweCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgc3RvcmU6IHtcbiAgICAgICAgICByZWxhdGl2ZVBhdGhGaWxlU3lzdGVtOiAncHVibGljL2Fzc2V0cy9jdXN0b20vaW1hZ2VzJyxcbiAgICAgICAgICBmaWxlbmFtZTogJ2N1c3RvbWl6YXRpb24ubG9nby5yZXBvcnRzJyxcbiAgICAgICAgICByZXNvbHZlU3RhdGljVVJMOiAoZmlsZW5hbWU6IHN0cmluZykgPT4gYGN1c3RvbS9pbWFnZXMvJHtmaWxlbmFtZX1gLFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9LFxuICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5maWxlUGlja2VyRmlsZVNpemUoe1xuICAgICAgICAgIC4uLnRoaXMub3B0aW9ucy5maWxlLnNpemUsXG4gICAgICAgICAgbWVhbmluZ2Z1bFVuaXQ6IHRydWUsXG4gICAgICAgIH0pLFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5maWxlUGlja2VyU3VwcG9ydGVkRXh0ZW5zaW9ucyhcbiAgICAgICAgICB0aGlzLm9wdGlvbnMuZmlsZS5leHRlbnNpb25zLFxuICAgICAgICApLFxuICAgICAgKSh2YWx1ZSk7XG4gICAgfSxcbiAgfSxcbiAgJ2N1c3RvbWl6YXRpb24ucmVwb3J0cy5mb290ZXInOiB7XG4gICAgdGl0bGU6ICdSZXBvcnRzIGZvb3RlcicsXG4gICAgZGVzY3JpcHRpb246ICdTZXQgdGhlIGZvb3RlciBvZiB0aGUgcmVwb3J0cy4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5DVVNUT01JWkFUSU9OLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS50ZXh0YXJlYSxcbiAgICBkZWZhdWx0VmFsdWU6ICcnLFxuICAgIGRlZmF1bHRWYWx1ZUlmTm90U2V0OiBSRVBPUlRTX1BBR0VfRk9PVEVSX1RFWFQsXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgb3B0aW9uczogeyBtYXhSb3dzOiAyLCBtYXhMZW5ndGg6IDUwIH0sXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG4gICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzU3RyaW5nLFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5tdWx0aXBsZUxpbmVzU3RyaW5nKHtcbiAgICAgICAgICBtYXhSb3dzOiB0aGlzLm9wdGlvbnM/Lm1heFJvd3MsXG4gICAgICAgICAgbWF4TGVuZ3RoOiB0aGlzLm9wdGlvbnM/Lm1heExlbmd0aCxcbiAgICAgICAgfSksXG4gICAgICApKHZhbHVlKTtcbiAgICB9LFxuICB9LFxuICAnY3VzdG9taXphdGlvbi5yZXBvcnRzLmhlYWRlcic6IHtcbiAgICB0aXRsZTogJ1JlcG9ydHMgaGVhZGVyJyxcbiAgICBkZXNjcmlwdGlvbjogJ1NldCB0aGUgaGVhZGVyIG9mIHRoZSByZXBvcnRzLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkNVU1RPTUlaQVRJT04sXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnRleHRhcmVhLFxuICAgIGRlZmF1bHRWYWx1ZTogJycsXG4gICAgZGVmYXVsdFZhbHVlSWZOb3RTZXQ6IFJFUE9SVFNfUEFHRV9IRUFERVJfVEVYVCxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICBvcHRpb25zOiB7IG1heFJvd3M6IDMsIG1heExlbmd0aDogNDAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNTdHJpbmcsXG4gICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLm11bHRpcGxlTGluZXNTdHJpbmcoe1xuICAgICAgICAgIG1heFJvd3M6IHRoaXMub3B0aW9ucz8ubWF4Um93cyxcbiAgICAgICAgICBtYXhMZW5ndGg6IHRoaXMub3B0aW9ucz8ubWF4TGVuZ3RoLFxuICAgICAgICB9KSxcbiAgICAgICkodmFsdWUpO1xuICAgIH0sXG4gIH0sXG4gICdlbnJvbGxtZW50LmRucyc6IHtcbiAgICB0aXRsZTogJ0Vucm9sbG1lbnQgRE5TJyxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdTcGVjaWZpZXMgdGhlIFdhenVoIHJlZ2lzdHJhdGlvbiBzZXJ2ZXIsIHVzZWQgZm9yIHRoZSBhZ2VudCBlbnJvbGxtZW50LicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnRleHQsXG4gICAgZGVmYXVsdFZhbHVlOiAnJyxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzU3RyaW5nLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3Iuc2VydmVyQWRkcmVzc0hvc3RuYW1lRlFETklQdjRJUHY2LFxuICAgICksXG4gIH0sXG4gICdlbnJvbGxtZW50LnBhc3N3b3JkJzoge1xuICAgIHRpdGxlOiAnRW5yb2xsbWVudCBwYXNzd29yZCcsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnU3BlY2lmaWVzIHRoZSBwYXNzd29yZCB1c2VkIHRvIGF1dGhlbnRpY2F0ZSBkdXJpbmcgdGhlIGFnZW50IGVucm9sbG1lbnQuJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuR0VORVJBTCxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUudGV4dCxcbiAgICBkZWZhdWx0VmFsdWU6ICcnLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiBmYWxzZSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzU3RyaW5nLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNOb3RFbXB0eVN0cmluZyxcbiAgICApLFxuICB9LFxuICBoaWRlTWFuYWdlckFsZXJ0czoge1xuICAgIHRpdGxlOiAnSGlkZSBtYW5hZ2VyIGFsZXJ0cycsXG4gICAgZGVzY3JpcHRpb246ICdIaWRlIHRoZSBhbGVydHMgb2YgdGhlIG1hbmFnZXIgaW4gZXZlcnkgZGFzaGJvYXJkLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IGZhbHNlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIHJlcXVpcmVzUmVsb2FkaW5nQnJvd3NlclRhYjogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzd2l0Y2g6IHtcbiAgICAgICAgdmFsdWVzOiB7XG4gICAgICAgICAgZGlzYWJsZWQ6IHsgbGFiZWw6ICdmYWxzZScsIHZhbHVlOiBmYWxzZSB9LFxuICAgICAgICAgIGVuYWJsZWQ6IHsgbGFiZWw6ICd0cnVlJywgdmFsdWU6IHRydWUgfSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcsXG4gICAgKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuICB9LFxuICBob3N0czoge1xuICAgIHRpdGxlOiAnU2VydmVyIGhvc3RzJyxcbiAgICBkZXNjcmlwdGlvbjogJ0NvbmZpZ3VyZSB0aGUgQVBJIGNvbm5lY3Rpb25zLicsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5BUElfQ09OTkVDVElPTixcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuYXJyYXlPZixcbiAgICBkZWZhdWx0VmFsdWU6IFtdLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IGZhbHNlLFxuICAgICAgICBkZWZhdWx0QmxvY2s6IGAjIFRoZSBmb2xsb3dpbmcgY29uZmlndXJhdGlvbiBpcyB0aGUgZGVmYXVsdCBzdHJ1Y3R1cmUgdG8gZGVmaW5lIGEgaG9zdC5cbiNcbiMgaG9zdHM6XG4jICAgIyBIb3N0IElEIC8gbmFtZSxcbiMgICAtIGVudi0xOlxuIyAgICAgICAjIEhvc3QgVVJMXG4jICAgICAgIHVybDogaHR0cHM6Ly9lbnYtMS5leGFtcGxlXG4jICAgICAgICMgSG9zdCAvIEFQSSBwb3J0XG4jICAgICAgIHBvcnQ6IDU1MDAwXG4jICAgICAgICMgSG9zdCAvIEFQSSB1c2VybmFtZVxuIyAgICAgICB1c2VybmFtZTogd2F6dWgtd3VpXG4jICAgICAgICMgSG9zdCAvIEFQSSBwYXNzd29yZFxuIyAgICAgICBwYXNzd29yZDogd2F6dWgtd3VpXG4jICAgICAgICMgVXNlIFJCQUMgb3Igbm90LiBJZiBzZXQgdG8gdHJ1ZSwgdGhlIHVzZXJuYW1lIG11c3QgYmUgXCJ3YXp1aC13dWlcIi5cbiMgICAgICAgcnVuX2FzOiB0cnVlXG4jICAgLSBlbnYtMjpcbiMgICAgICAgdXJsOiBodHRwczovL2Vudi0yLmV4YW1wbGVcbiMgICAgICAgcG9ydDogNTUwMDBcbiMgICAgICAgdXNlcm5hbWU6IHdhenVoLXd1aVxuIyAgICAgICBwYXNzd29yZDogd2F6dWgtd3VpXG4jICAgICAgIHJ1bl9hczogdHJ1ZVxuXG5ob3N0czpcbiAgLSBkZWZhdWx0OlxuICAgICAgdXJsOiBodHRwczovL2xvY2FsaG9zdFxuICAgICAgcG9ydDogNTUwMDBcbiAgICAgIHVzZXJuYW1lOiB3YXp1aC13dWlcbiAgICAgIHBhc3N3b3JkOiB3YXp1aC13dWlcbiAgICAgIHJ1bl9hczogZmFsc2VgLFxuICAgICAgICB0cmFuc2Zvcm1Gcm9tOiB2YWx1ZSA9PiB7XG4gICAgICAgICAgcmV0dXJuIHZhbHVlLm1hcChob3N0RGF0YSA9PiB7XG4gICAgICAgICAgICBjb25zdCBrZXkgPSBPYmplY3Qua2V5cyhob3N0RGF0YSk/LlswXTtcbiAgICAgICAgICAgIHJldHVybiB7IC4uLmhvc3REYXRhW2tleV0sIGlkOiBrZXkgfTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBhcnJheU9mOiB7XG4gICAgICAgIGlkOiB7XG4gICAgICAgICAgdGl0bGU6ICdJZGVudGlmaWVyJyxcbiAgICAgICAgICBkZXNjcmlwdGlvbjogJ0lkZW50aWZpZXIgb2YgdGhlIEFQSSBjb25uZWN0aW9uLiBUaGlzIG11c3QgYmUgdW5pcXVlLicsXG4gICAgICAgICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnRleHQsXG4gICAgICAgICAgZGVmYXVsdFZhbHVlOiAnZGVmYXVsdCcsXG4gICAgICAgICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgICAgICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG4gICAgICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc1N0cmluZyxcbiAgICAgICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzTm90RW1wdHlTdHJpbmcsXG4gICAgICAgICAgKSxcbiAgICAgICAgfSxcbiAgICAgICAgdXJsOiB7XG4gICAgICAgICAgdGl0bGU6ICdVUkwnLFxuICAgICAgICAgIGRlc2NyaXB0aW9uOiAnU2VydmVyIFVSTCBhZGRyZXNzJyxcbiAgICAgICAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUudGV4dCxcbiAgICAgICAgICBkZWZhdWx0VmFsdWU6ICdodHRwczovL2xvY2FsaG9zdCcsXG4gICAgICAgICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgICAgICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG4gICAgICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc1N0cmluZyxcbiAgICAgICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzTm90RW1wdHlTdHJpbmcsXG4gICAgICAgICAgKSxcbiAgICAgICAgfSxcbiAgICAgICAgcG9ydDoge1xuICAgICAgICAgIHRpdGxlOiAnUG9ydCcsXG4gICAgICAgICAgZGVzY3JpcHRpb246ICdQb3J0JyxcbiAgICAgICAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUubnVtYmVyLFxuICAgICAgICAgIGRlZmF1bHRWYWx1ZTogNTUwMDAsXG4gICAgICAgICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgICAgICAgb3B0aW9uczoge1xuICAgICAgICAgICAgbnVtYmVyOiB7XG4gICAgICAgICAgICAgIG1pbjogMCxcbiAgICAgICAgICAgICAgbWF4OiA2NTUzNSxcbiAgICAgICAgICAgICAgaW50ZWdlcjogdHJ1ZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB1aUZvcm1UcmFuc2Zvcm1Db25maWd1cmF0aW9uVmFsdWVUb0lucHV0VmFsdWU6IGZ1bmN0aW9uIChcbiAgICAgICAgICAgIHZhbHVlOiBudW1iZXIsXG4gICAgICAgICAgKSB7XG4gICAgICAgICAgICByZXR1cm4gU3RyaW5nKHZhbHVlKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIHVpRm9ybVRyYW5zZm9ybUlucHV0VmFsdWVUb0NvbmZpZ3VyYXRpb25WYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgICAgICAgdmFsdWU6IHN0cmluZyxcbiAgICAgICAgICApOiBudW1iZXIge1xuICAgICAgICAgICAgcmV0dXJuIE51bWJlcih2YWx1ZSk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZShcbiAgICAgICAgICAgICAgdGhpcy51aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWUodmFsdWUpLFxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIHZhbGlkYXRlOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgICAgIHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5udW1iZXIodGhpcy5vcHRpb25zLm51bWJlcikodmFsdWUpO1xuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIHVzZXJuYW1lOiB7XG4gICAgICAgICAgdGl0bGU6ICdVc2VybmFtZScsXG4gICAgICAgICAgZGVzY3JpcHRpb246ICdTZXJ2ZXIgQVBJIHVzZXJuYW1lJyxcbiAgICAgICAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUudGV4dCxcbiAgICAgICAgICBkZWZhdWx0VmFsdWU6ICd3YXp1aC13dWknLFxuICAgICAgICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgICAgICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlKHZhbHVlKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNTdHJpbmcsXG4gICAgICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc05vdEVtcHR5U3RyaW5nLFxuICAgICAgICAgICksXG4gICAgICAgIH0sXG4gICAgICAgIHBhc3N3b3JkOiB7XG4gICAgICAgICAgdGl0bGU6ICdQYXNzd29yZCcsXG4gICAgICAgICAgZGVzY3JpcHRpb246IFwiVXNlcidzIFBhc3N3b3JkXCIsXG4gICAgICAgICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnBhc3N3b3JkLFxuICAgICAgICAgIGRlZmF1bHRWYWx1ZTogJ3dhenVoLXd1aScsXG4gICAgICAgICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgICAgICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG4gICAgICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc1N0cmluZyxcbiAgICAgICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzTm90RW1wdHlTdHJpbmcsXG4gICAgICAgICAgKSxcbiAgICAgICAgfSxcbiAgICAgICAgcnVuX2FzOiB7XG4gICAgICAgICAgdGl0bGU6ICdSdW4gYXMnLFxuICAgICAgICAgIGRlc2NyaXB0aW9uOiAnVXNlIHRoZSBhdXRoZW50aWNhdGlvbiBjb250ZXh0LicsXG4gICAgICAgICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICAgICAgICBkZWZhdWx0VmFsdWU6IGZhbHNlLFxuICAgICAgICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgICAgICAgIG9wdGlvbnM6IHtcbiAgICAgICAgICAgIHN3aXRjaDoge1xuICAgICAgICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAoXG4gICAgICAgICAgICB2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyxcbiAgICAgICAgICApOiBib29sZWFuIHtcbiAgICAgICAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlKHZhbHVlKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0sXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IGZhbHNlLFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAoXG4gICAgICB2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyxcbiAgICApOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIC8vIFRPRE86IGFkZCB2YWxpZGF0aW9uXG4gICAgLy8gdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcbiAgICAvLyB2YWxpZGF0ZTogZnVuY3Rpb24gKHNjaGVtYSkge1xuICAgIC8vICAgcmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG4gICAgLy8gfSxcbiAgfSxcbiAgJ2lwLmlnbm9yZSc6IHtcbiAgICB0aXRsZTogJ0luZGV4IHBhdHRlcm4gaWdub3JlJyxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdEaXNhYmxlIGNlcnRhaW4gaW5kZXggcGF0dGVybiBuYW1lcyBmcm9tIGJlaW5nIGF2YWlsYWJsZSBpbiBpbmRleCBwYXR0ZXJuIHNlbGVjdG9yLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLmVkaXRvcixcbiAgICBkZWZhdWx0VmFsdWU6IFtdLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIGVkaXRvcjoge1xuICAgICAgICBsYW5ndWFnZTogJ2pzb24nLFxuICAgICAgfSxcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNvbmZpZ3VyYXRpb25WYWx1ZVRvSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBhbnkpOiBhbnkge1xuICAgICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHZhbHVlKTtcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUlucHV0VmFsdWVUb0NvbmZpZ3VyYXRpb25WYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IHN0cmluZyxcbiAgICApOiBhbnkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIEpTT04ucGFyc2UodmFsdWUpO1xuICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgcmV0dXJuIHZhbHVlO1xuICAgICAgfVxuICAgIH0sXG4gICAgLy8gVmFsaWRhdGlvbjogaHR0cHM6Ly9naXRodWIuY29tL2VsYXN0aWMvZWxhc3RpY3NlYXJjaC9ibG9iL3Y3LjEwLjIvZG9jcy9yZWZlcmVuY2UvaW5kaWNlcy9jcmVhdGUtaW5kZXguYXNjaWlkb2NcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gU2V0dGluZ3NWYWxpZGF0b3IuanNvbih0aGlzLnZhbGlkYXRlKSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmFycmF5KFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzU3RyaW5nLFxuICAgICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzTm90RW1wdHlTdHJpbmcsXG4gICAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm9TcGFjZXMsXG4gICAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3Iubm9MaXRlcmFsU3RyaW5nKCcuJywgJy4uJyksXG4gICAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3Iubm9TdGFydHNXaXRoU3RyaW5nKCctJywgJ18nLCAnKycsICcuJyksXG4gICAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm90SW52YWxpZENoYXJhY3RlcnMoXG4gICAgICAgICAgICAnXFxcXCcsXG4gICAgICAgICAgICAnLycsXG4gICAgICAgICAgICAnPycsXG4gICAgICAgICAgICAnXCInLFxuICAgICAgICAgICAgJzwnLFxuICAgICAgICAgICAgJz4nLFxuICAgICAgICAgICAgJ3wnLFxuICAgICAgICAgICAgJywnLFxuICAgICAgICAgICAgJyMnLFxuICAgICAgICAgICksXG4gICAgICAgICksXG4gICAgICApLFxuICAgICksXG4gIH0sXG4gICdpcC5zZWxlY3Rvcic6IHtcbiAgICB0aXRsZTogJ0lQIHNlbGVjdG9yJyxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdEZWZpbmUgaWYgdGhlIHVzZXIgaXMgYWxsb3dlZCB0byBjaGFuZ2UgdGhlIHNlbGVjdGVkIGluZGV4IHBhdHRlcm4gZGlyZWN0bHkgZnJvbSB0aGUgdG9wIG1lbnUgYmFyLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH0sXG4gICAgICB9LFxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ2hhbmdlZElucHV0VmFsdWU6IGZ1bmN0aW9uIChcbiAgICAgIHZhbHVlOiBib29sZWFuIHwgc3RyaW5nLFxuICAgICk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIEJvb2xlYW4odmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcbiAgfSxcbiAgJ3dhenVoLnVwZGF0ZXMuZGlzYWJsZWQnOiB7XG4gICAgdGl0bGU6ICdDaGVjayB1cGRhdGVzJyxcbiAgICBkZXNjcmlwdGlvbjogJ0RlZmluZSBpZiB0aGUgY2hlY2sgdXBkYXRlcyBzZXJ2aWNlIGlzIGRpc2FibGVkLicsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5HRU5FUkFMLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiBmYWxzZSxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAoXG4gICAgICB2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyxcbiAgICApOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG4gIH0sXG4gIHBhdHRlcm46IHtcbiAgICB0aXRsZTogJ0luZGV4IHBhdHRlcm4nLFxuICAgIHN0b3JlOiB7XG4gICAgICBmaWxlOiB7XG4gICAgICAgIGNvbmZpZ3VyYWJsZU1hbmFnZWQ6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgZGVzY3JpcHRpb246XG4gICAgICBcIkRlZmF1bHQgaW5kZXggcGF0dGVybiB0byB1c2Ugb24gdGhlIGFwcC4gSWYgdGhlcmUncyBubyB2YWxpZCBpbmRleCBwYXR0ZXJuLCB0aGUgYXBwIHdpbGwgYXV0b21hdGljYWxseSBjcmVhdGUgb25lIHdpdGggdGhlIG5hbWUgaW5kaWNhdGVkIGluIHRoaXMgb3B0aW9uLlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuR0VORVJBTCxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUudGV4dCxcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX0FMRVJUU19QQVRURVJOLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIHJlcXVpcmVzUnVubmluZ0hlYWx0aENoZWNrOiB0cnVlLFxuICAgIC8vIFZhbGlkYXRpb246IGh0dHBzOi8vZ2l0aHViLmNvbS9lbGFzdGljL2VsYXN0aWNzZWFyY2gvYmxvYi92Ny4xMC4yL2RvY3MvcmVmZXJlbmNlL2luZGljZXMvY3JlYXRlLWluZGV4LmFzY2lpZG9jXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc1N0cmluZyxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzTm90RW1wdHlTdHJpbmcsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb1NwYWNlcyxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLm5vTGl0ZXJhbFN0cmluZygnLicsICcuLicpLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3Iubm9TdGFydHNXaXRoU3RyaW5nKCctJywgJ18nLCAnKycsICcuJyksXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb3RJbnZhbGlkQ2hhcmFjdGVycyhcbiAgICAgICAgJ1xcXFwnLFxuICAgICAgICAnLycsXG4gICAgICAgICc/JyxcbiAgICAgICAgJ1wiJyxcbiAgICAgICAgJzwnLFxuICAgICAgICAnPicsXG4gICAgICAgICd8JyxcbiAgICAgICAgJywnLFxuICAgICAgICAnIycsXG4gICAgICApLFxuICAgICksXG4gIH0sXG4gIHRpbWVvdXQ6IHtcbiAgICB0aXRsZTogJ1JlcXVlc3QgdGltZW91dCcsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdNYXhpbXVtIHRpbWUsIGluIG1pbGxpc2Vjb25kcywgdGhlIGFwcCB3aWxsIHdhaXQgZm9yIGFuIEFQSSByZXNwb25zZSB3aGVuIG1ha2luZyByZXF1ZXN0cyB0byBpdC4gSXQgd2lsbCBiZSBpZ25vcmVkIGlmIHRoZSB2YWx1ZSBpcyBzZXQgdW5kZXIgMTUwMCBtaWxsaXNlY29uZHMuJyxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLm51bWJlcixcbiAgICBkZWZhdWx0VmFsdWU6IDIwMDAwLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIG51bWJlcjoge1xuICAgICAgICBtaW46IDE1MDAsXG4gICAgICAgIGludGVnZXI6IHRydWUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ29uZmlndXJhdGlvblZhbHVlVG9JbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IG51bWJlcikge1xuICAgICAgcmV0dXJuIFN0cmluZyh2YWx1ZSk7XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWU6IGZ1bmN0aW9uIChcbiAgICAgIHZhbHVlOiBzdHJpbmcsXG4gICAgKTogbnVtYmVyIHtcbiAgICAgIHJldHVybiBOdW1iZXIodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUoXG4gICAgICAgIHRoaXMudWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlKHZhbHVlKSxcbiAgICAgICk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gU2V0dGluZ3NWYWxpZGF0b3IubnVtYmVyKHRoaXMub3B0aW9ucy5udW1iZXIpKHZhbHVlKTtcbiAgICB9LFxuICB9LFxuICAnd2F6dWgubW9uaXRvcmluZy5jcmVhdGlvbic6IHtcbiAgICB0aXRsZTogJ0luZGV4IGNyZWF0aW9uJyxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdEZWZpbmUgdGhlIGludGVydmFsIGluIHdoaWNoIGEgbmV3IHdhenVoLW1vbml0b3JpbmcgaW5kZXggd2lsbCBiZSBjcmVhdGVkLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5Lk1PTklUT1JJTkcsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnNlbGVjdCxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzZWxlY3Q6IFtcbiAgICAgICAge1xuICAgICAgICAgIHRleHQ6ICdIb3VybHknLFxuICAgICAgICAgIHZhbHVlOiAnaCcsXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiAnRGFpbHknLFxuICAgICAgICAgIHZhbHVlOiAnZCcsXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiAnV2Vla2x5JyxcbiAgICAgICAgICB2YWx1ZTogJ3cnLFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogJ01vbnRobHknLFxuICAgICAgICAgIHZhbHVlOiAnbScsXG4gICAgICAgIH0sXG4gICAgICBdLFxuICAgIH0sXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfQ1JFQVRJT04sXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgdmFsaWRhdGVVSUZvcm06IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIHRoaXMudmFsaWRhdGUodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIFNldHRpbmdzVmFsaWRhdG9yLmxpdGVyYWwoXG4gICAgICAgIHRoaXMub3B0aW9ucy5zZWxlY3QubWFwKCh7IHZhbHVlIH0pID0+IHZhbHVlKSxcbiAgICAgICkodmFsdWUpO1xuICAgIH0sXG4gIH0sXG4gICd3YXp1aC5tb25pdG9yaW5nLmVuYWJsZWQnOiB7XG4gICAgdGl0bGU6ICdTdGF0dXMnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ0VuYWJsZSBvciBkaXNhYmxlIHRoZSB3YXp1aC1tb25pdG9yaW5nIGluZGV4IGNyZWF0aW9uIGFuZC9vciB2aXN1YWxpemF0aW9uLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5Lk1PTklUT1JJTkcsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9FTkFCTEVELFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVNldHRpbmdzOiB0cnVlLFxuICAgIHJlcXVpcmVzUmVzdGFydGluZ1BsdWdpblBsYXRmb3JtOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAoXG4gICAgICB2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyxcbiAgICApOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG4gIH0sXG4gICd3YXp1aC5tb25pdG9yaW5nLmZyZXF1ZW5jeSc6IHtcbiAgICB0aXRsZTogJ0ZyZXF1ZW5jeScsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnRnJlcXVlbmN5LCBpbiBzZWNvbmRzLCBvZiBBUEkgcmVxdWVzdHMgdG8gZ2V0IHRoZSBzdGF0ZSBvZiB0aGUgYWdlbnRzIGFuZCBjcmVhdGUgYSBuZXcgZG9jdW1lbnQgaW4gdGhlIHdhenVoLW1vbml0b3JpbmcgaW5kZXggd2l0aCB0aGlzIGRhdGEuJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuTU9OSVRPUklORyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUubnVtYmVyLFxuICAgIGRlZmF1bHRWYWx1ZTogV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0ZSRVFVRU5DWSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICByZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybTogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBudW1iZXI6IHtcbiAgICAgICAgbWluOiA2MCxcbiAgICAgICAgaW50ZWdlcjogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1Db25maWd1cmF0aW9uVmFsdWVUb0lucHV0VmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogbnVtYmVyKSB7XG4gICAgICByZXR1cm4gU3RyaW5nKHZhbHVlKTtcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUlucHV0VmFsdWVUb0NvbmZpZ3VyYXRpb25WYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IHN0cmluZyxcbiAgICApOiBudW1iZXIge1xuICAgICAgcmV0dXJuIE51bWJlcih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZShcbiAgICAgICAgdGhpcy51aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWUodmFsdWUpLFxuICAgICAgKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5udW1iZXIodGhpcy5vcHRpb25zLm51bWJlcikodmFsdWUpO1xuICAgIH0sXG4gIH0sXG4gICd3YXp1aC5tb25pdG9yaW5nLnBhdHRlcm4nOiB7XG4gICAgdGl0bGU6ICdJbmRleCBwYXR0ZXJuJyxcbiAgICBkZXNjcmlwdGlvbjogJ0RlZmF1bHQgaW5kZXggcGF0dGVybiB0byB1c2UgZm9yIFdhenVoIG1vbml0b3JpbmcuJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuTU9OSVRPUklORyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUudGV4dCxcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX01PTklUT1JJTkdfUEFUVEVSTixcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICByZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjazogdHJ1ZSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZSh2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzU3RyaW5nLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNOb3RFbXB0eVN0cmluZyxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmhhc05vU3BhY2VzLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3Iubm9MaXRlcmFsU3RyaW5nKCcuJywgJy4uJyksXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5ub1N0YXJ0c1dpdGhTdHJpbmcoJy0nLCAnXycsICcrJywgJy4nKSxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmhhc05vdEludmFsaWRDaGFyYWN0ZXJzKFxuICAgICAgICAnXFxcXCcsXG4gICAgICAgICcvJyxcbiAgICAgICAgJz8nLFxuICAgICAgICAnXCInLFxuICAgICAgICAnPCcsXG4gICAgICAgICc+JyxcbiAgICAgICAgJ3wnLFxuICAgICAgICAnLCcsXG4gICAgICAgICcjJyxcbiAgICAgICksXG4gICAgKSxcbiAgfSxcbiAgJ3dhenVoLm1vbml0b3JpbmcucmVwbGljYXMnOiB7XG4gICAgdGl0bGU6ICdJbmRleCByZXBsaWNhcycsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnRGVmaW5lIHRoZSBudW1iZXIgb2YgcmVwbGljYXMgdG8gdXNlIGZvciB0aGUgd2F6dWgtbW9uaXRvcmluZy0qIGluZGljZXMuJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuTU9OSVRPUklORyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUubnVtYmVyLFxuICAgIGRlZmF1bHRWYWx1ZTogV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0lORElDRVNfUkVQTElDQVMsXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgbnVtYmVyOiB7XG4gICAgICAgIG1pbjogMCxcbiAgICAgICAgaW50ZWdlcjogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1Db25maWd1cmF0aW9uVmFsdWVUb0lucHV0VmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogbnVtYmVyKSB7XG4gICAgICByZXR1cm4gU3RyaW5nKHZhbHVlKTtcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUlucHV0VmFsdWVUb0NvbmZpZ3VyYXRpb25WYWx1ZTogZnVuY3Rpb24gKFxuICAgICAgdmFsdWU6IHN0cmluZyxcbiAgICApOiBudW1iZXIge1xuICAgICAgcmV0dXJuIE51bWJlcih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZVVJRm9ybTogZnVuY3Rpb24gKHZhbHVlKSB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZShcbiAgICAgICAgdGhpcy51aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWUodmFsdWUpLFxuICAgICAgKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5udW1iZXIodGhpcy5vcHRpb25zLm51bWJlcikodmFsdWUpO1xuICAgIH0sXG4gIH0sXG4gICd3YXp1aC5tb25pdG9yaW5nLnNoYXJkcyc6IHtcbiAgICB0aXRsZTogJ0luZGV4IHNoYXJkcycsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnRGVmaW5lIHRoZSBudW1iZXIgb2Ygc2hhcmRzIHRvIHVzZSBmb3IgdGhlIHdhenVoLW1vbml0b3JpbmctKiBpbmRpY2VzLicsXG4gICAgc3RvcmU6IHtcbiAgICAgIGZpbGU6IHtcbiAgICAgICAgY29uZmlndXJhYmxlTWFuYWdlZDogdHJ1ZSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5Lk1PTklUT1JJTkcsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLm51bWJlcixcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9JTkRJQ0VTX1NIQVJEUyxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21TZXR0aW5nczogdHJ1ZSxcbiAgICByZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjazogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBudW1iZXI6IHtcbiAgICAgICAgbWluOiAxLFxuICAgICAgICBpbnRlZ2VyOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNvbmZpZ3VyYXRpb25WYWx1ZVRvSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBudW1iZXIpIHtcbiAgICAgIHJldHVybiBTdHJpbmcodmFsdWUpO1xuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlOiBmdW5jdGlvbiAoXG4gICAgICB2YWx1ZTogc3RyaW5nLFxuICAgICk6IG51bWJlciB7XG4gICAgICByZXR1cm4gTnVtYmVyKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlKFxuICAgICAgICB0aGlzLnVpRm9ybVRyYW5zZm9ybUlucHV0VmFsdWVUb0NvbmZpZ3VyYXRpb25WYWx1ZSh2YWx1ZSksXG4gICAgICApO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIFNldHRpbmdzVmFsaWRhdG9yLm51bWJlcih0aGlzLm9wdGlvbnMubnVtYmVyKSh2YWx1ZSk7XG4gICAgfSxcbiAgfSxcbiAgJ3Z1bG5lcmFiaWxpdGllcy5wYXR0ZXJuJzoge1xuICAgIHRpdGxlOiAnSW5kZXggcGF0dGVybicsXG4gICAgZGVzY3JpcHRpb246ICdEZWZhdWx0IGluZGV4IHBhdHRlcm4gdG8gdXNlIGZvciB2dWxuZXJhYmlsaXRpZXMuJyxcbiAgICBzdG9yZToge1xuICAgICAgZmlsZToge1xuICAgICAgICBjb25maWd1cmFibGVNYW5hZ2VkOiB0cnVlLFxuICAgICAgfSxcbiAgICB9LFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuVlVMTkVSQUJJTElUSUVTLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS50ZXh0LFxuICAgIGRlZmF1bHRWYWx1ZTogV0FaVUhfVlVMTkVSQUJJTElUSUVTX1BBVFRFUk4sXG4gICAgaXNDb25maWd1cmFibGVGcm9tU2V0dGluZ3M6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IGZhbHNlLFxuICAgIHZhbGlkYXRlVUlGb3JtOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNTdHJpbmcsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc05vdEVtcHR5U3RyaW5nLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm9TcGFjZXMsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5ub0xpdGVyYWxTdHJpbmcoJy4nLCAnLi4nKSxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLm5vU3RhcnRzV2l0aFN0cmluZygnLScsICdfJywgJysnLCAnLicpLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm90SW52YWxpZENoYXJhY3RlcnMoXG4gICAgICAgICdcXFxcJyxcbiAgICAgICAgJy8nLFxuICAgICAgICAnPycsXG4gICAgICAgICdcIicsXG4gICAgICAgICc8JyxcbiAgICAgICAgJz4nLFxuICAgICAgICAnfCcsXG4gICAgICAgICcsJyxcbiAgICAgICAgJyMnLFxuICAgICAgKSxcbiAgICApLFxuICB9LFxufTtcblxuZXhwb3J0IHR5cGUgVFBsdWdpblNldHRpbmdLZXkgPSBrZXlvZiB0eXBlb2YgUExVR0lOX1NFVFRJTkdTO1xuXG5leHBvcnQgZW51bSBIVFRQX1NUQVRVU19DT0RFUyB7XG4gIENPTlRJTlVFID0gMTAwLFxuICBTV0lUQ0hJTkdfUFJPVE9DT0xTID0gMTAxLFxuICBQUk9DRVNTSU5HID0gMTAyLFxuICBPSyA9IDIwMCxcbiAgQ1JFQVRFRCA9IDIwMSxcbiAgQUNDRVBURUQgPSAyMDIsXG4gIE5PTl9BVVRIT1JJVEFUSVZFX0lORk9STUFUSU9OID0gMjAzLFxuICBOT19DT05URU5UID0gMjA0LFxuICBSRVNFVF9DT05URU5UID0gMjA1LFxuICBQQVJUSUFMX0NPTlRFTlQgPSAyMDYsXG4gIE1VTFRJX1NUQVRVUyA9IDIwNyxcbiAgTVVMVElQTEVfQ0hPSUNFUyA9IDMwMCxcbiAgTU9WRURfUEVSTUFORU5UTFkgPSAzMDEsXG4gIE1PVkVEX1RFTVBPUkFSSUxZID0gMzAyLFxuICBTRUVfT1RIRVIgPSAzMDMsXG4gIE5PVF9NT0RJRklFRCA9IDMwNCxcbiAgVVNFX1BST1hZID0gMzA1LFxuICBURU1QT1JBUllfUkVESVJFQ1QgPSAzMDcsXG4gIFBFUk1BTkVOVF9SRURJUkVDVCA9IDMwOCxcbiAgQkFEX1JFUVVFU1QgPSA0MDAsXG4gIFVOQVVUSE9SSVpFRCA9IDQwMSxcbiAgUEFZTUVOVF9SRVFVSVJFRCA9IDQwMixcbiAgRk9SQklEREVOID0gNDAzLFxuICBOT1RfRk9VTkQgPSA0MDQsXG4gIE1FVEhPRF9OT1RfQUxMT1dFRCA9IDQwNSxcbiAgTk9UX0FDQ0VQVEFCTEUgPSA0MDYsXG4gIFBST1hZX0FVVEhFTlRJQ0FUSU9OX1JFUVVJUkVEID0gNDA3LFxuICBSRVFVRVNUX1RJTUVPVVQgPSA0MDgsXG4gIENPTkZMSUNUID0gNDA5LFxuICBHT05FID0gNDEwLFxuICBMRU5HVEhfUkVRVUlSRUQgPSA0MTEsXG4gIFBSRUNPTkRJVElPTl9GQUlMRUQgPSA0MTIsXG4gIFJFUVVFU1RfVE9PX0xPTkcgPSA0MTMsXG4gIFJFUVVFU1RfVVJJX1RPT19MT05HID0gNDE0LFxuICBVTlNVUFBPUlRFRF9NRURJQV9UWVBFID0gNDE1LFxuICBSRVFVRVNURURfUkFOR0VfTk9UX1NBVElTRklBQkxFID0gNDE2LFxuICBFWFBFQ1RBVElPTl9GQUlMRUQgPSA0MTcsXG4gIElNX0FfVEVBUE9UID0gNDE4LFxuICBJTlNVRkZJQ0lFTlRfU1BBQ0VfT05fUkVTT1VSQ0UgPSA0MTksXG4gIE1FVEhPRF9GQUlMVVJFID0gNDIwLFxuICBNSVNESVJFQ1RFRF9SRVFVRVNUID0gNDIxLFxuICBVTlBST0NFU1NBQkxFX0VOVElUWSA9IDQyMixcbiAgTE9DS0VEID0gNDIzLFxuICBGQUlMRURfREVQRU5ERU5DWSA9IDQyNCxcbiAgUFJFQ09ORElUSU9OX1JFUVVJUkVEID0gNDI4LFxuICBUT09fTUFOWV9SRVFVRVNUUyA9IDQyOSxcbiAgUkVRVUVTVF9IRUFERVJfRklFTERTX1RPT19MQVJHRSA9IDQzMSxcbiAgVU5BVkFJTEFCTEVfRk9SX0xFR0FMX1JFQVNPTlMgPSA0NTEsXG4gIElOVEVSTkFMX1NFUlZFUl9FUlJPUiA9IDUwMCxcbiAgTk9UX0lNUExFTUVOVEVEID0gNTAxLFxuICBCQURfR0FURVdBWSA9IDUwMixcbiAgU0VSVklDRV9VTkFWQUlMQUJMRSA9IDUwMyxcbiAgR0FURVdBWV9USU1FT1VUID0gNTA0LFxuICBIVFRQX1ZFUlNJT05fTk9UX1NVUFBPUlRFRCA9IDUwNSxcbiAgSU5TVUZGSUNJRU5UX1NUT1JBR0UgPSA1MDcsXG4gIE5FVFdPUktfQVVUSEVOVElDQVRJT05fUkVRVUlSRUQgPSA1MTEsXG59XG5cbi8vIE1vZHVsZSBTZWN1cml0eSBjb25maWd1cmF0aW9uIGFzc2Vzc21lbnRcbmV4cG9ydCBjb25zdCBNT0RVTEVfU0NBX0NIRUNLX1JFU1VMVF9MQUJFTCA9IHtcbiAgcGFzc2VkOiAnUGFzc2VkJyxcbiAgZmFpbGVkOiAnRmFpbGVkJyxcbiAgJ25vdCBhcHBsaWNhYmxlJzogJ05vdCBhcHBsaWNhYmxlJyxcbn07XG5cbi8vIFNlYXJjaCBiYXJcblxuLy8gVGhpcyBsaW1pdHMgdGhlIHJlc3VsdHMgaW4gdGhlIEFQSSByZXF1ZXN0XG5leHBvcnQgY29uc3QgU0VBUkNIX0JBUl9XUUxfVkFMVUVfU1VHR0VTVElPTlNfQ09VTlQgPSAzMDtcbi8vIFRoaXMgbGltaXRzIHRoZSBzdWdnZXN0aW9ucyBmb3IgdGhlIHRva2VuIG9mIHR5cGUgdmFsdWUgZGlzcGxheWVkIGluIHRoZSBzZWFyY2ggYmFyXG5leHBvcnQgY29uc3QgU0VBUkNIX0JBUl9XUUxfVkFMVUVfU1VHR0VTVElPTlNfRElTUExBWV9DT1VOVCA9IDEwO1xuLyogVGltZSBpbiBtaWxsaXNlY29uZHMgdG8gZGVib3VuY2UgdGhlIGFuYWx5c2lzIG9mIHNlYXJjaCBiYXIuIFRoaXMgbWl0aWdhdGVzIHNvbWUgcHJvYmxlbXMgcmVsYXRlZFxudG8gY2hhbmdlcyBydW5uaW5nIGluIHBhcmFsbGVsICovXG5leHBvcnQgY29uc3QgU0VBUkNIX0JBUl9ERUJPVU5DRV9VUERBVEVfVElNRSA9IDQwMDtcblxuLy8gUGx1Z2luIHNldHRpbmdzXG5leHBvcnQgY29uc3QgV0FaVUhfQ09SRV9FTkNSWVBUSU9OX1BBU1NXT1JEID0gJ3NlY3JldGVuY3J5cHRpb25rZXkhJztcblxuLy8gQ29uZmlndXJhdGlvbiBiYWNrZW5kIHNlcnZpY2VcbmV4cG9ydCBjb25zdCBXQVpVSF9DT1JFX0NPTkZJR1VSQVRJT05fSU5TVEFOQ0UgPSAnd2F6dWgtZGFzaGJvYXJkJztcbmV4cG9ydCBjb25zdCBXQVpVSF9DT1JFX0NPTkZJR1VSQVRJT05fQ0FDSEVfU0VDT05EUyA9IDEwO1xuXG4vLyBBUEkgY29ubmVjdGlvbiBwZXJtaXNzaW9uc1xuZXhwb3J0IGNvbnN0IFdBWlVIX1JPTEVfQURNSU5JU1RSQVRPUl9JRCA9IDE7XG5cbi8vIElEIHVzZWQgdG8gcmVmZXIgdGhlIGNyZWF0ZU9zZFVybFN0YXRlU3RvcmFnZSBzdGF0ZVxuZXhwb3J0IGNvbnN0IE9TRF9VUkxfU1RBVEVfU1RPUkFHRV9JRCA9ICdzdGF0ZTpzdG9yZUluU2Vzc2lvblN0b3JhZ2UnO1xuIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBV0EsSUFBQUEsS0FBQSxHQUFBQyxzQkFBQSxDQUFBQyxPQUFBO0FBQ0EsSUFBQUMsUUFBQSxHQUFBRCxPQUFBO0FBRUEsSUFBQUUsa0JBQUEsR0FBQUYsT0FBQTtBQUEwRSxTQUFBRCx1QkFBQUksR0FBQSxXQUFBQSxHQUFBLElBQUFBLEdBQUEsQ0FBQUMsVUFBQSxHQUFBRCxHQUFBLEtBQUFFLE9BQUEsRUFBQUYsR0FBQTtBQWQxRTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUdBOztBQUdBO0FBQ08sTUFBTUcsY0FBYyxHQUFBQyxPQUFBLENBQUFELGNBQUEsR0FBR0UsZ0JBQU87QUFD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LENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFqQkEsaUJBQWlCLENBQWpCQSxpQkFBaUI7RUFBakJBLGlCQUFpQixDQUFqQkEsaUJBQWlCO0VBQWpCQSxpQkFBaUIsQ0FBakJBLGlCQUFpQjtFQUFBLE9BQWpCQSxpQkFBaUI7QUFBQSxPQTJEN0I7QUFDTyxNQUFNQyw2QkFBNkIsR0FBQWxRLE9BQUEsQ0FBQWtRLDZCQUFBLEdBQUc7RUFDM0NDLE1BQU0sRUFBRSxRQUFRO0VBQ2hCQyxNQUFNLEVBQUUsUUFBUTtFQUNoQixnQkFBZ0IsRUFBRTtBQUNwQixDQUFDOztBQUVEOztBQUVBO0FBQ08sTUFBTUMsc0NBQXNDLEdBQUFyUSxPQUFBLENBQUFxUSxzQ0FBQSxHQUFHLEVBQUU7QUFDeEQ7QUFDTyxNQUFNQyw4Q0FBOEMsR0FBQXRRLE9BQUEsQ0FBQXNRLDhDQUFBLEdBQUcsRUFBRTtBQUNoRTtBQUNBO0FBQ08sTUFBTUMsK0JBQStCLEdBQUF2USxPQUFBLENBQUF1USwrQkFBQSxHQUFHLEdBQUc7O0FBRWxEO0FBQ08sTUFBTUMsOEJBQThCLEdBQUF4USxPQUFBLENBQUF3USw4QkFBQSxHQUFHLHNCQUFzQjs7QUFFcEU7QUFDTyxNQUFNQyxpQ0FBaUMsR0FBQXpRLE9BQUEsQ0FBQXlRLGlDQUFBLEdBQUcsaUJBQWlCO0FBQzNELE1BQU1DLHNDQUFzQyxHQUFBMVEsT0FBQSxDQUFBMFEsc0NBQUEsR0FBRyxFQUFFOztBQUV4RDtBQUNPLE1BQU1DLDJCQUEyQixHQUFBM1EsT0FBQSxDQUFBMlEsMkJBQUEsR0FBRyxDQUFDOztBQUU1QztBQUNPLE1BQU1DLHdCQUF3QixHQUFBNVEsT0FBQSxDQUFBNFEsd0JBQUEsR0FBRyw2QkFBNkIifQ==