"""Constants for the Passive BLE monitor integration."""

DOMAIN = "ble_monitor"

CONF_DEVICES = "devices"
CONF_DISCOVERY = "discovery"
CONF_MAC = "mac"
CONF_NAME = "name"
CONF_TEMPERATURE_UNIT = "temperature_unit"

ATTR_BATTERY_LEVEL = "battery_level"

# Temperature units
TEMP_CELSIUS = "°C"
TEMP_FAHRENHEIT = "°F"
TEMP_KELVIN = "K"

# Percentage units
PERCENTAGE = "%"

# Conductivity units
CONDUCTIVITY: str = "µS/cm"

# States
STATE_ON = "on"
STATE_OFF = "off"
STATE_UNKNOWN = "unknown"

# On means power detected, Off means no power
DEVICE_CLASS_LIGHT = "light"
DEVICE_CLASS_OPENING = "opening"
DEVICE_CLASS_BATTERY = "battery"
DEVICE_CLASS_HUMIDITY = "humidity"
DEVICE_CLASS_ILLUMINANCE = "illuminance"
DEVICE_CLASS_SIGNAL_STRENGTH = "signal_strength"
DEVICE_CLASS_TEMPERATURE = "temperature"
DEVICE_CLASS_TIMESTAMP = "timestamp"
DEVICE_CLASS_PRESSURE = "pressure"
DEVICE_CLASS_POWER = "power"
DEVICE_CLASS_CURRENT = "current"
DEVICE_CLASS_ENERGY = "energy"
DEVICE_CLASS_POWER_FACTOR = "power_factor"
DEVICE_CLASS_VOLTAGE = "voltage"

# Configuration options
CONF_ROUNDING = "rounding"
CONF_DECIMALS = "decimals"
CONF_PERIOD = "period"
CONF_LOG_SPIKES = "log_spikes"
CONF_USE_MEDIAN = "use_median"
CONF_ACTIVE_SCAN = "active_scan"
CONF_HCI_INTERFACE = "hci_interface"
CONF_BATT_ENTITIES = "batt_entities"
CONF_REPORT_UNKNOWN = "report_unknown"
CONF_RESTORE_STATE = "restore_state"
CONF_ENCRYPTION_KEY = "encryption_key"

# Default values for configuration options
DEFAULT_ROUNDING = True
DEFAULT_DECIMALS = 1
DEFAULT_PERIOD = 60
DEFAULT_LOG_SPIKES = False
DEFAULT_USE_MEDIAN = False
DEFAULT_ACTIVE_SCAN = False
DEFAULT_HCI_INTERFACE = 0
DEFAULT_BATT_ENTITIES = False
DEFAULT_REPORT_UNKNOWN = False
DEFAULT_DISCOVERY = True
DEFAULT_RESTORE_STATE = False

"""Fixed constants."""

# Sensor measurement limits to exclude erroneous spikes from the results (temperature in °C)
CONF_TMIN = -40.0
CONF_TMAX = 60.0
CONF_HMIN = 0.0
CONF_HMAX = 99.9

# Xiaomi sensor types dictionary for adv parser
XIAOMI_TYPE_DICT = {
    b'\x98\x00': "HHCCJCY01",
    b'\xAA\x01': "LYWSDCGQ",
    b'\x5B\x04': "LYWSD02",
    b'\x47\x03': "CGG1",
    b'\x5D\x01': "HHCCPOT002",
    b'\xBC\x03': "GCLS002",
    b'\x5B\x05': "LYWSD03MMC",
    b'\x76\x05': "CGD1",
    b'\xDF\x02': "JQJCY01YM",
    b'\x0A\x04': "WX08ZM",
    b'\x87\x03': "MHO-C401",
    b'\xd3\x06': "MHO-C303",
    b'\x8B\x09': "MCCGQ02HL",
}

# Sensor type indexes dictionary
# Temperature, Humidity, Moisture, Conductivity, Illuminance, Formaldehyde, Consumable, Switch, Opening, Light, Battery
# Measurement type T  H  M  C  I  F  Cn Sw O  L  B   9 - no measurement
MMTS_DICT = {
    'HHCCJCY01': [0, 9, 1, 2, 3, 9, 9, 9, 9, 9, 9],
    'GCLS002': [0, 9, 1, 2, 3, 9, 9, 9, 9, 9, 9],
    'HHCCPOT002': [9, 9, 0, 1, 9, 9, 9, 9, 9, 9, 9],
    'LYWSDCGQ': [0, 1, 9, 9, 9, 9, 9, 9, 9, 9, 2],
    'LYWSD02': [0, 1, 9, 9, 9, 9, 9, 9, 9, 9, 2],
    'CGG1': [0, 1, 9, 9, 9, 9, 9, 9, 9, 9, 2],
    'LYWSD03MMC': [0, 1, 9, 9, 9, 9, 9, 9, 9, 9, 2],
    'CGD1': [0, 1, 9, 9, 9, 9, 9, 9, 9, 9, 2],
    'JQJCY01YM': [0, 1, 9, 9, 9, 2, 9, 9, 9, 9, 3],
    'WX08ZM': [9, 9, 9, 9, 9, 9, 0, 1, 9, 9, 2],
    'MHO-C401': [0, 1, 9, 9, 9, 9, 9, 9, 9, 9, 2],
    'MHO-C303': [0, 1, 9, 9, 9, 9, 9, 9, 9, 9, 2],
    'MCCGQ02HL': [9, 9, 9, 9, 9, 9, 9, 9, 0, 1, 2],
}
