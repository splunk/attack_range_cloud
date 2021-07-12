import configparser
import collections
import sys
from pathlib import Path
import re

class CustomConfigParser:
    def __init__(self):
        self.settings = {}

    def _config_rules(self, CONFIG_PATH):

        key_name_regex = re.compile('[@!#$%^&*()\' <>?/\|}{~:]')
        if (key_name_regex.search(self.settings['key_name']) != None):
            print("ERROR - with configuration file at: {0}, no special characters, spaces, single quotes allowed in key_name: {1}".format(CONFIG_PATH,self.settings['key_name']))
            sys.exit(1)
            
        range_name_regex = re.compile('[@!#$%^&*()\' <>?/\|}{~:]')
        if (range_name_regex.search(self.settings['range_name']) != None):
            print("ERROR - with configuration file at: {0}, no special characters, spaces, single quotes allowed in range_name: {1}".format(
                CONFIG_PATH, self.settings['range_name']))
            sys.exit(1)

        if '0.0.0.0/0' in self.settings['ip_whitelist']:
            print("WARNING - with configuration file at: {0}, the attack range will be public and open to the world, it is recommended that users secure attack_range servers by whitelisting only the public IP address in this format: ip_whitelist= <X.X.X.X>/32".format(CONFIG_PATH))


    def load_conf(self,CONFIG_PATH):
        """Provided a config file path and a collections of type dict,
        will return that collections with all the settings in it"""

        config = configparser.RawConfigParser()
        config.read(CONFIG_PATH)
        for section in config.sections():
            for key in config[section]:
                try:
                    self.settings[key] = config.get(section, key)
                except Exception as e:
                    print("ERROR - with configuration file at {0} failed with error {1}".format(CONFIG_PATH, e))
                    sys.exit(1)
        self._config_rules(CONFIG_PATH)

        return self.settings
