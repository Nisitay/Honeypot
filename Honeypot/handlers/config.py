from configparser import ConfigParser

CONFIG_PATH = r"Honeypot/common/config.ini"
INT_ATTRIBUTES = [
    "asset_port",
    "honeypot_port",
    "fake_asset_port",
    "max_syns_allowed"
]


class Config():
    """
    Handles config for a certain section and updates the config file
    """
    def __init__(self, config_section):
        self.__dict__["config"] = config_section

    def __getattr__(self, name):
        value = self.config[name]
        return int(value) if name in INT_ATTRIBUTES else value

    def __setattr__(self, name, value):
        self.config[name] = str(value)

    @staticmethod
    def update_file():
        """
        Updates the config file with all changes, across all sections
        """
        with open(CONFIG_PATH, "w") as configfile:
            config.write(configfile)


config = ConfigParser()
config.read(CONFIG_PATH)
general_conf = Config(config["general"])
ftp_conf = Config(config["ftp"])
http_conf = Config(config["http"])