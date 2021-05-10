from configparser import ConfigParser

CONFIG_PATH = r"Honeypot/common/config.ini"
INT_ATTRIBUTES = {
    "asset_port",
    "honeypot_port",
    "fake_asset_port",
    "max_syns_allowed"
}


class Config:
    """
    Handles config for a certain section and updates the config file
    """
    def __init__(self, config_section):
        self.__dict__["config"] = config_section

    def __getattr__(self, name):
        if name in INT_ATTRIBUTES:
            return self.config.getint(name)
        return self.config.get(name)

    def __setattr__(self, name, value):
        self.config[name] = str(value)

    def asdict(self):
        d = {}
        for key, value in self.config.items():
            if key in INT_ATTRIBUTES:
                d[key] = self.config.getint(key)
            else:
                d[key] = self.config.get(key)
        return d

    @staticmethod
    def update_file():
        """
        Updates the config file with all changes, across all sections
        """
        with open(CONFIG_PATH, "w") as configfile:
            config.write(configfile)


class HTTPConfig(Config):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def update_settings(self, asset_ip, asset_port,
                        honeypot_ip, honeypot_port,
                        fake_asset_port, asset_db_path, max_syns_allowed):
        self.asset_ip = asset_ip
        self.asset_port = asset_port
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        self.fake_asset_port = fake_asset_port
        self.asset_database_path = asset_db_path
        self.max_syns_allowed = max_syns_allowed
        self.update_file()

    def get_settings(self):
        return [
            self.asset_ip,
            self.honeypot_ip,
            self.asset_port,
            self.honeypot_port,
            self.fake_asset_port,
            self.asset_database_path,
            self.max_syns_allowed
        ]


class FTPConfig(Config):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def update_settings(self, asset_ip, asset_port,
                        honeypot_ip, honeypot_port,
                        fake_asset_port, max_syns_allowed):
        self.asset_ip = asset_ip
        self.asset_port = asset_port
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        self.fake_asset_port = fake_asset_port
        self.max_syns_allowed = max_syns_allowed
        self.update_file()

    def get_settings(self):
        return [
            self.asset_ip,
            self.honeypot_ip,
            self.asset_port,
            self.honeypot_port,
            self.fake_asset_port,
            self.max_syns_allowed
        ]


config = ConfigParser()
config.read(CONFIG_PATH)
ftp_conf = FTPConfig(config["ftp"])
http_conf = HTTPConfig(config["http"])