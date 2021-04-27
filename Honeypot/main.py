import sys
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQml import QQmlApplicationEngine
from PyQt5.QtCore import QObject, pyqtSlot, pyqtSignal, QVariant

from .handlers import FTPRouter, HTTPRouter
from .handlers.gui import GUI
from .handlers.logger import Logger
from .handlers.database import database
from .handlers.blacklist import Blacklist
from .handlers.tcp.syn_handler import SynHandler
from .handlers.config import general_conf, ftp_conf, http_conf


class MainWindow(QObject):
    def __init__(self):
        super().__init__()
        self.blacklist = Blacklist()
        self.logger = Logger("Router Admin").get_logger()

        ftp_router_config = ftp_conf.asdict()
        self.ftp_router = FTPRouter(**ftp_router_config)

        http_router_config = http_conf.asdict()
        http_router_config.pop("asset_database_path")
        self.http_router = HTTPRouter(**http_router_config)

    # Qt Signals
    addToBlacklist = pyqtSignal(str)  # Add ip addr to blacklist GUI
    addLog = pyqtSignal(str)  # Add log to GUI
    addAttacker = pyqtSignal(QVariant)  # Add new attacker to GUI
    addAttack = pyqtSignal(QVariant)  # Add new attack to GUI
    incrementAttack = pyqtSignal(str)  # Increments attacks_num on GUI for IP

    def stop_routers(self):
        """
        Stops both routers.
        """
        self.http_router.stop()
        self.ftp_router.stop()

    @pyqtSlot()
    def start_ftp_router(self):
        self.ftp_router.start()

    @pyqtSlot()
    def stop_ftp_router(self):
        self.ftp_router.stop()

    @pyqtSlot()
    def start_http_router(self):
        self.http_router.start()

    @pyqtSlot()
    def stop_http_router(self):
        self.http_router.stop()

    @pyqtSlot(int, result=bool)
    def update_general_settings(self, max_syns_allowed: int) -> bool:
        """
        Updates the general settings

        Args:
            max_syns_allowed (int)

        Returns:
            bool: Whether the settings were updated
        """
        if self.ftp_router.running or self.http_router.running:
            return False
        general_conf.update_settings(max_syns_allowed)
        SynHandler.max_syns_allowed = max_syns_allowed
        return True

    @pyqtSlot(str, int, str, int, int, result=bool)
    def update_ftp_settings(self, asset_ip, asset_port, honeypot_ip,
                            honeypot_port, fake_asset_port):
        """
        Updates the FTP settings

        Args:
            asset_ip (str)
            asset_port (int)
            honeypot_ip (str)
            honeypot_port (int)
            fake_asset_port (nt)

        Returns:
            bool: Whether the settings were updated
        """
        if self.ftp_router.running:
            return False
        self.ftp_router.update_settings(asset_ip, asset_port, honeypot_ip,
                                        honeypot_port, fake_asset_port)
        ftp_conf.update_settings(asset_ip, asset_port, honeypot_ip,
                                 honeypot_port, fake_asset_port)
        return True

    @pyqtSlot(str, int, str, int, int, str, result=bool)
    def update_http_settings(self, asset_ip, asset_port, honeypot_ip,
                             honeypot_port, fake_asset_port, asset_db_path):
        """
        Updates the HTTP settings

        Args:
            asset_ip (str)
            asset_port (int)
            honeypot_ip (str)
            honeypot_port (int)
            fake_asset_port (int)
            asset_db_path (str)

        Returns:
            bool: Whether the settings were updated
        """
        if self.http_router.running:
            return False
        self.http_router.update_settings(asset_ip, asset_port, honeypot_ip,
                                         honeypot_port, fake_asset_port)
        http_conf.update_settings(asset_ip, asset_port, honeypot_ip,
                                  honeypot_port, fake_asset_port,
                                  asset_db_path)
        database.asset_db_path = asset_db_path
        return True

    @pyqtSlot(result=QVariant)
    def load_general_settings(self):
        """
        Loads the default general settings to the GUI

        Returns:
            QVariant: List of general settings
        """
        return QVariant(general_conf.get_settings())

    @pyqtSlot(result=QVariant)
    def load_http_settings(self):
        """
        Loads the default HTTP settings to the GUI

        Returns:
            QVariant: List of HTTP settings
        """
        return QVariant(http_conf.get_settings())

    @pyqtSlot(result=QVariant)
    def load_ftp_settings(self):
        """
        Loads the default FTP settings to the GUI

        Returns:
            QVariant: List of FTP settings
        """
        return QVariant(ftp_conf.get_settings())

    @pyqtSlot(result=QVariant)
    def load_blacklist(self):
        """
        Loads the existing blacklist to the GUI

        Returns:
            QVariant: List of blacklisted IPs
        """
        return QVariant(self.blacklist.aslist())

    @pyqtSlot(result=QVariant)
    def load_attackers_data(self):
        """
        Loads the attacker history from the database to the GUI

        Returns:
            QVariant: List of attackers data
        """
        return QVariant(database.get_attackers_data())

    @pyqtSlot(result=QVariant)
    def load_attacks_data(self):
        """
        Loads the attack history from the database to the GUI

        Returns:
            QVariant: List of attacks data
        """
        return QVariant(database.get_attacks_data())

    @pyqtSlot(str)
    def remove_from_blacklist(self, ip: str):
        """
        Removes an IP address from the blacklist
        """
        self.blacklist.remove_address(ip)
        self.logger.info(f"IP address {ip} was unblocked by the admin.")

    @pyqtSlot(str)
    def add_whitelist_password(self, password: str):
        """
        Adds a whitelisted password to FTP router
        """
        self.ftp_router.add_whitelist_password(password)

    @pyqtSlot(str)
    def remove_whitelist_password(self, password: str):
        """
        Removes a whitelisted password from the FTP router
        """
        self.ftp_router.remove_whitelist_password(password)


if __name__ == "__main__":
    app = QGuiApplication(sys.argv)
    app.setOrganizationName(" ")
    app.setOrganizationDomain(" ")

    main_window = MainWindow()
    GUI.main = main_window
    engine = QQmlApplicationEngine()
    root = engine.rootContext()

    root.setContextProperty("backend", main_window)
    engine.load(r"Honeypot/qml/main.qml")

    if not engine.rootObjects():
        sys.exit(-1)
    ret = app.exec_()
    main_window.stop_routers()  # stop routers before exit
    sys.exit(ret)
