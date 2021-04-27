from PyQt5.QtCore import QVariant


class GUI:
    """
    Handles GUI signals when sending data to it.
    """
    main_window = None

    @classmethod
    def add_log(cls, record: str):
        cls.main_window.addLog.emit(record)

    @classmethod
    def add_to_blacklist(cls, ip_addr: str):
        cls.main_window.addToBlacklist.emit(ip_addr)

    @classmethod
    def add_attacker(cls, attacker_ip: str, probable_os: str):
        data = QVariant([attacker_ip, probable_os])
        cls.main_window.addAttacker.emit(data)

    @classmethod
    def add_attack(cls, attacker_ip: str, attacker_port: int,
                   date: int, description: str):
        data = QVariant([attacker_ip, attacker_port, date, description])
        cls.main_window.addAttack.emit(data)

    @classmethod
    def increment_attacks_num(cls, ip_addr: str):
        cls.main_window.incrementAttack.emit(ip_addr)
