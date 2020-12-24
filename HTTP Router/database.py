import sqlite3 as lite
from threading import Lock
from datetime import datetime

DATABASE_PATH = "Database.db"


class Database():
    def __init__(self):
        self.lock = Lock()
        self.create_tables()

    def execute(self, *args):
        with self.lock, lite.connect(DATABASE_PATH) as connection:
            cursor = connection.cursor()
            cursor.execute(*args)
            connection.commit()
            return cursor.lastrowid

    def fetch(self, *args):
        with self.lock, lite.connect(DATABASE_PATH) as connection:
            cursor = connection.cursor()
            cursor.execute(*args)
            return cursor.fetchall()

    def create_tables(self):
        self.execute(
            """
            CREATE TABLE IF NOT EXISTS attackers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                os TEXT NOT NULL,
                attacks_num INTEGER NOT NULL
            )
            """
        )

        self.execute(
            """
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attacker INTEGER NOT NULL,
                date TEXT NOT NULL,
                description TEXT NOT NULL,
                FOREIGN KEY(attacker) REFERENCES attackers(id)
            )
            """
        )

    def add_attacker(self, attacker_ip, probable_os):
        attacker_exists = self.fetch("SELECT * FROM attackers WHERE ip = ?",
                                     (attacker_ip,))
        if attacker_exists:
            attacks_num = self.fetch("SELECT attacks_num FROM attackers WHERE ip = ?",
                                     (attacker_ip,))[0][0]
            self.execute("UPDATE attackers SET attacks_num = ? WHERE ip = ?",
                         (attacks_num + 1, attacker_ip))
        else:
            self.execute("INSERT INTO attackers (ip, os, attacks_num) VALUES (?, ?, ?)",
                         (attacker_ip, probable_os, 1))

    def add_attack(self, attacker_ip, description):
        system_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        attacker_id = self.fetch("SELECT id from attackers WHERE ip = ?",
                                 (attacker_ip,))[0][0]
        self.execute("INSERT INTO attacks (attacker, date, description) VALUES (?, ?, ?)",
                     (attacker_id, system_time, description))

database = Database()