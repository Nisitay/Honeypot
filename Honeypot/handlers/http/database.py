import sqlite3 as lite
import pandas
import datetime
from threading import Lock
from ..config import DATABASE_PATH, ASSET_DATABASE_PATH


class Database():
    def __init__(self):
        self.lock = Lock()
        self.create_tables()

    def execute(self, *args):
        with self.lock, lite.connect(DATABASE_PATH) as connection:
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")
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
                id INTEGER PRIMARY KEY,
                ip TEXT UNIQUE NOT NULL,
                os TEXT NOT NULL,
                attacks_num INTEGER NOT NULL
            )
            """
        )

        self.execute(
            """
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY,
                attacker INTEGER NOT NULL,
                port INTEGER NOT NULL,
                date TEXT NOT NULL,
                description TEXT NOT NULL,
                FOREIGN KEY(attacker) REFERENCES attackers(id) ON DELETE CASCADE
            )
            """
        )

        self.execute(
            """
            CREATE TABLE IF NOT EXISTS allowed_users (
                id INTEGER PRIMARY KEY,
                ip TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL
            )
            """
        )

    def add_attacker(self, attacker_ip, probable_os):
        """
        Adds an attacker to the database, or increments his
        number of attacks if he already exists.

        Args:
            attacker_ip (str)
            probable_os (str)
        """
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

    def remove_attacker(self, attacker_ip):
        """
        Removes an attacker from the database and the attacks
        associated with him.

        Args:
            attacker_ip (str)
        """
        attacker_id = self.fetch("SELECT id from attackers WHERE ip = ?",
                                 (attacker_ip,))[0][0]
        self.execute("DELETE FROM attackers WHERE id = ?", (attacker_id,))

    def add_attack(self, attacker_ip, attacker_port, description):
        """
        Adds an attack and its' information to the database

        Args:
            attacker_ip (str):
            attacker_port (int):
            description (str):
        """
        system_time = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        attacker_id = self.fetch("SELECT id from attackers WHERE ip = ?",
                                 (attacker_ip,))[0][0]
        self.execute("INSERT INTO attacks (attacker, port, date, description) VALUES (?, ?, ?, ?)",
                     (attacker_id, attacker_port, system_time, description))

    def is_allowed(self, ip, username):
        """
        Checks whether an IP address is allowed to log into
        an account with the given username.

        Args:
            ip (str)
            username (str)

        Returns:
            bool
        """
        exists = self.fetch("SELECT * FROM allowed_users WHERE ip = ? AND username = ?",
                            (ip, username))
        return exists

    def has_allowed(self, ip):
        """
        Checks whether the IP address has a username
        it's allowed to log into.

        Args:
            ip (str)

        Returns:
            bool
        """
        exists = self.fetch("SELECT * FROM allowed_users WHERE ip = ?",
                            (ip,))
        return exists

    def add_allowed(self, ip, username):
        """
        Adds an allowed username to log into for
        a given IP address.

        Args:
            ip (str)
            username (str)
        """
        self.execute("INSERT INTO allowed_users (ip, username) VALUES (?, ?)",
                     (ip, username))

    def get_username(self, email):
        """
        Returns the username associated with the
        email address in the asset database.

        Args:
            email (str)

        Returns:
            str
        """
        with lite.connect(ASSET_DATABASE_PATH) as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT username FROM user WHERE email = ?", (email,))
            username = cursor.fetchall()
            return username[0][0] if username else None

    # TODO: Change the method of retreiving the table data
    def get_pretty_table(self, table_name):
        with self.lock, lite.connect(DATABASE_PATH) as connection:
            return pandas.read_sql_query(f"SELECT * FROM {table_name}", connection)

database = Database()