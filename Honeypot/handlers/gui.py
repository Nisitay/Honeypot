class GUI():
    main = None

    @classmethod
    def add_ftp_log(cls, record):
        cls.main.addLog.emit(record)
