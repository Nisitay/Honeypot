class GUI():
    main = None

    @classmethod
    def add_log(cls, record):
        cls.main.addLog.emit(record)
