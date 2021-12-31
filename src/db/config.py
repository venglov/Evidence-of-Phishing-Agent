class Config:
    def __init__(self):
        self.transfers = None
        self.base = None

    def get_transfers(self):
        return self.transfers

    def set_tables(self, transfers):
        self.transfers = transfers

    def set_base(self, base):
        self.base = base


config = Config()
