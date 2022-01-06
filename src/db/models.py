from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base


async def wrapped_models(Base: declarative_base):
    class Transfers(Base):
        __tablename__ = 'transfers'

        id = Column(Integer, primary_key=True, autoincrement=True)
        block = Column(Integer)
        token_address = Column(String)
        victim = Column(String)
        spender = Column(String)
        amount = Column(String)

    return [Transfers]
