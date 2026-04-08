from sqlalchemy import Column, String, Integer, BigInteger, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
import uuid

DATABASE_URL = "sqlite+aiosqlite:///./ids.db"

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def generate_uuid():
    return str(uuid.uuid4())


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    severity = Column(String(10), nullable=False, index=True)
    category = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_ip = Column(String(45), nullable=False)
    dest_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    signature_id = Column(String(100), nullable=True)
    detection_method = Column(String(30), nullable=False)
    resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(100), nullable=True)


class CapturedPacket(Base):
    __tablename__ = "captured_packets"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=False)
    length = Column(Integer, default=0)
    ttl = Column(Integer, default=64)
    tcp_flags = Column(String(20), nullable=True)
    is_alert = Column(Boolean, default=False)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with async_session() as session:
        yield session
