import uuid
from datetime import datetime
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db import Base

class User(Base):
    __tablename__="users"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str]=mapped_column(String(320), unique=True)
    password_hash: Mapped[str]=mapped_column(Text)
    is_active: Mapped[bool]=mapped_column(Boolean, default=True)
    failed_logins: Mapped[int]=mapped_column(Integer, default=0)
    locked_until: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    roles: Mapped[list["Role"]]=relationship(secondary="user_roles", lazy="selectin")

class Role(Base):
    __tablename__="roles"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str]=mapped_column(String(100), unique=True)
    permissions: Mapped[list["Permission"]]=relationship(secondary="role_permissions", lazy="selectin")
class Permission(Base):
    __tablename__="permissions"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code: Mapped[str]=mapped_column(String(100), unique=True)
class UserRole(Base):
    __tablename__="user_roles"
    user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id"), primary_key=True)
    role_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("roles.id"), primary_key=True)
class RolePermission(Base):
    __tablename__="role_permissions"
    role_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("roles.id"), primary_key=True)
    permission_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("permissions.id"), primary_key=True)
class Device(Base):
    __tablename__="devices"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_identifier: Mapped[str]=mapped_column(String(200), unique=True)
    hostname: Mapped[str]=mapped_column(String(255))
    username: Mapped[str|None]=mapped_column(String(255))
    ip_address: Mapped[str|None]=mapped_column(INET)
    os_name: Mapped[str|None]=mapped_column(String(100))
    os_version: Mapped[str|None]=mapped_column(String(100))
    agent_version: Mapped[str|None]=mapped_column(String(50))
    vlan: Mapped[str|None]=mapped_column(String(100))
    first_seen: Mapped[datetime]=mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    last_heartbeat: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    credential_revoked_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    agent_identity: Mapped[uuid.UUID|None]=mapped_column(UUID(as_uuid=True),unique=True)
    credential_hash: Mapped[str|None]=mapped_column(String(64))
    credential_version: Mapped[int]=mapped_column(Integer,default=1)
    architecture: Mapped[str|None]=mapped_column(String(30)); mac_address: Mapped[str|None]=mapped_column(String(17))
    boot_time: Mapped[datetime|None]=mapped_column(DateTime(timezone=True)); uptime_seconds: Mapped[int|None]=mapped_column(BigInteger)
    last_heartbeat_ip: Mapped[str|None]=mapped_column(INET); current_status: Mapped[str]=mapped_column(String(10),default="OFFLINE")
    enrollment_state: Mapped[str]=mapped_column(String(20),default="ENROLLED"); group_name: Mapped[str|None]=mapped_column(String(100)); department: Mapped[str|None]=mapped_column(String(100))
    metadata_: Mapped[dict]=mapped_column("metadata", JSONB, default=dict)
class AgentEnrollment(Base):
    __tablename__="agent_enrollments"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); token_hash: Mapped[str]=mapped_column(String(64),unique=True); expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True)); used_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True)); created_by: Mapped[uuid.UUID|None]=mapped_column(ForeignKey("users.id")); created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now()); revoked_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True)); max_uses: Mapped[int]=mapped_column(Integer,default=1); use_count: Mapped[int]=mapped_column(Integer,default=0); group_name: Mapped[str|None]=mapped_column(String(100)); department: Mapped[str|None]=mapped_column(String(100))
class DeviceStateTransition(Base):
    __tablename__="device_state_transitions"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4); device_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("devices.id",ondelete="CASCADE")); occurred_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now()); previous_status: Mapped[str]=mapped_column(String(10)); new_status: Mapped[str]=mapped_column(String(10))
class Policy(Base):
    __tablename__="policies"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str]=mapped_column(String(200), unique=True)
    default_action: Mapped[str]=mapped_column(String(10), default="BLOCK")
    active_version: Mapped[int]=mapped_column(Integer, default=1)
class PolicyRule(Base):
    __tablename__="policy_rules"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    version: Mapped[int]=mapped_column(Integer)
    priority: Mapped[int]=mapped_column(Integer)
    action: Mapped[str]=mapped_column(String(10))
    domain_pattern: Mapped[str]=mapped_column(String(253))
    expires_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    enabled: Mapped[bool]=mapped_column(Boolean, default=True)
class AuditEvent(Base):
    __tablename__="audit_events"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), server_default=func.now())
    actor_id: Mapped[uuid.UUID|None]=mapped_column(ForeignKey("users.id"))
    action: Mapped[str]=mapped_column(String(150))
    resource_type: Mapped[str]=mapped_column(String(100))
    resource_id: Mapped[str|None]=mapped_column(String(200))
    source_ip: Mapped[str|None]=mapped_column(INET)
    previous_value: Mapped[dict|None]=mapped_column(JSONB)
    new_value: Mapped[dict|None]=mapped_column(JSONB)
    result: Mapped[str]=mapped_column(String(30))
    request_id: Mapped[str]=mapped_column(String(64))
class ServiceCredential(Base):
    __tablename__="service_credentials"
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str]=mapped_column(String(150), unique=True)
    kind: Mapped[str]=mapped_column(String(30))
    secret_hash: Mapped[str]=mapped_column(String(64))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
class TelemetryEventId(Base):
    __tablename__="event_ids"
    __table_args__={"schema":"telemetry"}
    event_id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True), primary_key=True)
    event_time: Mapped[datetime]=mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), server_default=func.now())
class ProxyEvent(Base):
    __tablename__="proxy_events"; __table_args__={"schema":"telemetry"}
    id: Mapped[uuid.UUID]=mapped_column(UUID(as_uuid=True),primary_key=True)
    occurred_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),primary_key=True)
    received_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now())
    device_id: Mapped[uuid.UUID|None]=mapped_column(UUID(as_uuid=True)); user_id: Mapped[uuid.UUID|None]=mapped_column(UUID(as_uuid=True))
    username: Mapped[str|None]=mapped_column(String(255)); hostname: Mapped[str|None]=mapped_column(String(255)); source_ip: Mapped[str|None]=mapped_column(INET)
    domain: Mapped[str]=mapped_column(String(253)); url: Mapped[str|None]=mapped_column(Text); destination_ip: Mapped[str|None]=mapped_column(INET)
    protocol: Mapped[str]=mapped_column(String(20)); port: Mapped[int]=mapped_column(Integer); method: Mapped[str|None]=mapped_column(String(20)); status_code: Mapped[int|None]=mapped_column(SmallInteger)
    action: Mapped[str]=mapped_column(String(10)); policy_id: Mapped[uuid.UUID|None]=mapped_column(UUID(as_uuid=True)); matched_rule_id: Mapped[uuid.UUID|None]=mapped_column(UUID(as_uuid=True)); category: Mapped[str|None]=mapped_column(String(100))
    bytes_up: Mapped[int]=mapped_column(BigInteger,default=0); bytes_down: Mapped[int]=mapped_column(BigInteger,default=0); duration_ms: Mapped[int|None]=mapped_column(BigInteger); idempotency_key: Mapped[str]=mapped_column(String(100))
