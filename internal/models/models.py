from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Float, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from internal.db.database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="member")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    workspaces = relationship("Workspace", back_populates="owner")


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, unique=True, index=True)
    name = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Workspace(Base):
    __tablename__ = "workspaces"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    owner = relationship("User", back_populates="workspaces")
    targets = relationship("Target", back_populates="workspace")
    alert_configs = relationship("AlertConfig", back_populates="workspace")


class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=True)
    domain = Column(String, index=True)
    description = Column(Text, nullable=True)
    tags = Column(JSON, default=list)
    meta = Column(JSON, default=dict)
    added_at = Column(DateTime, default=datetime.utcnow)
    last_scanned = Column(DateTime, nullable=True)
    risk_score = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    assets = relationship("Asset", back_populates="target")
    workspace = relationship("Workspace", back_populates="targets")
    scan_jobs = relationship("ScanJob", back_populates="target")
    alert_configs = relationship("AlertConfig", back_populates="target")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    asset_type = Column(String)
    value = Column(String)
    details = Column(Text, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    tags = Column(JSON, default=list)
    cpe = Column(String, nullable=True)
    cve_ids = Column(JSON, default=list)
    screenshot_path = Column(String, nullable=True)
    meta = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    target = relationship("Target", back_populates="assets")


class AssetHistory(Base):
    __tablename__ = "asset_history"
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    target_id = Column(Integer, ForeignKey("targets.id"))
    field_changed = Column(String)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    change_type = Column(String)
    changed_at = Column(DateTime, default=datetime.utcnow)


class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    description = Column(Text, nullable=True)
    config = Column(JSON, default=dict)
    is_system = Column(Boolean, default=False)


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    scan_type = Column(String)
    scan_profile = Column(String, default="standard")
    status = Column(String, default="pending")
    progress = Column(Float, default=0.0)
    progress_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    results_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    triggered_by = Column(String, default="manual")
    target = relationship("Target", back_populates="scan_jobs")


class AlertConfig(Base):
    __tablename__ = "alert_configs"
    id = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, ForeignKey("workspaces.id"), nullable=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    name = Column(String)
    channel = Column(String)
    config = Column(JSON, default=dict)
    events = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    workspace = relationship("Workspace", back_populates="alert_configs")
    target = relationship("Target", back_populates="alert_configs")


class AlertEvent(Base):
    __tablename__ = "alert_events"
    id = Column(Integer, primary_key=True, index=True)
    alert_config_id = Column(Integer, ForeignKey("alert_configs.id"), nullable=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    event_type = Column(String)
    severity = Column(String)
    title = Column(String)
    message = Column(Text)
    extra_data = Column(JSON, default=dict)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
