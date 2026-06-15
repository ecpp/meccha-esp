#!/usr/bin/env python3
"""
Production-ready external box ESP for MECCHA CHAMELEON (UE5.6).
Fully external: scans GUObjectArray, walks objects, renders overlay.
"""
import sys
import struct
import math
import ctypes
from dataclasses import dataclass
from typing import Tuple

import pymem
from PyQt5.QtWidgets import (
    QApplication, QWidget, QCheckBox, QComboBox, QLabel,
    QVBoxLayout, QHBoxLayout, QPushButton, QFrame, QColorDialog,
    QSpinBox
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPainter, QPen, QColor, QFont


# ---------------------------------------------------------------------------
# Bootstrap offsets: stable UObject/UStruct/FField layout used to resolve
# everything else dynamically at runtime.
# ---------------------------------------------------------------------------
OFFSETS = {
    "UObjectBase::ClassPrivate": 0x10,
    "UObjectBase::NamePrivate": 0x18,
    "UObjectBase::OuterPrivate": 0x20,

    "UStruct::SuperStruct": 0x40,
    "UStruct::ChildProperties": 0x50,

    "FField::Next": 0x18,
    "FField::NamePrivate": 0x20,
    "FProperty::Offset_Internal": 0x44,

    # Nested struct layouts are extremely stable; keep as fallback.
    "FCameraCacheEntry::POV": 0x10,
    "FMinimalViewInfo::Location": 0x0,
    "FMinimalViewInfo::Rotation": 0x18,
    "FMinimalViewInfo::FOV": 0x30,
}


# ---------------------------------------------------------------------------
# Dynamic offset resolver: walks class FField property chains.
# ---------------------------------------------------------------------------
class OffsetResolver:
    """Resolves engine class property offsets by walking ChildProperties."""

    def __init__(self, pm, objects):
        self.pm = pm
        self.objects = objects
        self.cache = dict(OFFSETS)

    def _field_name(self, field):
        return self.objects.fnames.resolve(ru32(self.pm, field + self.cache["FField::NamePrivate"]))

    def _resolve_on_class(self, cls, prop_name):
        prop = rp(self.pm, cls + self.cache["UStruct::ChildProperties"])
        depth = 0
        while prop and depth < 512:
            name = self._field_name(prop)
            if name == prop_name:
                return ru32(self.pm, prop + self.cache["FProperty::Offset_Internal"])
            prop = rp(self.pm, prop + self.cache["FField::Next"])
            depth += 1
        return None

    def resolve(self, class_name, prop_name):
        key = f"{class_name}::{prop_name}"
        if key in self.cache:
            return self.cache[key]
        cls = self.objects.find_class(class_name)
        if not cls:
            return None
        offset = self._resolve_on_class(cls, prop_name)
        seen = {cls}
        while offset is None:
            super_cls = rp(self.pm, cls + self.cache["UStruct::SuperStruct"])
            if not super_cls or super_cls in seen:
                break
            seen.add(super_cls)
            offset = self._resolve_on_class(super_cls, prop_name)
        if offset is not None:
            self.cache[key] = offset
        return offset

    def resolve_map(self, mapping):
        out = {}
        for key, (cls, prop) in mapping.items():
            val = self.resolve(cls, prop)
            if val is None:
                raise RuntimeError(f"Could not resolve offset {key} ({cls}.{prop})")
            out[key] = val
        return out


# ---------------------------------------------------------------------------
# Memory primitives
# ---------------------------------------------------------------------------
def rp(pm, addr):
    try:
        return struct.unpack("<Q", pm.read_bytes(addr, 8))[0]
    except Exception:
        return 0


def ru32(pm, addr):
    try:
        return struct.unpack("<I", pm.read_bytes(addr, 4))[0]
    except Exception:
        return 0


def ru16(pm, addr):
    try:
        return struct.unpack("<H", pm.read_bytes(addr, 2))[0]
    except Exception:
        return 0


def rfloat(pm, addr):
    try:
        return struct.unpack("<f", pm.read_bytes(addr, 4))[0]
    except Exception:
        return 0.0


def rvec3(pm, addr):
    try:
        return struct.unpack("<ddd", pm.read_bytes(addr, 24))
    except Exception:
        return (0.0, 0.0, 0.0)


def read_array(pm, addr):
    try:
        data = rp(pm, addr)
        count = ru32(pm, addr + 8)
        cap = ru32(pm, addr + 0x10)
        return data, count, cap
    except Exception:
        return 0, 0, 0


def dist(a, b):
    return math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2)


# ---------------------------------------------------------------------------
# Pattern scanner
# ---------------------------------------------------------------------------
class PatternScanner:
    CHUNK_SIZE = 0x200000  # 2 MiB chunks to avoid huge allocations on shipping exes

    def __init__(self, pm, module_name):
        self.pm = pm
        self.module = pymem.process.module_from_name(pm.process_handle, module_name)
        if not self.module:
            raise RuntimeError(f"Module {module_name} not found")
        self.base = self.module.lpBaseOfDll
        self.size = self.module.SizeOfImage

    def _match_at(self, data, offset, pattern, mask):
        pat_len = len(pattern)
        for j in range(pat_len):
            if mask[j] and data[offset + j] != pattern[j]:
                return False
        return True

    def scan_all(self, pattern, mask):
        """Yield every match address in ascending order."""
        pat_len = len(pattern)
        if pat_len == 0 or self.size == 0:
            return
        step = self.CHUNK_SIZE
        for start in range(0, self.size, step):
            # Overlap reads by pat_len so patterns spanning chunk boundaries aren't missed.
            end = min(start + step + pat_len, self.size)
            read_size = end - start
            try:
                data = self.pm.read_bytes(self.base + start, read_size)
            except Exception:
                continue
            scan_len = len(data) - pat_len
            for i in range(scan_len):
                if self._match_at(data, i, pattern, mask):
                    yield self.base + start + i

    def scan(self, pattern, mask):
        for addr in self.scan_all(pattern, mask):
            return addr
        return 0


# ---------------------------------------------------------------------------
# FName + object array
# ---------------------------------------------------------------------------
class FNameResolver:
    # FNamePool block-pointer tables sit at different offsets depending on UE5 version.
    BLOCK_TABLE_OFFSETS = (0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
                           0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70)

    def __init__(self, pm, fname_pool):
        self.pm = pm
        self.fname_pool = fname_pool
        self.block_table_off = 0x10
        self.header_style = "ue5"  # or "ue4"
        self._detect_layout()

    def _read_entry(self, entry_id, table_off, style):
        block_idx = entry_id >> 16
        within = (entry_id & 0xFFFF) << 1
        block_addr = rp(self.pm, self.fname_pool + table_off + block_idx * 8)
        if not block_addr:
            return None
        hdr = ru16(self.pm, block_addr + within)
        if style == "ue4":
            # UE4: bIsWide (1 bit), Len (15 bits)
            is_wide = hdr & 1
            length = hdr >> 1
        elif style == "custom":
            # MECCHA CHAMELEON build: bIsWide (bit 0), Len (bits 6-15)
            is_wide = hdr & 1
            length = (hdr >> 6) & 0x3FF
        else:
            # Standard UE5: Len (10 bits), bIsWide (1 bit), LowercaseProbeHash (5 bits)
            length = hdr & 0x3FF
            is_wide = (hdr >> 10) & 1
        if length == 0 or length > 512:
            return None
        if is_wide:
            raw = self.pm.read_bytes(block_addr + within + 2, length * 2)
            return raw.decode("utf-16-le", errors="ignore")
        else:
            raw = self.pm.read_bytes(block_addr + within + 2, length)
            return raw.decode("latin-1")

    def _detect_layout(self):
        """Probe block-table offsets and header styles until entry 0 is 'None'."""
        for off in self.BLOCK_TABLE_OFFSETS:
            for style in ("custom", "ue5", "ue4"):
                try:
                    if self._read_entry(0, off, style) == "None":
                        self.block_table_off = off
                        self.header_style = style
                        return
                except Exception:
                    continue

    def resolve(self, entry_id):
        try:
            name = self._read_entry(entry_id, self.block_table_off, self.header_style)
            if name is not None:
                return name
        except Exception:
            pass
        # If the cached layout fails, re-probe once per call until something works.
        for off in self.BLOCK_TABLE_OFFSETS:
            for style in ("custom", "ue5", "ue4"):
                if off == self.block_table_off and style == self.header_style:
                    continue
                try:
                    name = self._read_entry(entry_id, off, style)
                    if name is not None:
                        self.block_table_off = off
                        self.header_style = style
                        return name
                except Exception:
                    continue
        return None


class UObjectArray:
    def __init__(self, pm, guobject_array, fname_pool):
        self.pm = pm
        self.guobject_array = guobject_array
        self.fnames = FNameResolver(pm, fname_pool)
        self._meta_class_addr = None
        self._class_cache = {}

    def _obj_name(self, obj):
        return self.fnames.resolve(ru32(self.pm, obj + OFFSETS["UObjectBase::NamePrivate"]))

    def _obj_class(self, obj):
        return rp(self.pm, obj + OFFSETS["UObjectBase::ClassPrivate"])

    def iter_objects(self):
        objects_ptr = rp(self.pm, self.guobject_array + 0x10)
        if not objects_ptr:
            return
        chunk_idx = 0
        while chunk_idx < 64:
            chunk = rp(self.pm, objects_ptr + chunk_idx * 8)
            if not chunk:
                break
            for within in range(0x10000):
                obj = rp(self.pm, chunk + within * 0x18)
                if obj:
                    yield obj
            chunk_idx += 1

    def _meta_class(self):
        # Don't cache a failed search; the object array may still be loading.
        if self._meta_class_addr is None or not self._meta_class_addr:
            for obj in self.iter_objects():
                if self._obj_name(obj) == "Class":
                    self._meta_class_addr = obj
                    break
        return self._meta_class_addr

    def find_class(self, name):
        cached = self._class_cache.get(name)
        if cached:
            # Validate the cached pointer still names itself correctly.
            if self._obj_name(cached) == name:
                return cached
            del self._class_cache[name]
        meta = self._meta_class()
        if not meta:
            return 0
        for obj in self.iter_objects():
            if self._obj_class(obj) == meta and self._obj_name(obj) == name:
                self._class_cache[name] = obj
                return obj
        return 0

    def find_first_instance(self, class_name, skip_default=True):
        cls = self.find_class(class_name)
        if not cls:
            return 0
        for obj in self.iter_objects():
            if self._obj_class(obj) == cls:
                name = self._obj_name(obj)
                if skip_default and name and name.startswith("Default__"):
                    continue
                return obj
        return 0


# ---------------------------------------------------------------------------
# Game reader
# ---------------------------------------------------------------------------
class MecchaESP:
    PROCESS_NAME = "PenguinHotel-Win64-Shipping.exe"
    MODULE_NAME = "PenguinHotel-Win64-Shipping.exe"

    GUOBJECT_SIG = bytes([
        0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x01, 0x45, 0x8B, 0xD1
    ])
    GUOBJECT_MASK = bytes([1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1])

    # Multiple FNamePool references can appear; we verify by trying to read names.
    FNAMEPOOL_PATTERNS = (
        # lea rcx,[FNamePool]; call FName::FName; mov r8,rax
        (bytes([0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
                0xE8, 0x00, 0x00, 0x00, 0x00,
                0x4C, 0x8B, 0xC0]),
         bytes([1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1])),
        # lea rcx,[FNamePool]; call FName::FName; mov rax,[rbx+...]
        (bytes([0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
                0xE8, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x8B]),
         bytes([1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1])),
        # lea rsi,[FNamePool]
        (bytes([0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]),
         bytes([1, 1, 1, 0, 0, 0, 0])),
        # lea rdi,[FNamePool]
        (bytes([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]),
         bytes([1, 1, 1, 0, 0, 0, 0])),
    )
    FNAMEPOOL_DELTA = 0xE3B40

    OFFSET_MAP = {
        "UWorld::GameState": ("World", "GameState"),
        "UWorld::OwningGameInstance": ("World", "OwningGameInstance"),
        "UGameInstance::LocalPlayers": ("GameInstance", "LocalPlayers"),
        "UPlayer::PlayerController": ("Player", "PlayerController"),
        "UEngine::GameViewport": ("Engine", "GameViewport"),
        "UGameViewportClient::World": ("GameViewportClient", "World"),
        "AGameStateBase::PlayerArray": ("GameStateBase", "PlayerArray"),
        "APlayerState::PawnPrivate": ("PlayerState", "PawnPrivate"),
        "AController::PlayerState": ("Controller", "PlayerState"),
        "APlayerController::AcknowledgedPawn": ("PlayerController", "AcknowledgedPawn"),
        "APlayerController::PlayerCameraManager": ("PlayerController", "PlayerCameraManager"),
        "APlayerCameraManager::CameraCachePrivate": ("PlayerCameraManager", "CameraCachePrivate"),
        "AActor::RootComponent": ("Actor", "RootComponent"),
        "USceneComponent::RelativeLocation": ("SceneComponent", "RelativeLocation"),
        # Note: UWorld::PersistentLevel and ULevel::Actors are only used in the
        # level-actors fallback; they are resolved lazily with hardcoded defaults.
    }

    def __init__(self):
        self.pm = pymem.Pymem(self.PROCESS_NAME)
        self.guobject_array = self._scan_guobject_array()
        if not self.guobject_array:
            raise RuntimeError("Could not find GUObjectArray via pattern scan")
        self.fname_pool = self._scan_fname_pool()
        if not self.fname_pool:
            raise RuntimeError("Could not find FNamePool via pattern scan or delta fallback")
        self.objects = UObjectArray(self.pm, self.guobject_array, self.fname_pool)
        # Sanity-check globals; on failure we still open, but warn in overlay.
        self._globals_ok = self._verify_globals()
        self.resolver = OffsetResolver(self.pm, self.objects)
        self.offsets = self.resolver.resolve_map(self.OFFSET_MAP)
        # Fill in the stable nested struct offsets from the bootstrap dict.
        for key in ("FCameraCacheEntry::POV", "FMinimalViewInfo::Location",
                    "FMinimalViewInfo::Rotation", "FMinimalViewInfo::FOV"):
            self.offsets[key] = OFFSETS[key]
        self.gengine = self.objects.find_first_instance("GameEngine")
        if not self.gengine:
            raise RuntimeError("Could not find GEngine instance")

    def _scan_guobject_array(self):
        scanner = PatternScanner(self.pm, self.MODULE_NAME)
        addr = scanner.scan(self.GUOBJECT_SIG, self.GUOBJECT_MASK)
        if not addr:
            return 0
        rel = struct.unpack("<i", self.pm.read_bytes(addr + 3, 4))[0]
        return addr + 7 + rel

    def _scan_fname_pool(self):
        # The delta has been stable for this build; use it as the default.
        delta_candidate = self.guobject_array - self.FNAMEPOOL_DELTA
        if self._verify_fname_pool(delta_candidate):
            return delta_candidate
        # Try a few common FNamePool signatures as backups.
        scanner = PatternScanner(self.pm, self.MODULE_NAME)
        for sig, mask in self.FNAMEPOOL_PATTERNS:
            for addr in scanner.scan_all(sig, mask):
                rel = struct.unpack("<i", self.pm.read_bytes(addr + 3, 4))[0]
                candidate = addr + 7 + rel
                if self._verify_fname_pool(candidate):
                    return candidate
        # Even if unverified, fall back to the delta so the ESP can still open.
        # Name resolution may self-correct via the resolver's lazy offset probe.
        return delta_candidate

    def _verify_fname_pool(self, pool_addr):
        resolver = FNameResolver(self.pm, pool_addr)
        if resolver.resolve(0) == "None":
            return True
        # Some builds don't keep "None" at id 0; settle for any printable name.
        for probe in (0, 1, 2, 3, 4, 5):
            name = resolver.resolve(probe)
            if name and 0 < len(name) <= 128 and name.isprintable():
                return True
        return False

    def _verify_globals(self):
        # GUObjectArray + 0x10 is TUObjectArray::Objects; read its header.
        obj_array = self.guobject_array + 0x10
        num = ru32(self.pm, obj_array + 0x14)
        max_chunks = ru32(self.pm, obj_array + 0x18)
        if num == 0 or num > 10_000_000 or max_chunks == 0 or max_chunks > 64:
            return False
        # We should be able to find the meta Class object.
        return self.objects.find_class("Class") != 0

    def _get_world(self):
        viewport = rp(self.pm, self.gengine + self.offsets["UEngine::GameViewport"])
        if not viewport:
            return 0
        return rp(self.pm, viewport + self.offsets["UGameViewportClient::World"])

    def _get_local_controller(self, world):
        if not world:
            return 0
        gi = rp(self.pm, world + self.offsets["UWorld::OwningGameInstance"])
        if not gi:
            return 0
        lp_data, lp_count, _ = read_array(self.pm, gi + self.offsets["UGameInstance::LocalPlayers"])
        if not lp_data or lp_count == 0:
            return 0
        local_player = rp(self.pm, lp_data)
        if not local_player:
            return 0
        return rp(self.pm, local_player + self.offsets["UPlayer::PlayerController"])

    def get_camera(self):
        world = self._get_world()
        if not world:
            return None
        pc = self._get_local_controller(world)
        if not pc:
            return None
        cam = rp(self.pm, pc + self.offsets["APlayerController::PlayerCameraManager"])
        if not cam:
            return None
        cc = cam + self.offsets["APlayerCameraManager::CameraCachePrivate"]
        pov = cc + self.offsets["FCameraCacheEntry::POV"]
        loc = rvec3(self.pm, pov + self.offsets["FMinimalViewInfo::Location"])
        rot = rvec3(self.pm, pov + self.offsets["FMinimalViewInfo::Rotation"])
        fov = rfloat(self.pm, pov + self.offsets["FMinimalViewInfo::FOV"])
        return {"loc": loc, "rot": rot, "fov": fov}

    def _class_name(self, obj):
        if not obj:
            return ""
        cls = rp(self.pm, obj + OFFSETS["UObjectBase::ClassPrivate"])
        return self.objects._obj_name(cls) if cls else ""

    def iter_players(self, include_local=False, team_filter=False):
        world = self._get_world()
        if not world:
            return
        gamestate = rp(self.pm, world + self.offsets["UWorld::GameState"])
        pc = self._get_local_controller(world)
        local_pawn = rp(self.pm, pc + self.offsets["APlayerController::AcknowledgedPawn"]) if pc else 0
        local_ps = rp(self.pm, pc + self.offsets["AController::PlayerState"]) if pc else 0
        local_pawn_cls = self._class_name(local_pawn)

        if include_local and local_pawn:
            root = rp(self.pm, local_pawn + self.offsets["AActor::RootComponent"])
            if root:
                pos = rvec3(self.pm, root + self.offsets["USceneComponent::RelativeLocation"])
                yield True, pos, 0

        yielded = 0
        if gamestate:
            pa_data, pa_count, _ = read_array(self.pm, gamestate + self.offsets["AGameStateBase::PlayerArray"])
            if pa_data and pa_count > 0:
                for i in range(pa_count):
                    ps = rp(self.pm, pa_data + i * 8)
                    if not ps or ps == local_ps:
                        continue
                    pawn = rp(self.pm, ps + self.offsets["APlayerState::PawnPrivate"])
                    if not pawn or pawn == local_pawn:
                        continue
                    pawn_cls = self._class_name(pawn)
                    if not pawn_cls:
                        continue
                    if team_filter and local_pawn_cls:
                        # If every player uses the same pawn class, filtering by exact class
                        # would hide everyone. That case is recovered by the level-actor fallback.
                        if pawn_cls == local_pawn_cls:
                            continue
                        if "Spectate" in pawn_cls:
                            continue
                    root = rp(self.pm, pawn + self.offsets["AActor::RootComponent"])
                    if not root:
                        continue
                    pos = rvec3(self.pm, root + self.offsets["USceneComponent::RelativeLocation"])
                    yielded += 1
                    yield False, pos, i

        # Fallback: if the PlayerArray path produced nothing (empty array, unresolved
        # offsets, or team-filter hid every candidate), walk the persistent level actors.
        if yielded == 0:
            persistent_level_off = self.resolver.resolve("World", "PersistentLevel") if hasattr(self, "resolver") else None
            if persistent_level_off is None:
                persistent_level_off = 0x30
            level = rp(self.pm, world + persistent_level_off)
            if level:
                actors_off = self.resolver.resolve("Level", "Actors") if hasattr(self, "resolver") else None
                if actors_off is None:
                    actors_off = 0x98
                actors_data, actors_count, _ = read_array(self.pm, level + actors_off)
                if actors_data and actors_count > 0:
                    for i in range(actors_count):
                        actor = rp(self.pm, actors_data + i * 8)
                        if not actor or actor == local_pawn:
                            continue
                        cls_name = self._class_name(actor)
                        if not cls_name or "Character" not in cls_name:
                            continue
                        root = rp(self.pm, actor + self.offsets["AActor::RootComponent"])
                        if not root:
                            continue
                        pos = rvec3(self.pm, root + self.offsets["USceneComponent::RelativeLocation"])
                        yield False, pos, i


# ---------------------------------------------------------------------------
# World-to-screen
# ---------------------------------------------------------------------------
def rotation_to_axes(rot):
    pitch, yaw, roll = [math.radians(x) for x in rot]
    sp, cp = math.sin(pitch), math.cos(pitch)
    sy, cy = math.sin(yaw), math.cos(yaw)
    sr, cr = math.sin(roll), math.cos(roll)

    forward = (cp * cy, cp * sy, sp)
    right = (sr * sp * cy - cr * sy, sr * sp * sy + cr * cy, -sr * cp)
    up = (-(cr * sp * cy + sr * sy), cy * sr - cr * sp * sy, cr * cp)
    return forward, right, up


def w2s(world_pos, camera, screen_w, screen_h):
    cam_loc = camera["loc"]
    cam_rot = camera["rot"]
    fov = camera["fov"]

    forward, right, up = rotation_to_axes(cam_rot)

    dx = world_pos[0] - cam_loc[0]
    dy = world_pos[1] - cam_loc[1]
    dz = world_pos[2] - cam_loc[2]

    view_x = dx * forward[0] + dy * forward[1] + dz * forward[2]
    view_y = dx * right[0] + dy * right[1] + dz * right[2]
    view_z = dx * up[0] + dy * up[1] + dz * up[2]

    if view_x <= 0.1:
        return None

    aspect = screen_w / screen_h
    tan_hfov = math.tan(math.radians(fov) / 2.0)

    ndc_x = view_y / (view_x * tan_hfov)
    ndc_y = view_z / (view_x * tan_hfov / aspect)

    screen_x = (1.0 + ndc_x) * screen_w / 2.0
    screen_y = (1.0 - ndc_y) * screen_h / 2.0

    if not (0 <= screen_x <= screen_w and 0 <= screen_y <= screen_h):
        return None
    return (screen_x, screen_y)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
@dataclass
class Config:
    enabled: bool = True
    box_esp: bool = True
    box_type: str = "corner"  # "2d" or "corner"
    show_local: bool = True
    show_names: bool = True
    show_distance: bool = True
    snap_lines: bool = True
    enemy_color: Tuple[int, int, int] = (255, 0, 0)
    local_color: Tuple[int, int, int] = (0, 255, 0)
    box_height_world: float = 100.0
    box_width_ratio: float = 0.45
    box_y_offset: int = 0
    team_filter: bool = True


# ---------------------------------------------------------------------------
# Menu window
# ---------------------------------------------------------------------------
class Menu(QWidget):
    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.setWindowTitle("MECCHA ESP Menu")
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._drag_pos = None

        self._build_ui()
        self.setFixedSize(260, 440)

    def _build_ui(self):
        container = QFrame(self)
        container.setStyleSheet("""
            QFrame {
                background-color: rgba(20, 20, 20, 220);
                border: 1px solid #444;
                border-radius: 8px;
            }
            QLabel {
                color: #eee;
                font-size: 12px;
            }
            QCheckBox {
                color: #eee;
                font-size: 12px;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QComboBox {
                background-color: #333;
                color: #eee;
                border: 1px solid #555;
                padding: 4px;
            }
            QPushButton {
                background-color: #333;
                color: #eee;
                border: 1px solid #555;
                padding: 6px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)

        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        title = QLabel("MECCHA ESP")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #0f0;")
        layout.addWidget(title)

        self.cb_enabled = self._chk("ESP Enabled", "enabled")
        self.cb_box = self._chk("Box ESP", "box_esp")
        self.cb_local = self._chk("Show Local Player", "show_local")
        self.cb_names = self._chk("Show Names", "show_names")
        self.cb_dist = self._chk("Show Distance", "show_distance")
        self.cb_snap = self._chk("Snap Lines", "snap_lines")
        self.cb_team = self._chk("Team Filter (Hunters)", "team_filter")
        layout.addWidget(self.cb_enabled)
        layout.addWidget(self.cb_box)
        layout.addWidget(self.cb_local)
        layout.addWidget(self.cb_names)
        layout.addWidget(self.cb_dist)
        layout.addWidget(self.cb_snap)
        layout.addWidget(self.cb_team)

        box_row = QHBoxLayout()
        box_row.addWidget(QLabel("Box Style:"))
        self.cmb_box = QComboBox()
        self.cmb_box.addItems(["2D", "Corner"])
        self.cmb_box.setCurrentText("Corner" if self.config.box_type == "corner" else "2D")
        self.cmb_box.currentTextChanged.connect(self._on_box_changed)
        box_row.addWidget(self.cmb_box)
        layout.addLayout(box_row)

        color_row = QHBoxLayout()
        self.btn_enemy_color = QPushButton("Enemy Color")
        self.btn_enemy_color.clicked.connect(self._pick_enemy_color)
        self.btn_local_color = QPushButton("Local Color")
        self.btn_local_color.clicked.connect(self._pick_local_color)
        color_row.addWidget(self.btn_enemy_color)
        color_row.addWidget(self.btn_local_color)
        layout.addLayout(color_row)

        height_row = QHBoxLayout()
        height_row.addWidget(QLabel("Box Height:"))
        self.spn_height = QSpinBox()
        self.spn_height.setRange(50, 250)
        self.spn_height.setValue(int(self.config.box_height_world))
        self.spn_height.valueChanged.connect(lambda v: setattr(self.config, "box_height_world", float(v)))
        height_row.addWidget(self.spn_height)
        layout.addLayout(height_row)

        offset_row = QHBoxLayout()
        offset_row.addWidget(QLabel("Y Offset:"))
        self.spn_yoff = QSpinBox()
        self.spn_yoff.setRange(-50, 50)
        self.spn_yoff.setValue(self.config.box_y_offset)
        self.spn_yoff.valueChanged.connect(lambda v: setattr(self.config, "box_y_offset", v))
        offset_row.addWidget(self.spn_yoff)
        layout.addLayout(offset_row)

        hint = QLabel("Insert / F1 to toggle menu")
        hint.setStyleSheet("color: #888; font-size: 10px;")
        layout.addWidget(hint)

        outer = QVBoxLayout(self)
        outer.addWidget(container)
        outer.setContentsMargins(0, 0, 0, 0)
        self.setLayout(outer)

    def _chk(self, text, attr):
        cb = QCheckBox(text)
        cb.setChecked(getattr(self.config, attr))
        cb.stateChanged.connect(lambda s, a=attr: setattr(self.config, a, bool(s)))
        return cb

    def _on_box_changed(self, text):
        self.config.box_type = text.lower()

    def _pick_enemy_color(self):
        c = QColorDialog.getColor(QColor(*self.config.enemy_color), self)
        if c.isValid():
            self.config.enemy_color = (c.red(), c.green(), c.blue())

    def _pick_local_color(self):
        c = QColorDialog.getColor(QColor(*self.config.local_color), self)
        if c.isValid():
            self.config.local_color = (c.red(), c.green(), c.blue())

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None and event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self._drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_pos = None


# ---------------------------------------------------------------------------
# Overlay
# ---------------------------------------------------------------------------
class Overlay(QWidget):
    def __init__(self, esp: MecchaESP, config: Config, menu: Menu):
        super().__init__()
        self.esp = esp
        self.config = config
        self.menu = menu
        self.setWindowFlags(
            Qt.FramelessWindowHint
            | Qt.WindowStaysOnTopHint
            | Qt.Tool
            | Qt.WindowTransparentForInput
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setWindowTitle("MECCHA ESP")

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_overlay)
        self.timer.start(16)

        self.game_hwnd = self._find_game_window()
        self._resize_to_game()

    def _find_game_window(self):
        try:
            import win32gui
            return win32gui.FindWindow(None, "Chameleon  ")
        except Exception:
            return 0

    def _resize_to_game(self):
        try:
            import win32gui
            if self.game_hwnd:
                rect = win32gui.GetClientRect(self.game_hwnd)
                tl = win32gui.ClientToScreen(self.game_hwnd, (rect[0], rect[1]))
                br = win32gui.ClientToScreen(self.game_hwnd, (rect[2], rect[3]))
                self.setGeometry(tl[0], tl[1], br[0] - tl[0], br[1] - tl[1])
            else:
                self.setGeometry(0, 0, 1920, 1080)
        except Exception:
            self.setGeometry(0, 0, 1920, 1080)

    def update_overlay(self):
        self._resize_to_game()
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        font = QFont("Consolas", 10)
        painter.setFont(font)

        w = self.width()
        h = self.height()

        if not self.config.enabled:
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.drawText(10, 20, "ESP OFF")
            return

        cam = self.esp.get_camera()
        if not cam:
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.drawText(10, 20, "NO CAMERA")
            return

        count = 0
        for is_local, pos, idx in self.esp.iter_players(include_local=self.config.show_local, team_filter=self.config.team_filter):
            screen_info = self._project_box(pos, cam, w, h)
            if not screen_info:
                continue
            sx, sy, box_w, box_h = screen_info
            color = self.config.local_color if is_local else self.config.enemy_color

            if self.config.box_esp:
                self._draw_box(painter, sx, sy, box_w, box_h, color)

            if self.config.snap_lines:
                painter.setPen(QPen(QColor(*color), 1))
                painter.drawLine(int(w / 2), int(h), int(sx), int(sy + box_h / 2))

            label_parts = []
            if self.config.show_names:
                label_parts.append("YOU" if is_local else f"Enemy {idx}")
            if self.config.show_distance:
                d = int(dist(pos, cam["loc"]) / 100)
                label_parts.append(f"{d}m")
            if label_parts:
                painter.setPen(QPen(QColor(*color)))
                text = " | ".join(label_parts)
                painter.drawText(int(sx - box_w / 2), int(sy - box_h / 2 - 6), text)

            count += 1

        painter.setPen(QPen(QColor(255, 255, 255)))
        painter.drawText(10, 20, f"Players: {count}")

    def _project_box(self, feet_pos, camera, screen_w, screen_h):
        head_pos = (feet_pos[0], feet_pos[1], feet_pos[2] + self.config.box_height_world)
        s_feet = w2s(feet_pos, camera, screen_w, screen_h)
        s_head = w2s(head_pos, camera, screen_w, screen_h)
        if not s_feet or not s_head:
            return None

        box_h = abs(s_feet[1] - s_head[1])
        box_w = box_h * self.config.box_width_ratio
        cx = s_feet[0]
        cy = (s_feet[1] + s_head[1]) / 2 + self.config.box_y_offset
        return (cx, cy, box_w, box_h)

    def _draw_box(self, painter, cx, cy, bw, bh, color):
        x1 = int(cx - bw / 2)
        y1 = int(cy - bh / 2)
        x2 = int(cx + bw / 2)
        y2 = int(cy + bh / 2)
        painter.setPen(QPen(QColor(*color), 2))

        if self.config.box_type == "corner":
            corner = int(min(bw, bh) * 0.25)
            # Top-left
            painter.drawLine(x1, y1, x1 + corner, y1)
            painter.drawLine(x1, y1, x1, y1 + corner)
            # Top-right
            painter.drawLine(x2, y1, x2 - corner, y1)
            painter.drawLine(x2, y1, x2, y1 + corner)
            # Bottom-left
            painter.drawLine(x1, y2, x1 + corner, y2)
            painter.drawLine(x1, y2, x1, y2 - corner)
            # Bottom-right
            painter.drawLine(x2, y2, x2 - corner, y2)
            painter.drawLine(x2, y2, x2, y2 - corner)
        else:
            painter.drawRect(x1, y1, int(bw), int(bh))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _set_dpi_aware():
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(-4)  # PerMonitorAwareV2
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main():
    _set_dpi_aware()
    app = QApplication(sys.argv)
    config = Config()
    esp = MecchaESP()
    menu = Menu(config)
    overlay = Overlay(esp, config, menu)
    overlay.show()
    menu.show()

    # Poll Insert/F1 globally to toggle menu visibility.
    VK_INSERT = 0x2D
    VK_F1 = 0x70
    _key_states = {"insert": False, "f1": False}

    def poll_keys():
        for vk, name in [(VK_INSERT, "insert"), (VK_F1, "f1")]:
            state = ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000
            if state and not _key_states[name]:
                menu.setVisible(not menu.isVisible())
            _key_states[name] = bool(state)

    key_timer = QTimer()
    key_timer.timeout.connect(poll_keys)
    key_timer.start(50)

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
