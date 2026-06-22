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
    QSpinBox, QDoubleSpinBox
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


def wfloat(pm, addr, value):
    try:
        pm.write_bytes(addr, struct.pack("<f", value), 4)
        return True
    except Exception:
        return False


def rvec3(pm, addr):
    try:
        return struct.unpack("<ddd", pm.read_bytes(addr, 24))
    except Exception:
        return (0.0, 0.0, 0.0)


def rrot(pm, addr):
    """Read an FRotator (Pitch/Yaw/Roll as floats, 12 bytes)."""
    try:
        return struct.unpack("<fff", pm.read_bytes(addr, 12))
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
        "AController::ControlRotation": ("Controller", "ControlRotation"),
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

    def _read_pov(self, pov_addr):
        """Read a minimal view POV from the given address."""
        return {
            "loc": rvec3(self.pm, pov_addr + self.offsets["FMinimalViewInfo::Location"]),
            "rot": rvec3(self.pm, pov_addr + self.offsets["FMinimalViewInfo::Rotation"]),
            "fov": rfloat(self.pm, pov_addr + self.offsets["FMinimalViewInfo::FOV"]),
        }

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

        # Primary: CameraCachePrivate (always reflects the current camera).
        cc = cam + self.offsets["APlayerCameraManager::CameraCachePrivate"]
        pov = cc + self.offsets["FCameraCacheEntry::POV"]
        try:
            camera = self._read_pov(pov)
        except Exception:
            camera = None

        # Fallback: PlayerCameraManager->ViewTarget.POV (some spectate/free-look modes).
        if (camera is None or
            (abs(camera["loc"][0]) < 0.01 and abs(camera["loc"][1]) < 0.01 and abs(camera["loc"][2]) < 0.01) or
            camera["fov"] <= 0.0):
            vt_off = self.offsets.get("APlayerCameraManager::ViewTarget")
            vt_pov_off = self.offsets.get("FTViewTarget::POV")
            if vt_off is not None and vt_pov_off is not None:
                try:
                    fallback = self._read_pov(cam + vt_off + vt_pov_off)
                    if fallback["fov"] > 0.0:
                        camera = fallback
                except Exception:
                    pass

        if camera is None or camera["fov"] <= 0.0:
            return None
        return camera

    def _class_name(self, obj):
        if not obj:
            return ""
        cls = rp(self.pm, obj + OFFSETS["UObjectBase::ClassPrivate"])
        return self.objects._obj_name(cls) if cls else ""

    def _pawn_controller(self, pawn):
        if not pawn:
            return 0
        off = self.offsets.get("APawn::Controller")
        if off is None:
            return 0
        return rp(self.pm, pawn + off)

    def _pawn_playerstate(self, pawn):
        if not pawn:
            return 0
        off = self.offsets.get("APawn::PlayerState")
        if off is None:
            return 0
        return rp(self.pm, pawn + off)

    def _actor_owner(self, actor):
        if not actor:
            return 0
        off = self.offsets.get("AActor::Owner")
        if off is None:
            return 0
        return rp(self.pm, actor + off)

    def _component_world_pos(self, component):
        """Read a USceneComponent's world translation from ComponentToWorld."""
        if not component:
            return None
        ctw_off = self.offsets.get("USceneComponent::ComponentToWorld")
        trans_off = self.offsets.get("FTransform::Translation")
        if ctw_off is None or trans_off is None:
            return None
        try:
            return rvec3(self.pm, component + ctw_off + trans_off)
        except Exception:
            return None

    def _actor_position(self, actor):
        """Return the best available world position for an actor.

        The old RelativeLocation path was working for this game, so it stays
        primary. ComponentToWorld is only used as a fallback if RelativeLocation
        is missing or clearly uninitialized.
        """
        if not actor:
            return None
        root = rp(self.pm, actor + self.offsets["AActor::RootComponent"])
        if root:
            rel_off = self.offsets.get("USceneComponent::RelativeLocation")
            if rel_off is not None:
                try:
                    pos = rvec3(self.pm, root + rel_off)
                    # Only fall through to ComponentToWorld if RelativeLocation
                    # is clearly uninitialized (origin-only).
                    if not (abs(pos[0]) < 0.01 and abs(pos[1]) < 0.01 and abs(pos[2]) < 0.01):
                        return pos
                except Exception:
                    pass
            # Fallback: world-space transform.
            pos = self._component_world_pos(root)
            if pos is not None:
                return pos
        # Last resort: mesh world transform.
        mesh_off = self.offsets.get("ACharacter::Mesh")
        if mesh_off is not None:
            mesh = rp(self.pm, actor + mesh_off)
            if mesh:
                pos = self._component_world_pos(mesh)
                if pos is not None:
                    return pos
        return None

    def iter_players(self, include_local=False, players_only=False):
        world = self._get_world()
        if not world:
            self._last_iter_stats = {"pa_total": 0, "pa_valid": 0,
                                     "level_total": 0, "level_valid": 0,
                                     "rendered": 0}
            return
        gamestate = rp(self.pm, world + self.offsets["UWorld::GameState"])
        pc = self._get_local_controller(world)
        local_pawn = rp(self.pm, pc + self.offsets["APlayerController::AcknowledgedPawn"]) if pc else 0
        local_ps = rp(self.pm, pc + self.offsets["AController::PlayerState"]) if pc else 0

        stats = {"pa_total": 0, "pa_valid": 0,
                 "level_total": 0, "level_valid": 0,
                 "rendered": 0}
        seen = set()

        def _is_valid_target(pawn):
            if not pawn:
                return False
            cls_name = self._class_name(pawn)
            if not cls_name:
                return False
            # Default logic: show every live Character in the world. Team filters
            # are intentionally gone because they hide players in free-look/spectate
            # and across game modes where pawn classes overlap.
            return "Character" in cls_name and "Spectate" not in cls_name

        def _emit_actor(actor, idx, stat_key):
            pos = self._actor_position(actor)
            if pos is None:
                return
            # Drop uninitialized / origin-only positions.
            if abs(pos[0]) < 0.01 and abs(pos[1]) < 0.01 and abs(pos[2]) < 0.01:
                return
            stats[stat_key] += 1
            stats["rendered"] += 1
            yield False, pos, idx

        # Local marker for calibration.
        if include_local and local_pawn:
            pos = self._actor_position(local_pawn)
            if pos is not None:
                stats["rendered"] += 1
                yield True, pos, 0

        # Pass 1: GameState->PlayerArray. This is the only source the aimbot uses,
        # because the level-actor scan can include NPCs/dummies with garbage positions.
        yielded = 0
        if gamestate:
            pa_data, pa_count, _ = read_array(self.pm, gamestate + self.offsets["AGameStateBase::PlayerArray"])
            stats["pa_total"] = pa_count
            if pa_data and pa_count > 0:
                for i in range(pa_count):
                    ps = rp(self.pm, pa_data + i * 8)
                    if not ps or ps == local_ps:
                        continue
                    pawn = rp(self.pm, ps + self.offsets["APlayerState::PawnPrivate"])
                    if not pawn or pawn == local_pawn or pawn in seen:
                        continue
                    pawn_cls = self._class_name(pawn)
                    if not pawn_cls:
                        continue
                    seen.add(pawn)
                    if not _is_valid_target(pawn):
                        continue
                    yield from _emit_actor(pawn, i, "pa_valid")
                    yielded += 1

        # Pass 2: Persistent level actors (fallback / merge).
        # ESP uses this to catch players PlayerArray hasn't updated yet. The aimbot
        # intentionally skips it to avoid locking onto random NPCs or dummy pawns.
        if not players_only:
            persistent_level_off = self.offsets.get("UWorld::PersistentLevel", 0x30)
            level = rp(self.pm, world + persistent_level_off)
            if level:
                actors_off = self.offsets.get("ULevel::Actors", 0xA0)
                actors_data, actors_count, _ = read_array(self.pm, level + actors_off)
                stats["level_total"] = actors_count
                if actors_data and actors_count > 0 and actors_count < 10000:
                    for i in range(actors_count):
                        actor = rp(self.pm, actors_data + i * 8)
                        if not actor or actor == local_pawn or actor in seen:
                            continue
                        cls_name = self._class_name(actor)
                        if not cls_name or "Character" not in cls_name:
                            continue
                        seen.add(actor)
                        if not _is_valid_target(actor):
                            continue
                        yield from _emit_actor(actor, i, "level_valid")

        self._last_iter_stats = stats


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
    box_esp: bool = True  # now draws a dot instead of a box
    show_local: bool = True
    show_names: bool = True
    show_distance: bool = True
    snap_lines: bool = True
    enemy_color: Tuple[int, int, int] = (255, 0, 0)
    local_color: Tuple[int, int, int] = (0, 255, 0)
    box_height_world: float = 100.0
    box_y_offset: int = 0
    dot_radius: int = 8
    show_debug: bool = False

    # Aimbot
    aimbot_enabled: bool = False
    aimbot_key: str = "MB5"
    aimbot_fov: int = 150
    aimbot_smooth: float = 0.30
    aimbot_target_offset: float = 0.0  # 0 = lock on ESP dot; raise for head/chest
    aimbot_show_fov: bool = True


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
        self.setFixedSize(260, 640)

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
        self.cb_box = self._chk("Dot ESP", "box_esp")
        self.cb_local = self._chk("Show Local Player", "show_local")
        self.cb_names = self._chk("Show Names", "show_names")
        self.cb_dist = self._chk("Show Distance", "show_distance")
        self.cb_snap = self._chk("Snap Lines", "snap_lines")
        self.cb_debug = self._chk("Show Debug Counters", "show_debug")
        layout.addWidget(self.cb_enabled)
        layout.addWidget(self.cb_box)
        layout.addWidget(self.cb_local)
        layout.addWidget(self.cb_names)
        layout.addWidget(self.cb_dist)
        layout.addWidget(self.cb_snap)
        layout.addWidget(self.cb_debug)

        dot_row = QHBoxLayout()
        dot_row.addWidget(QLabel("Dot Radius:"))
        self.spn_dot = QSpinBox()
        self.spn_dot.setRange(2, 32)
        self.spn_dot.setValue(self.config.dot_radius)
        self.spn_dot.valueChanged.connect(lambda v: setattr(self.config, "dot_radius", v))
        dot_row.addWidget(self.spn_dot)
        layout.addLayout(dot_row)

        aim_title = QLabel("AIMBOT")
        aim_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #f0f;")
        layout.addWidget(aim_title)

        self.cb_aimbot = self._chk("Aimbot Enabled", "aimbot_enabled")
        self.cb_aim_fov = self._chk("Show FOV Circle", "aimbot_show_fov")
        layout.addWidget(self.cb_aimbot)
        layout.addWidget(self.cb_aim_fov)

        aim_key_row = QHBoxLayout()
        self.lbl_aim_key = QLabel(f"Aim Key: {self.config.aimbot_key}")
        self.btn_record_key = QPushButton("Record Key")
        self.btn_record_key.clicked.connect(self._start_record_key)
        aim_key_row.addWidget(self.lbl_aim_key)
        aim_key_row.addWidget(self.btn_record_key)
        layout.addLayout(aim_key_row)

        fov_row = QHBoxLayout()
        fov_row.addWidget(QLabel("FOV Radius:"))
        self.spn_aim_fov = QSpinBox()
        self.spn_aim_fov.setRange(10, 600)
        self.spn_aim_fov.setValue(self.config.aimbot_fov)
        self.spn_aim_fov.valueChanged.connect(lambda v: setattr(self.config, "aimbot_fov", v))
        fov_row.addWidget(self.spn_aim_fov)
        layout.addLayout(fov_row)

        smooth_row = QHBoxLayout()
        smooth_row.addWidget(QLabel("Smooth:"))
        self.spn_aim_smooth = QDoubleSpinBox()
        self.spn_aim_smooth.setRange(0.01, 1.0)
        self.spn_aim_smooth.setSingleStep(0.05)
        self.spn_aim_smooth.setValue(self.config.aimbot_smooth)
        self.spn_aim_smooth.valueChanged.connect(lambda v: setattr(self.config, "aimbot_smooth", v))
        smooth_row.addWidget(self.spn_aim_smooth)
        layout.addLayout(smooth_row)

        aim_off_row = QHBoxLayout()
        aim_off_row.addWidget(QLabel("Target Offset:"))
        self.spn_aim_off = QSpinBox()
        self.spn_aim_off.setRange(-200, 200)
        self.spn_aim_off.setValue(int(self.config.aimbot_target_offset))
        self.spn_aim_off.valueChanged.connect(lambda v: setattr(self.config, "aimbot_target_offset", float(v)))
        aim_off_row.addWidget(self.spn_aim_off)
        layout.addLayout(aim_off_row)

        color_row = QHBoxLayout()
        self.btn_enemy_color = QPushButton("Enemy Color")
        self.btn_enemy_color.clicked.connect(self._pick_enemy_color)
        self.btn_local_color = QPushButton("Local Color")
        self.btn_local_color.clicked.connect(self._pick_local_color)
        color_row.addWidget(self.btn_enemy_color)
        color_row.addWidget(self.btn_local_color)
        layout.addLayout(color_row)

        height_row = QHBoxLayout()
        height_row.addWidget(QLabel("Model Height:"))
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

    def _pick_enemy_color(self):
        c = QColorDialog.getColor(QColor(*self.config.enemy_color), self)
        if c.isValid():
            self.config.enemy_color = (c.red(), c.green(), c.blue())

    def _pick_local_color(self):
        c = QColorDialog.getColor(QColor(*self.config.local_color), self)
        if c.isValid():
            self.config.local_color = (c.red(), c.green(), c.blue())

    # Key recording for aimbot
    AIM_KEY_NAMES = {
        0x01: "LMB", 0x02: "RMB", 0x04: "MMB", 0x05: "MB4", 0x06: "MB5",
        0x08: "Backspace", 0x09: "Tab", 0x0D: "Enter", 0x10: "Shift",
        0x11: "Ctrl", 0x12: "Alt", 0x13: "Pause", 0x1B: "Esc", 0x20: "Space",
        0x21: "PageUp", 0x22: "PageDown", 0x23: "End", 0x24: "Home",
        0x25: "Left", 0x26: "Up", 0x27: "Right", 0x28: "Down",
        0x2D: "Insert", 0x2E: "Delete",
        0x30: "0", 0x31: "1", 0x32: "2", 0x33: "3", 0x34: "4",
        0x35: "5", 0x36: "6", 0x37: "7", 0x38: "8", 0x39: "9",
        0x41: "A", 0x42: "B", 0x43: "C", 0x44: "D", 0x45: "E", 0x46: "F",
        0x47: "G", 0x48: "H", 0x49: "I", 0x4A: "J", 0x4B: "K", 0x4C: "L",
        0x4D: "M", 0x4E: "N", 0x4F: "O", 0x50: "P", 0x51: "Q", 0x52: "R",
        0x53: "S", 0x54: "T", 0x55: "U", 0x56: "V", 0x57: "W", 0x58: "X",
        0x59: "Y", 0x5A: "Z",
        0x60: "Num0", 0x61: "Num1", 0x62: "Num2", 0x63: "Num3", 0x64: "Num4",
        0x65: "Num5", 0x66: "Num6", 0x67: "Num7", 0x68: "Num8", 0x69: "Num9",
        0x70: "F1", 0x71: "F2", 0x72: "F3", 0x73: "F4", 0x74: "F5",
        0x75: "F6", 0x76: "F7", 0x77: "F8", 0x78: "F9", 0x79: "F10",
        0x7A: "F11", 0x7B: "F12",
        0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
        0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'",
    }

    def _start_record_key(self):
        self.btn_record_key.setEnabled(False)
        self.btn_record_key.setText("Press any key...")
        self._record_start = ctypes.windll.kernel32.GetTickCount()
        self._record_timer = QTimer(self)
        self._record_timer.timeout.connect(self._poll_record_key)
        self._record_timer.start(50)

    def _poll_record_key(self):
        elapsed = ctypes.windll.kernel32.GetTickCount() - self._record_start
        # Ignore the first 300 ms so the click on the record button isn't captured.
        if elapsed < 300:
            return
        for vk in range(1, 0x100):
            if ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000:
                name = self.AIM_KEY_NAMES.get(vk, f"VK_{vk:02X}")
                self.config.aimbot_key = name
                self.lbl_aim_key.setText(f"Aim Key: {name}")
                self._record_timer.stop()
                self.btn_record_key.setEnabled(True)
                self.btn_record_key.setText("Record Key")
                return
        if elapsed > 5000:
            self._record_timer.stop()
            self.btn_record_key.setEnabled(True)
            self.btn_record_key.setText("Record Key")

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
        for is_local, pos, idx in self.esp.iter_players(
                include_local=self.config.show_local):
            screen_info = self._project_dot(pos, cam, w, h)
            if not screen_info:
                continue
            sx, sy = screen_info
            color = self.config.local_color if is_local else self.config.enemy_color

            if self.config.box_esp:
                self._draw_dot(painter, sx, sy, color)

            if self.config.snap_lines:
                painter.setPen(QPen(QColor(*color), 1))
                painter.drawLine(int(w / 2), int(h), int(sx), int(sy))

            label_parts = []
            if self.config.show_names:
                label_parts.append("YOU" if is_local else f"Enemy {idx}")
            if self.config.show_distance:
                d = int(dist(pos, cam["loc"]) / 100)
                label_parts.append(f"{d}m")
            if label_parts:
                painter.setPen(QPen(QColor(*color)))
                text = " | ".join(label_parts)
                painter.drawText(int(sx + self.config.dot_radius + 4), int(sy), text)

            count += 1

        painter.setPen(QPen(QColor(255, 255, 255)))
        painter.drawText(10, 20, f"Players: {count}")
        if self.config.show_debug:
            stats = getattr(self.esp, "_last_iter_stats", {})
            line = (f"PA:{stats.get('pa_total', 0)}/{stats.get('pa_valid', 0)} "
                    f"LA:{stats.get('level_total', 0)}/{stats.get('level_valid', 0)}")
            painter.drawText(10, 35, line)

        # ------------------------------------------------------------------
        # Aimbot
        # ------------------------------------------------------------------
        if self.config.aimbot_enabled:
            cx, cy = w / 2, h / 2
            if self.config.aimbot_show_fov:
                painter.setPen(QPen(QColor(255, 255, 255), 1))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(int(cx - self.config.aimbot_fov),
                                    int(cy - self.config.aimbot_fov),
                                    self.config.aimbot_fov * 2,
                                    self.config.aimbot_fov * 2)

            best_target = self._find_best_target(cam, w, h)
            key_held = self._aim_key_held()
            if self.config.show_debug:
                print(f"[AIM-DEBUG] key_held={key_held} best_target={best_target[0] if best_target else None}")
            if best_target and key_held:
                self._aim_at(best_target[0], best_target[1])

    def _project_dot(self, center_pos, camera, screen_w, screen_h):
        # The actor's RootComponent relative location is already the capsule center,
        # so project it directly instead of guessing from feet/head.
        s = w2s(center_pos, camera, screen_w, screen_h)
        if not s:
            return None
        return (s[0], s[1] + self.config.box_y_offset)

    def _draw_dot(self, painter, cx, cy, color):
        r = self.config.dot_radius
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(*color))
        painter.drawEllipse(int(cx - r), int(cy - r), r * 2, r * 2)

    # -----------------------------------------------------------------------
    # Aimbot helpers
    # -----------------------------------------------------------------------
    AIM_KEY_VK = {
        "LMB": 0x01, "RMB": 0x02, "MMB": 0x04, "MB4": 0x05, "MB5": 0x06,
        "Backspace": 0x08, "Tab": 0x09, "Enter": 0x0D, "Shift": 0x10,
        "Ctrl": 0x11, "Alt": 0x12, "Pause": 0x13, "Esc": 0x1B, "Space": 0x20,
        "PageUp": 0x21, "PageDown": 0x22, "End": 0x23, "Home": 0x24,
        "Left": 0x25, "Up": 0x26, "Right": 0x27, "Down": 0x28,
        "Insert": 0x2D, "Delete": 0x2E,
        "0": 0x30, "1": 0x31, "2": 0x32, "3": 0x33, "4": 0x34,
        "5": 0x35, "6": 0x36, "7": 0x37, "8": 0x38, "9": 0x39,
        "A": 0x41, "B": 0x42, "C": 0x43, "D": 0x44, "E": 0x45, "F": 0x46,
        "G": 0x47, "H": 0x48, "I": 0x49, "J": 0x4A, "K": 0x4B, "L": 0x4C,
        "M": 0x4D, "N": 0x4E, "O": 0x4F, "P": 0x50, "Q": 0x51, "R": 0x52,
        "S": 0x53, "T": 0x54, "U": 0x55, "V": 0x56, "W": 0x57, "X": 0x58,
        "Y": 0x59, "Z": 0x5A,
        "Num0": 0x60, "Num1": 0x61, "Num2": 0x62, "Num3": 0x63, "Num4": 0x64,
        "Num5": 0x65, "Num6": 0x66, "Num7": 0x67, "Num8": 0x68, "Num9": 0x69,
        "F1": 0x70, "F2": 0x71, "F3": 0x72, "F4": 0x73, "F5": 0x74,
        "F6": 0x75, "F7": 0x76, "F8": 0x77, "F9": 0x78, "F10": 0x79,
        "F11": 0x7A, "F12": 0x7B,
        ";": 0xBA, "=": 0xBB, ",": 0xBC, "-": 0xBD, ".": 0xBE, "/": 0xBF,
        "`": 0xC0, "[": 0xDB, "\\": 0xDC, "]": 0xDD, "'": 0xDE,
    }

    def _aim_key_held(self):
        vk = self.AIM_KEY_VK.get(self.config.aimbot_key, 0x06)
        held = bool(ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000)
        if self.config.show_debug:
            print(f"[AIM-DEBUG] aim_key='{self.config.aimbot_key}' vk={hex(vk)} held={held}")
        return held

    def _find_best_target(self, camera, screen_w, screen_h):
        # Extra self-filter: iter_players should skip local, but if local controller
        # resolution fails it can leak through. Skip anything close to the camera
        # or to the local pawn.
        world = self.esp._get_world()
        local_pc = self.esp._get_local_controller(world) if world else 0
        local_pawn = rp(self.esp.pm, local_pc + self.esp.offsets["APlayerController::AcknowledgedPawn"]) if local_pc else 0
        local_pos = self.esp._actor_position(local_pawn) if local_pawn else None

        cx, cy = screen_w / 2, screen_h / 2
        cam_loc = camera["loc"]

        # If we cannot identify the local player, do not silently aim at anyone
        # (prevents locking onto our own body when controller resolution fails).
        if not local_pawn:
            if self.config.show_debug:
                print("[AIM-DEBUG] local pawn not resolved; refusing to aim")
            return None

        best_dist = float("inf")
        best_target = None
        count = 0
        for is_local, pos, idx in self.esp.iter_players(include_local=False, players_only=True):
            if is_local:
                continue
            # Skip self if it leaked through. Use a generous threshold because
            # third-person cameras can sit more than 50 cm from the capsule center.
            if local_pos:
                dself = math.sqrt((pos[0] - local_pos[0]) ** 2 +
                                  (pos[1] - local_pos[1]) ** 2 +
                                  (pos[2] - local_pos[2]) ** 2)
                if dself < 150.0:
                    continue
            # Skip anything right on top of the camera (failsafe for broken local filter).
            dcam = math.sqrt((pos[0] - cam_loc[0]) ** 2 +
                             (pos[1] - cam_loc[1]) ** 2 +
                             (pos[2] - cam_loc[2]) ** 2)
            if dcam < 100.0:
                continue
            count += 1

            # Aim at the same point the ESP dot is drawn, plus the user offset.
            # Default offset is 0 so the crosshair lands on the dot.
            aim_pos = (pos[0], pos[1], pos[2] + self.config.aimbot_target_offset)
            s = w2s(aim_pos, camera, screen_w, screen_h)
            if not s:
                continue
            dx = s[0] - cx
            dy = s[1] - cy
            d = math.sqrt(dx * dx + dy * dy)
            if d <= self.config.aimbot_fov and d < best_dist:
                best_dist = d
                best_target = (aim_pos, camera)
        if self.config.show_debug:
            print(f"[AIM-DEBUG] candidates={count} best_target={best_target[0] if best_target else None} fov={self.config.aimbot_fov}")
        return best_target

    def _vector_to_rotation(self, vec):
        x, y, z = vec
        length = math.sqrt(x * x + y * y + z * z)
        if length == 0:
            return (0.0, 0.0, 0.0)
        x, y, z = x / length, y / length, z / length
        # Pitch sign is flipped for this build — positive looks down, not up.
        pitch = -math.degrees(math.asin(z))
        yaw = math.degrees(math.atan2(y, x))
        return (pitch, yaw, 0.0)

    def _read_control_rotation(self):
        world = self.esp._get_world()
        if not world:
            return None
        pc = self.esp._get_local_controller(world)
        if not pc:
            return None
        addr = pc + self.esp.offsets["AController::ControlRotation"]
        rot = (rfloat(self.esp.pm, addr), rfloat(self.esp.pm, addr + 4), rfloat(self.esp.pm, addr + 8))
        if self.config.show_debug:
            print(f"[AIM-DEBUG] ControlRotation={rot} addr={hex(addr)} pc={hex(pc)}")
        return rot

    def _write_control_rotation(self, rot):
        world = self.esp._get_world()
        if not world:
            return False
        pc = self.esp._get_local_controller(world)
        if not pc:
            return False
        addr = pc + self.esp.offsets["AController::ControlRotation"]
        ok = (wfloat(self.esp.pm, addr, rot[0]) and
              wfloat(self.esp.pm, addr + 4, rot[1]) and
              wfloat(self.esp.pm, addr + 8, rot[2]))
        if self.config.show_debug:
            print(f"[AIM-DEBUG] write ControlRotation={rot} ok={ok}")
        return ok

    def _aim_at(self, target_pos, camera):
        if not camera:
            return
        current = self._read_control_rotation()
        if current is None:
            return
        dx = target_pos[0] - camera["loc"][0]
        dy = target_pos[1] - camera["loc"][1]
        dz = target_pos[2] - camera["loc"][2]
        target_rot = self._vector_to_rotation((dx, dy, dz))
        smooth = self.config.aimbot_smooth
        new_pitch = current[0] + (target_rot[0] - current[0]) * smooth
        new_yaw = current[1] + (target_rot[1] - current[1]) * smooth
        if self.config.show_debug:
            print(f"[AIM-DEBUG] cam_loc={camera['loc']} target_pos={target_pos} current={current} target_rot={target_rot} new=({new_pitch}, {new_yaw})")
        self._write_control_rotation((new_pitch, new_yaw, current[2]))


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
