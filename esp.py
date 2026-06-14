#!/usr/bin/env python3
"""
Production-ready external box ESP for MECCHA CHAMELEON (UE5.6).
Fully external: scans GUObjectArray, walks objects, renders overlay.
"""
import sys
import struct
import math
from dataclasses import dataclass
from typing import Tuple

import pymem
from PyQt5.QtWidgets import (
    QApplication, QWidget, QCheckBox, QComboBox, QLabel,
    QVBoxLayout, QHBoxLayout, QPushButton, QFrame, QColorDialog
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPainter, QPen, QColor, QFont


# ---------------------------------------------------------------------------
# Offsets from CXXHeaderDump / UE4SS Live View
# ---------------------------------------------------------------------------
OFFSETS = {
    "UObjectBase::ClassPrivate": 0x10,
    "UObjectBase::NamePrivate": 0x18,

    "UWorld::GameState": 0x1B0,
    "UWorld::OwningGameInstance": 0x228,

    "UGameInstance::LocalPlayers": 0x38,
    "UPlayer::PlayerController": 0x30,

    "UEngine::GameViewport": 0xC10,
    "UGameViewportClient::World": 0x78,

    "AGameStateBase::PlayerArray": 0x2C0,
    "APlayerState::PawnPrivate": 0x320,

    "APlayerController::AcknowledgedPawn": 0x350,
    "APlayerController::PlayerCameraManager": 0x360,

    "APlayerCameraManager::CameraCachePrivate": 0x1530,

    "FCameraCacheEntry::POV": 0x10,
    "FMinimalViewInfo::Location": 0x0,
    "FMinimalViewInfo::Rotation": 0x18,
    "FMinimalViewInfo::FOV": 0x30,

    "AActor::RootComponent": 0x1B8,
    "USceneComponent::RelativeLocation": 0x140,
}


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
    def __init__(self, pm, module_name):
        self.pm = pm
        self.module = pymem.process.module_from_name(pm.process_handle, module_name)
        if not self.module:
            raise RuntimeError(f"Module {module_name} not found")
        self.base = self.module.lpBaseOfDll
        self.size = self.module.SizeOfImage

    def scan(self, pattern, mask):
        data = self.pm.read_bytes(self.base, self.size)
        pat_len = len(pattern)
        for i in range(self.size - pat_len):
            matched = True
            for j in range(pat_len):
                if mask[j] and data[i + j] != pattern[j]:
                    matched = False
                    break
            if matched:
                return self.base + i
        return 0


# ---------------------------------------------------------------------------
# FName + object array
# ---------------------------------------------------------------------------
class FNameResolver:
    def __init__(self, pm, fname_pool):
        self.pm = pm
        self.fname_pool = fname_pool

    def resolve(self, entry_id):
        try:
            block_idx = entry_id >> 16
            within = (entry_id & 0xFFFF) << 1
            block_addr = rp(self.pm, self.fname_pool + 0x10 + block_idx * 8)
            if not block_addr:
                return None
            hdr = ru16(self.pm, block_addr + within)
            is_wide = hdr & 1
            length = hdr >> 6
            if length == 0 or length > 256:
                return None
            if is_wide:
                raw = self.pm.read_bytes(block_addr + within + 2, length * 2)
                return raw.decode("utf-16-le", errors="ignore")
            else:
                raw = self.pm.read_bytes(block_addr + within + 2, length)
                return raw.decode("latin-1")
        except Exception:
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
        if self._meta_class_addr is None:
            for obj in self.iter_objects():
                if self._obj_name(obj) == "Class":
                    self._meta_class_addr = obj
                    break
        return self._meta_class_addr

    def find_class(self, name):
        if name in self._class_cache:
            return self._class_cache[name]
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
    FNAMEPOOL_DELTA = 0xE3B40

    def __init__(self):
        self.pm = pymem.Pymem(self.PROCESS_NAME)
        self.guobject_array = self._scan_guobject_array()
        if not self.guobject_array:
            raise RuntimeError("Could not find GUObjectArray via pattern scan")
        self.fname_pool = self.guobject_array - self.FNAMEPOOL_DELTA
        self.objects = UObjectArray(self.pm, self.guobject_array, self.fname_pool)
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

    def _get_world(self):
        viewport = rp(self.pm, self.gengine + OFFSETS["UEngine::GameViewport"])
        if not viewport:
            return 0
        return rp(self.pm, viewport + OFFSETS["UGameViewportClient::World"])

    def _get_local_controller(self, world):
        if not world:
            return 0
        gi = rp(self.pm, world + OFFSETS["UWorld::OwningGameInstance"])
        if not gi:
            return 0
        lp_data, lp_count, _ = read_array(self.pm, gi + OFFSETS["UGameInstance::LocalPlayers"])
        if not lp_data or lp_count == 0:
            return 0
        local_player = rp(self.pm, lp_data)
        if not local_player:
            return 0
        return rp(self.pm, local_player + OFFSETS["UPlayer::PlayerController"])

    def get_camera(self):
        world = self._get_world()
        if not world:
            return None
        pc = self._get_local_controller(world)
        if not pc:
            return None
        cam = rp(self.pm, pc + OFFSETS["APlayerController::PlayerCameraManager"])
        if not cam:
            return None
        cc = cam + OFFSETS["APlayerCameraManager::CameraCachePrivate"]
        pov = cc + OFFSETS["FCameraCacheEntry::POV"]
        loc = rvec3(self.pm, pov + OFFSETS["FMinimalViewInfo::Location"])
        rot = rvec3(self.pm, pov + OFFSETS["FMinimalViewInfo::Rotation"])
        fov = rfloat(self.pm, pov + OFFSETS["FMinimalViewInfo::FOV"])
        return {"loc": loc, "rot": rot, "fov": fov}

    def iter_players(self, include_local=False):
        world = self._get_world()
        if not world:
            return
        gamestate = rp(self.pm, world + OFFSETS["UWorld::GameState"])
        if not gamestate:
            return
        pc = self._get_local_controller(world)
        local_pawn = rp(self.pm, pc + OFFSETS["APlayerController::AcknowledgedPawn"]) if pc else 0

        if include_local and local_pawn:
            root = rp(self.pm, local_pawn + OFFSETS["AActor::RootComponent"])
            if root:
                pos = rvec3(self.pm, root + OFFSETS["USceneComponent::RelativeLocation"])
                yield True, pos, 0

        pa_data, pa_count, _ = read_array(self.pm, gamestate + OFFSETS["AGameStateBase::PlayerArray"])
        if not pa_data or pa_count == 0:
            return
        for i in range(pa_count):
            ps = rp(self.pm, pa_data + i * 8)
            if not ps:
                continue
            pawn = rp(self.pm, ps + OFFSETS["APlayerState::PawnPrivate"])
            if not pawn or pawn == local_pawn:
                continue
            root = rp(self.pm, pawn + OFFSETS["AActor::RootComponent"])
            if not root:
                continue
            pos = rvec3(self.pm, root + OFFSETS["USceneComponent::RelativeLocation"])
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
    box_height_world: float = 170.0
    box_width_ratio: float = 0.45


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
        self.setFixedSize(260, 360)

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
        layout.addWidget(self.cb_enabled)
        layout.addWidget(self.cb_box)
        layout.addWidget(self.cb_local)
        layout.addWidget(self.cb_names)
        layout.addWidget(self.cb_dist)
        layout.addWidget(self.cb_snap)

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
        for is_local, pos, idx in self.esp.iter_players(include_local=self.config.show_local):
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
        cy = (s_feet[1] + s_head[1]) / 2
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
def main():
    app = QApplication(sys.argv)
    config = Config()
    esp = MecchaESP()
    menu = Menu(config)
    overlay = Overlay(esp, config, menu)
    overlay.show()
    menu.show()

    # Poll Insert/F1 globally to toggle menu visibility.
    import ctypes
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
