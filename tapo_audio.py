"""Play a local audio file through a Tapo camera speaker on the LAN.

Protocol reference: AlexxIT/go2rtc (MIT), pkg/tapo and pkg/mpegts.
See THIRD_PARTY_NOTICES.txt. No credentials are saved by this program.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit


class TapoError(Exception):
    """A user-facing connection, conversion or protocol error."""


class AuthenticationError(TapoError):
    pass


CLIENT_BOUNDARY = b"--client-stream-boundary--"
SAMPLE_RATE = 8000
FRAME_BYTES = 160  # G.711 A-law: one byte/sample; 20 ms.


def _parameters(value):
    return dict(re.findall(r'([\w-]+)\s*=\s*"([^"]*)"', value))


def _md5(value):
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def digest_authorization(challenge, password_hash, cnonce=None):
    """The password prehash can be SHA256; HTTP Digest itself stays MD5."""
    fields = _parameters(challenge)
    if not challenge.lower().startswith("digest ") or not all(
        key in fields for key in ("realm", "nonce")
    ):
        raise TapoError("攝影機回傳了無法辨識的驗證要求。")
    cnonce = cnonce or secrets.token_hex(16)
    realm, nonce = fields["realm"], fields["nonce"]
    ha1 = _md5(f"admin:{realm}:{password_hash}")
    ha2 = _md5("POST:/stream")
    qop = fields.get("qop", "")
    if qop and "auth" not in qop.split(","):
        raise TapoError("攝影機要求的 Digest qop 不支援。")
    response = _md5(f"{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}") if qop else _md5(f"{ha1}:{nonce}:{ha2}")
    pieces = [f'username="admin"', f'realm="{realm}"', f'nonce="{nonce}"', 'uri="/stream"', f'response="{response}"', 'algorithm=MD5']
    if qop:
        pieces += ['qop=auth', 'nc=00000001', f'cnonce="{cnonce}"']
    if "opaque" in fields:
        pieces.append(f'opaque="{fields["opaque"]}"')
    return "Digest " + ", ".join(pieces)


class TapoTalkClient:
    def __init__(self, host, password, hash_method="auto", timeout=6, log=print):
        try:
            endpoint = urlsplit("//" + host)
            if endpoint.username or endpoint.password or endpoint.path or endpoint.query or endpoint.fragment:
                raise ValueError
            self.hostname = endpoint.hostname
            self.port = endpoint.port or 8800
            if not self.hostname or any(c.isspace() for c in host):
                raise ValueError
        except ValueError:
            raise TapoError("IP 格式不正確，請輸入例如 camera.local。") from None
        if hash_method not in ("auto", "sha256", "md5"):
            raise TapoError("密碼雜湊模式必須是 auto、sha256 或 md5。")
        if not password:
            raise TapoError("請輸入 Tapo App 登入密碼。")
        self.host, self.password = host, password
        self.hash_method, self.timeout, self.log = hash_method, timeout, log
        self.sock = self.reader = None
        self.session_id = ""
        self.server_boundary = b"--device-stream-boundary--"
        self.response_headers = {}
        self.used_hash = ""

    def _open_socket(self):
        self.sock = socket.create_connection((self.hostname, self.port), self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.reader = self.sock.makefile("rb")

    def _line(self):
        line = self.reader.readline(65537)
        if not line:
            raise TapoError("攝影機關閉了連線。")
        if len(line) > 65536:
            raise TapoError("攝影機回應的標頭過長。")
        # Strip line terminators; tolerate extra CR defensively.
        return line.rstrip(b"\r\n")

    def _headers(self):
        headers = {}
        for _ in range(100):
            line = self._line()
            if not line:
                return headers
            if b":" not in line:
                raise TapoError("攝影機回傳了無法辨識的標頭。")
            key, value = line.split(b":", 1)
            headers[key.decode("latin1").lower()] = value.decode("latin1").strip()
        raise TapoError("攝影機回應的標頭數量過多。")

    def _read_exact(self, length):
        if not 0 <= length <= 1024 * 1024:
            raise TapoError("攝影機回應的資料長度不正確。")
        data = self.reader.read(length)
        if len(data) != length:
            raise TapoError("攝影機回應不完整，連線已中斷。")
        return data

    def _post(self, authorization=None):
        lines = ["POST /stream HTTP/1.1", f"Host: {self.host}",
                 "Content-Type: multipart/mixed; boundary=--client-stream-boundary--",
                 "Connection: keep-alive", "Content-Length: -1"]
        if authorization:
            lines.append("Authorization: " + authorization)
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))
        status = self._line().split()
        if len(status) < 2 or not status[1].isdigit():
            raise TapoError("攝影機回傳了無法辨識的 HTTP 狀態。")
        headers = self._headers()
        length = int(headers.get("content-length", "0"))
        if length > 0:
            self._read_exact(length)
        return int(status[1]), headers

    def connect(self):
        """Authenticate; auto mode retries MD5 once if SHA256 is rejected."""
        override = None
        try:
            for attempt in range(2):
                self.close()
                self._open_socket()
                status, headers = self._post()
                challenge = headers.get("www-authenticate", "")
                if status != 401 or not challenge:
                    raise TapoError(f"攝影機未提供標準驗證要求（HTTP {status}）。")
                fields = _parameters(challenge)
                method = override or (self.hash_method if self.hash_method != "auto" else
                                      "sha256" if fields.get("encrypt_type") == "3" else "md5")
                prehash = hashlib.new(method, self.password.encode("utf-8")).hexdigest().upper()
                authorization = digest_authorization(challenge, prehash)
                try:
                    status, headers = self._post(authorization)
                except (OSError, TapoError):
                    # Some devices really close the initial 401 connection.
                    self.close()
                    self._open_socket()
                    status, headers = self._post(authorization)
                if status == 401:
                    if self.hash_method == "auto" and method == "sha256" and attempt == 0:
                        self.log("SHA256 驗證未通過，依相容性做法重試 MD5 一次。")
                        override = "md5"
                        continue
                    raise AuthenticationError(
                        "攝影機拒絕驗證（HTTP 401）。對講通常需要 Tapo App／TP-Link ID 的登入密碼，"
                        "RTSP 攝影機密碼通常不適用。請確認密碼及第三方相容性設定。")
                if status != 200:
                    raise TapoError(f"攝影機連線失敗（HTTP {status}）。")
                self.used_hash = method
                self.response_headers = headers
                match = re.search(r'boundary\s*=\s*"?([^";\s]+)', headers.get("content-type", ""))
                if match:
                    self.server_boundary = match.group(1).encode("ascii")
                self.log(f"驗證成功，使用 {method.upper()}，對講帳號 admin。")
                return self
        except BaseException:
            self.close()
            raise
        raise AuthenticationError("攝影機拒絕驗證。")

    def _send_part(self, content_type, body, audio=False):
        lines = [b"--" + CLIENT_BOUNDARY,
                 b"Content-Type: " + content_type.encode("ascii"),
                 b"Content-Length: " + str(len(body)).encode("ascii")]
        if audio:
            lines += [b"X-If-Encrypt: 0", b"X-Session-Id: " + self.session_id.encode("ascii")]
        self.sock.sendall(b"\r\n".join(lines) + b"\r\n\r\n" + body + (b"" if audio else b"\r\n"))

    def _decode_part(self, headers, body):
        if headers.get("x-if-encrypt", "0") != "1":
            return body
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.padding import PKCS7
        except ImportError:
            raise TapoError("此韌體加密回應，需要先執行 python -m pip install cryptography。") from None
        exchange = _parameters(self.response_headers.get("key-exchange", ""))
        nonce = exchange.get("nonce")
        if not nonce or exchange.get("username", "admin") != "admin":
            raise TapoError("不支援此攝影機的金鑰交換格式。")
        # Some firmware advertises type 3 but authenticates with the MD5 fallback.
        # Retain the method that actually succeeded, as pytapo does.
        method = self.used_hash
        prehash = hashlib.new(method, self.password.encode("utf-8")).hexdigest().upper()
        key = hashlib.md5((nonce + ":" + prehash).encode()).digest()
        iv = hashlib.md5(("admin:" + nonce).encode()).digest()
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(body) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def start_talk(self):
        request = {"params": {"talk": {"mode": "aec"}, "method": "get"}, "seq": 3, "type": "request"}
        self._send_part("application/json", json.dumps(request, separators=(",", ":")).encode())
        delimiter = b"--" + self.server_boundary
        for _ in range(20):
            if self._line() != delimiter:
                continue
            headers = self._headers()
            body = self._read_exact(int(headers.get("content-length", "0")))
            if "application/json" not in headers.get("content-type", ""):
                continue
            response = json.loads(self._decode_part(headers, body))
            params = response.get("params") or {}
            code = response.get("error_code", params.get("error_code", 0))
            if code not in (0, "0", None):
                raise TapoError(f"攝影機拒絕對講（代碼 {code}）。請關閉 Tapo App 的對講後再試。")
            session_id = params.get("session_id")
            if session_id:
                session_id = str(session_id)
                if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", session_id):
                    raise TapoError("攝影機回傳的對講識別碼格式不正確。")
                self.session_id = session_id
                self.log("攝影機已建立對講通道。")
                return
        raise TapoError("攝影機未回傳對講識別碼。")

    def send_audio(self, ts_bytes):
        if not self.session_id:
            raise TapoError("尚未建立對講通道。")
        self._send_part("audio/mp2t", ts_bytes, audio=True)

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self.reader:
            self.reader.close()
        if self.sock:
            self.sock.close()
        self.sock = self.reader = None
        self.session_id = ""


def _mpeg_crc(data):
    crc = 0xFFFFFFFF
    for value in data:
        crc ^= value << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04C11DB7 if crc & 0x80000000 else 0)) & 0xFFFFFFFF
    return crc


class TapoTSMuxer:
    """Tapo private PCMA stream type 0x90, matching go2rtc's talk muxer."""
    def __init__(self):
        self.counter = 0

    @staticmethod
    def _psi(pid, section):
        section += struct.pack(">I", _mpeg_crc(section))
        packet = b"G" + struct.pack(">H", 0x4000 | pid) + b"\x10\x00" + section
        return packet.ljust(188, b"\x00")

    def header(self):
        pat = bytes.fromhex("00 b0 0d 00 01 c1 00 00 00 01 f0 00")
        pmt = bytes.fromhex("02 b0 12 00 01 c1 00 00 ff ff f0 00 90 e1 00 f0 00")
        return self._psi(0, pat) + self._psi(0x1000, pmt)

    def frame(self, audio, timestamp):
        # Tapo/go2rtc use the 8 kHz sample clock here (not standard 90 kHz).
        t = timestamp & 0xFFFFFFFF
        pts = bytes((0x21 | ((t >> 29) & 0x0E), (t >> 22) & 255,
                     ((t >> 14) & 0xFE) | 1, (t >> 7) & 255, ((t << 1) & 0xFE) | 1))
        pes = b"\x00\x00\x01\xc0" + struct.pack(">H", len(audio) + 8) + b"\x80\x80\x05" + pts + audio
        result = bytearray()
        first = True
        while pes:
            payload, pes = pes[:184], pes[184:]
            pid = 0x100 | (0x4000 if first else 0)
            flags = 0x10 if len(payload) == 184 else 0x30
            result += b"G" + struct.pack(">H", pid) + bytes([flags | self.counter])
            if len(payload) < 184:
                padding_length = 183 - len(payload)
                result += bytes([padding_length]) + bytes(padding_length)
            result += payload
            self.counter = (self.counter + 1) & 15
            first = False
        return bytes(result)


def find_ffmpeg(ffmpeg_path=None):
    if ffmpeg_path:
        if Path(ffmpeg_path).is_file():
            return str(Path(ffmpeg_path).resolve())
        raise TapoError("指定的 FFmpeg 執行檔不存在。")
    candidates = [os.environ.get("TAPO_FFMPEG"), shutil.which("ffmpeg"),
                  str(Path(__file__).with_name("ffmpeg.exe"))]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    raise TapoError("找不到 FFmpeg。請加入 PATH，或用 --ffmpeg 指定 ffmpeg.exe。")


def convert_audio(audio_path, output_path, ffmpeg_path=None, gain=0.5, stop_event=None):
    """Convert before reserving the camera; no shell or network input URLs."""
    source = Path(audio_path).expanduser().resolve()
    if not source.is_file():
        raise TapoError("音訊檔案不存在。")
    if not 0 <= gain <= 2:
        raise TapoError("音量倍率必須介於 0 與 2。")
    ffmpeg = find_ffmpeg(ffmpeg_path)
    command = [ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
               "-protocol_whitelist", "file,pipe", "-i", str(source), "-map", "0:a:0", "-vn",
               "-af", f"volume={gain}", "-ar", "8000", "-ac", "1", "-c:a", "pcm_alaw",
               "-f", "alaw", str(output_path)]
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    # A file avoids stderr pipe deadlocks for malformed inputs.
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=errors, creationflags=flags)
        started = time.monotonic()
        try:
            while process.poll() is None:
                if stop_event and stop_event.wait(0.05):
                    raise TapoError("已停止音訊轉換。")
                if not stop_event:
                    time.sleep(0.05)
                if time.monotonic() - started > 180:
                    raise TapoError("音訊轉換超時，請先使用較短的音檔。")
            if process.returncode:
                errors.seek(0)
                detail = errors.read(1800).decode("utf-8", "replace").strip()
                raise TapoError("FFmpeg 無法讀取此音檔：" + detail)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
    if Path(output_path).stat().st_size == 0:
        raise TapoError("音檔沒有可播放的音訊內容。")


def probe_camera(host, password, hash_method="auto", log=print):
    """Open/close a real talk session without transmitting audio."""
    client = TapoTalkClient(host, password, hash_method, log=log)
    try:
        client.connect()
        client.start_talk()
        return {"authenticated": True, "talk_ready": True, "hash_method": client.used_hash}
    finally:
        client.close()


def play_file(host, password, audio_path, ffmpeg_path=None, gain=0.5,
              hash_method="auto", log=print, stop_event=None):
    """Convert once, then send a local file in real time. Blocks until done."""
    stop_event = stop_event if stop_event is not None else threading.Event()
    with tempfile.TemporaryDirectory(prefix="tapo_audio_") as temporary:
        alaw_path = Path(temporary) / "audio.alaw"
        log("正在轉換為 G.711 A-law／8 kHz／單聲道…")
        try:
            convert_audio(audio_path, alaw_path, ffmpeg_path, gain, stop_event)
        except TapoError:
            if stop_event.is_set():
                return {"sent_seconds": 0.0, "stopped": True}
            raise
        duration = alaw_path.stat().st_size / SAMPLE_RATE
        log(f"音檔長度 {duration:.2f} 秒，音量倍率 {gain:.2f}。")
        if stop_event.is_set():
            return {"sent_seconds": 0.0, "stopped": True}
        client = TapoTalkClient(host, password, hash_method, log=log)
        sent = 0
        try:
            client.connect()
            client.start_talk()
            if stop_event.is_set():
                return {"sent_seconds": 0.0, "stopped": True}
            muxer = TapoTSMuxer()
            client.send_audio(muxer.header())
            started = time.monotonic()
            with alaw_path.open("rb") as audio:
                while not stop_event.is_set():
                    frame = audio.read(FRAME_BYTES)
                    if not frame:
                        break
                    delay = started + sent / SAMPLE_RATE - time.monotonic()
                    if delay > 0 and stop_event.wait(delay):
                        break
                    client.send_audio(muxer.frame(frame, sent))
                    sent += len(frame)
            if not stop_event.is_set():
                stop_event.wait(max(0, started + sent / SAMPLE_RATE - time.monotonic()) + 0.3)
            stopped = stop_event.is_set()
            log("已停止傳送。" if stopped else "音訊已傳送完成；請在攝影機旁確認實際聲音。")
            return {"sent_seconds": sent / SAMPLE_RATE, "stopped": stopped,
                    "hash_method": client.used_hash}
        finally:
            client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Send a local audio file to a Tapo C200 speaker over the LAN.")
    parser.add_argument("--host", required=True, help="Camera IP or hostname; default port: 8800")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--file", type=Path, help="Local MP3, WAV, M4A or other FFmpeg-readable audio")
    mode.add_argument("--test", action="store_true", help="Play the bundled 2.4-second three-note test sound")
    mode.add_argument("--probe", action="store_true", help="Open and close a talk session without sending sound")
    parser.add_argument("--gain", type=float, default=0.5, help="Audio gain, 0 to 2 (default: 0.5)")
    parser.add_argument("--hash", dest="hash_method", choices=("auto", "sha256", "md5"), default="auto")
    parser.add_argument("--ffmpeg", help="Path to the FFmpeg executable")
    args = parser.parse_args(argv)
    try:
        password = os.environ.get("TAPO_CLOUD_PASSWORD")
        if not password:
            password = getpass.getpass("Tapo App password (not saved): ")
        if args.probe:
            probe_camera(args.host, password, args.hash_method)
            print("Connection test passed; no audio was sent.")
        else:
            audio_path = Path(__file__).with_name("test.wav") if args.test else args.file
            play_file(args.host, password, audio_path, args.ffmpeg, args.gain, args.hash_method)
        return 0
    except KeyboardInterrupt:
        print("\nStopped; the talk connection has been closed.")
        return 130
    except (TapoError, OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

