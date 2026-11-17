# Tapo C200 Audio

Play a local audio file through a **Tapo C200 camera speaker over your local network** using Python and FFmpeg. Includes a short, synthetic three-note test sound and a silent connection probe.

[繁體中文快速說明](#繁體中文快速說明)

## Requirements

- Python 3.10 or later.
- [FFmpeg](https://ffmpeg.org/download.html), available on `PATH` or specified with `--ffmpeg`.
- Network access to the camera on TCP port `8800`.
- The **Tapo App / TP-Link ID login password** for the account bound to the camera.
- **Third-Party Compatibility** enabled in the Tapo App.

In the Tapo App, look under **Me → Third-Party Services → Third-Party Compatibility**. Older versions may place this under **Tapo Lab**. See the [TP-Link FAQ](https://www.tapo.com/en/faqs/frequently-asked-questions-about-the-third-party-compatibility-feature).

The talk connection uses the fixed username `admin`. You do not enter your account email. Use your **App login password**, rather than the RTSP / camera account password.

## Install

Download or clone this repository, open its directory, then run:

```bash
python -m pip install -r requirements.txt
ffmpeg -version
```

`requirements.txt` installs the Python dependency; **install FFmpeg separately**.

## Quick test

Replace the example IP with your camera's IP:

```bash
python tapo_audio.py --host 192.168.1.100 --test
```

The program prompts for your Tapo App password with input hidden, then plays the bundled [test.wav](test.wav) through the **camera's physical speaker**. It does not save the password.

- The test sound is about 2.4 seconds: three synthetic notes with no speech.
- Playback runs once. Press `Ctrl+C` to stop.
- The default gain is `0.5`; adjust it with `--gain`. The camera's volume setting also affects loudness.

If FFmpeg is not on `PATH`:

```bash
python tapo_audio.py --host 192.168.1.100 --test --ffmpeg "C:\ffmpeg\bin\ffmpeg.exe"
```

To check the connection without sending audio:

```bash
python tapo_audio.py --host 192.168.1.100 --probe
```

This authenticates, briefly opens a talk session, and closes it without transmitting sound.

## Play your own file

```bash
python tapo_audio.py --host 192.168.1.100 --file "message.mp3"
python tapo_audio.py --host 192.168.1.100 --file "message.wav" --gain 0.5
```

Supports local audio files that FFmpeg can decode, including WAV, MP3, M4A, and OGG. Audio is streamed during playback; it is not saved to the camera's SD card.

## Use from Python

```python
import getpass
from tapo_audio import play_file

result = play_file(
    host="192.168.1.100",  # Replace with your camera's IP.
    password=getpass.getpass("Tapo App password: "),
    audio_path="test.wav",
    gain=0.5,
)
print(result)
```

`play_file()` blocks until transmission finishes. In an application, run it in a worker thread and allow only one playback job per camera at a time. To cancel, pass a `threading.Event` as `stop_event` and call its `.set()` method.

## How it works

```text
Local audio file
  → FFmpeg: G.711 A-law / 8 kHz / mono
  → Tapo private MPEG-TS packaging
  → /stream talk session over TCP 8800
  → Camera speaker
```

Uses native Python sockets. Running go2rtc or installing pytapo is not required. The talk protocol and MPEG-TS implementation are adapted from [go2rtc](https://github.com/AlexxIT/go2rtc/blob/master/internal/tapo/README.md); see [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) for the reference revision and original MIT license.

## HTTP 401 or no sound

1. Enable **Third-Party Compatibility**. On the tested C200, authentication returned 401 with the correct password until this setting was enabled.
2. Use the **App login password** of the account bound to the camera.
3. Close talk sessions in the phone app or other programs to avoid contention.
4. The default `--hash auto` selects SHA256 or MD5 based on the camera's challenge. If SHA256 is rejected, it retries MD5 once.
5. If the connection succeeds but there is no sound, try `--test` and check the camera's speaker volume and FFmpeg installation.

A 401 response alone does not prove the password is wrong; settings, firmware, or local authentication state can also affect the result.

## Verification and limitations

- The original functionality was confirmed by the user to play the correct sound through a physical **C200 speaker**.
- The tested device reported HardwareId `1.0` and firmware `1.3.17 Build 260112 Rel.54862n(4555)`. The test host used Windows and Python 3.12.
- Other hardware and firmware versions need their own testing. This is not an official TP-Link SDK.
- This minimal version provides single playback, a bundled test sound, and a silent probe. It does not manage automatic reconnection or multiple cameras.
- A successful return means data was transmitted. Confirm the actual sound at the camera.

Run the 10 offline tests with:

```bash
python -m unittest -v
```

The tests use a local mock camera, contact no physical device, and produce no sound at the camera. FFmpeg and the Python dependency are also required for these tests.

## Credentials and network

- The CLI does not save entered passwords. It also accepts `TAPO_CLOUD_PASSWORD` from the process environment.
- Do not put passwords, password hashes, or Authorization headers in source code, GitHub issues, or logs.
- The talk connection uses local TCP without TLS encryption for transmitted audio. Use a trusted local network and do not expose camera port `8800` directly to the internet.

## License

[MIT License](LICENSE). The protocol and MPEG-TS implementation are adapted from go2rtc; its original copyright and license are included in [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

`test.wav` is a synthetic sound included with this project under the MIT license.

## 繁體中文快速說明

用 Python 透過區網讓 **Tapo C200 現場喇叭播放本機音檔**。需要 Python 3.10 以上、FFmpeg，以及 Tapo App 的「第三方相容性」。

- App 設定通常在：**我 → 第三方服務 → 第三方相容性**；舊版可能在 **Tapo Lab**。
- 對講固定使用 `admin`，密碼是綁定攝影機的 **Tapo App／TP-Link ID 登入密碼**，不是 RTSP 攝影機帳密。
- 程式隱藏詢問密碼，不會儲存。`requirements.txt` 不會安裝 FFmpeg，請另行安裝。

進入專案資料夾後執行，並把範例 IP 換成自己的攝影機 IP：

```bash
python -m pip install -r requirements.txt
python tapo_audio.py --host 192.168.1.100 --test
```

`--test` 只播放一次約 2.4 秒的人工合成三聲提示音，沒有語音。可先用 `--probe` 無聲測試，或用 `--file` 播放自己的音檔：

```bash
python tapo_audio.py --host 192.168.1.100 --probe
python tapo_audio.py --host 192.168.1.100 --file "message.mp3"
```

預設增益為 `0.5`；按 `Ctrl+C` 可停止。音訊轉成 G.711 A-law／8 kHz／單聲道後即時傳送，不會存到 SD 卡。若出現 401，先確認第三方相容性及 App 登入密碼，並關閉其他對講工作。

本專案已由使用者在實體 C200 確認正確發聲，其他硬體與韌體版本仍需自行測試。僅在可信任區網使用，不要將攝影機 `8800` 連接埠開放到公網。完整限制、離線測試與授權見上方英文說明。
