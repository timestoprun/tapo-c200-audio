"""Offline protocol checks. Does not contact a camera or use real credentials."""
import hashlib
import contextlib
import io
import json
from pathlib import Path
import re
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import tapo_audio as audio

PASSWORD = 'offline-fixture-only'
CHALLENGE = 'Digest realm="fixture", nonce="nonce-1", qop="auth", opaque="xyz", encrypt_type="3"'


def fields(text):
    return dict(re.findall(r'([\w-]+)="([^"]*)"', text))


def md5(value):
    return hashlib.md5(value.encode()).hexdigest()


class CameraHandler(socketserver.StreamRequestHandler):
    def response(self, code, headers):
        # Deliberately emulate this C200's CR CR LF header lines.
        lines = [f'HTTP/1.0 {code} fixture'] + [k+': '+str(v) for k,v in headers.items()]
        self.wfile.write(('\r\r\n'.join(lines)+'\r\r\n\r\r\n').encode())

    def read_head(self):
        line = self.rfile.readline()
        while line and not line.strip():
            line = self.rfile.readline()
        if not line:
            return None, {}
        line = line.strip()
        headers = {}
        while True:
            item = self.rfile.readline().strip()
            if not item:
                return line, headers
            key, value = item.decode().split(':',1)
            headers[key.lower()] = value.strip()

    def handle(self):
        try:
            line, headers = self.read_head()
            assert line == b'POST /stream HTTP/1.1'
            assert 'authorization' not in headers
            self.response(401, {'WWW-Authenticate': CHALLENGE, 'Content-Length':0})
            line, headers = self.read_head()
            supplied = fields(headers['authorization'])
            assert PASSWORD not in headers['authorization']
            prehash = hashlib.new(self.server.accept_hash, PASSWORD.encode()).hexdigest().upper()
            a1=md5('admin:fixture:'+prehash)
            a2=md5('POST:/stream')
            expected=md5(':'.join([a1,'nonce-1','00000001',supplied['cnonce'],'auth',a2]))
            if supplied['response'] != expected or self.server.reject:
                self.response(401, {'WWW-Authenticate':CHALLENGE, 'Content-Length':0})
                return
            self.response(200, {'Content-Length':0,'Content-Type':'multipart/mixed; boundary=--device-stream-boundary--',
                                'Key-Exchange':'nonce="media-nonce", username="admin", encrypt_type="3"'})
            line, headers = self.read_head()
            assert line == b'----client-stream-boundary--'
            body = self.rfile.read(int(headers['content-length']))
            assert json.loads(body)['params']['talk']['mode'] == 'aec'
            reply = json.dumps({'error_code':0,'params':{'session_id':'fixture-session'}}).encode()
            encryption = '0'
            if self.server.encrypt:
                from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
                from cryptography.hazmat.primitives.padding import PKCS7
                key=hashlib.md5(('media-nonce:'+prehash).encode()).digest()
                iv=hashlib.md5(b'admin:media-nonce').digest()
                padder=PKCS7(128).padder()
                padded=padder.update(reply)+padder.finalize()
                enc=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor()
                reply=enc.update(padded)+enc.finalize()
                encryption='1'
            self.wfile.write(b'----device-stream-boundary--\r\nContent-Type: application/json\r\n' +
                             f'Content-Length: {len(reply)}\r\nX-If-Encrypt: {encryption}\r\n\r\n'.encode()+reply)
            while True:
                line, headers=self.read_head()
                if line is None:
                    return
                # The client's JSON request ends in a CRLF before its first audio part.
                if line == b'':
                    continue
                assert line == b'----client-stream-boundary--'
                body=self.rfile.read(int(headers['content-length']))
                assert headers['content-type']=='audio/mp2t'
                assert headers['x-session-id']=='fixture-session'
                assert headers['x-if-encrypt']=='0'
                assert len(body)%188==0
                assert all(body[n]==0x47 for n in range(0,len(body),188))
                self.server.parts.append((time.monotonic(),body))
        except (ConnectionResetError,BrokenPipeError):
            pass
        except Exception as error:
            self.server.errors.append(repr(error))


class FixtureServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    def __init__(self, accept_hash='sha256', encrypt=False, reject=False):
        super().__init__(('127.0.0.1',0),CameraHandler)
        self.accept_hash,self.encrypt,self.reject=accept_hash,encrypt,reject
        self.parts,self.errors=[],[]
        self.thread=threading.Thread(target=self.serve_forever,daemon=True)
        self.thread.start()
    @property
    def host(self):
        return '127.0.0.1:'+str(self.server_address[1])
    def __exit__(self,*args):
        self.shutdown()
        self.server_close()


class ProtocolTests(unittest.TestCase):
    def test_cli_requires_explicit_host(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(audio.getpass, 'getpass', side_effect=AssertionError('must parse host first')):
                with self.assertRaises(SystemExit) as result:
                    audio.main(['--probe'])
        self.assertEqual(result.exception.code, 2)

    def test_cli_bundled_test_sound(self):
        with FixtureServer() as server:
            with mock.patch.dict(audio.os.environ, {'TAPO_CLOUD_PASSWORD': PASSWORD}):
                with contextlib.redirect_stdout(io.StringIO()):
                    result=audio.main(['--host',server.host,'--test'])
            self.assertEqual(result,0)
            self.assertEqual(len(server.parts),121)
            self.assertEqual(server.errors,[])







    def test_exact_upstream_mux_bytes(self):
        mux=audio.TapoTSMuxer()
        actual=mux.header()
        for i,n in enumerate([160,160,320,1,183,184,511]):
            actual+=mux.frame(bytes([0xd5])*n,i*160)
        self.assertEqual(actual,(ROOT/'protocol_reference.bin').read_bytes())

    def test_probe_sha256(self):
        with FixtureServer() as server:
            result=audio.probe_camera(server.host,PASSWORD,log=lambda _:None)
            self.assertTrue(result['talk_ready'])
            self.assertEqual(result['hash_method'],'sha256')
            self.assertEqual(server.parts,[])
            self.assertEqual(server.errors,[])

    def test_md5_fallback_and_encrypted_reply(self):
        with FixtureServer(accept_hash='md5',encrypt=True) as server:
            result=audio.probe_camera(server.host,PASSWORD,log=lambda _:None)
            self.assertEqual(result['hash_method'],'md5')
            self.assertEqual(server.errors,[])

    def test_bad_password_is_reported(self):
        with FixtureServer(reject=True) as server:
            with self.assertRaises(audio.AuthenticationError):
                audio.probe_camera(server.host,PASSWORD,log=lambda _:None)
            self.assertEqual(server.errors,[])

    def test_ffmpeg_and_paced_send(self):
        with FixtureServer() as server:
            result=audio.play_file(server.host,PASSWORD,ROOT/'test.wav',log=lambda _:None)
            # One TS header plus 120 20-ms audio frames.
            self.assertAlmostEqual(result['sent_seconds'],2.4,places=3)
            self.assertEqual(len(server.parts),121)
            self.assertGreater(server.parts[-1][0]-server.parts[1][0],2.1)
            self.assertLess(server.parts[-1][0]-server.parts[1][0],3.2)
            self.assertEqual(server.errors,[])

    def test_stop_releases_socket(self):
        with FixtureServer() as server:
            stop=threading.Event()
            timer=threading.Timer(0.55,stop.set)
            timer.start()
            try:
                result=audio.play_file(server.host,PASSWORD,ROOT/'test.wav',stop_event=stop,log=lambda _:None)
                self.assertTrue(result['stopped'])
                self.assertLess(result['sent_seconds'],2.4)
                self.assertEqual(server.errors,[])
            finally:
                timer.cancel()

    def test_zero_gain_encodes_silence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'zero.alaw'
            audio.convert_audio(ROOT/'test.wav',path,gain=0)
            samples=path.read_bytes()
            self.assertEqual(len(samples),19200)
            # FFmpeg uses the positive zero A-law code.
            self.assertEqual(set(samples),{0xd5})

    def test_invalid_file_is_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'invalid.wav'
            path.write_bytes(b'not an audio stream')
            with self.assertRaisesRegex(audio.TapoError,'FFmpeg'):
                audio.convert_audio(path,Path(tmp)/'out.alaw')


if __name__=='__main__':
    unittest.main(verbosity=2)
