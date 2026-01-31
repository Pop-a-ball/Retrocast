"""
mitmproxy addon that forwards HTTP response bodies to the local Rust scanner DLL.

Behavior:
- Loads `scanner.dll` via ctypes if available. If not found, the addon logs and does nothing.
- On each HTTP response, the response body bytes are passed to `analyze_payload(const unsigned char*, size_t)`
  exported by the scanner. If the scanner returns non-zero the addon replaces the response with
  an HTTP 451 (Blocked) message.
"""

from mitmproxy import http
import ctypes
import os
import logging
import re
import json

log = logging.getLogger('mitm_addon')

# Basic PII redaction patterns (configurable)
PII_PATTERNS = {
    'email': re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}") ,
    'credit_card': re.compile(rb"\b(?:\d[ -]*?){13,16}\b"),
    'ssn': re.compile(rb"\b\d{3}-\d{2}-\d{4}\b"),
    'phone': re.compile(rb"\+?\d[\d ()-]{7,}\d")
}

def redact_pii(data: bytes, patterns=PII_PATTERNS) -> bytes:
    if not data:
        return data
    redacted = data
    try:
        for name, pat in patterns.items():
            redacted = pat.sub(b'[REDACTED]', redacted)
    except Exception:
        # Fail-safe: return original if redaction fails
        return data
    return redacted


class ScannerAddon:
    def __init__(self):
        self.analyze = None
        self.dll = None
        self.whitelist = []
        self.whitelist_path = os.path.join(os.path.dirname(__file__), 'whitelist.txt')
        self._load_whitelist()
        # Try a few likely locations for scanner.dll
        candidates = [
            os.path.join(os.path.dirname(__file__), '..', 'scanner', 'target', 'debug', 'scanner.dll'),
            os.path.join(os.path.dirname(__file__), '..', 'scanner', 'target', 'release', 'scanner.dll'),
            os.path.join(os.getcwd(), 'scanner.dll'),
            'scanner.dll'
        ]
        for p in candidates:
            try:
                p = os.path.abspath(p)
                if os.path.exists(p):
                    log.info(f'Loading scanner DLL from {p}')
                    self.dll = ctypes.CDLL(p)
                    break
            except Exception as e:
                log.debug('DLL load attempt failed: %s', e)

        if self.dll is None:
            try:
                # try by name
                self.dll = ctypes.CDLL('scanner.dll')
                log.info('Loaded scanner.dll by name')
            except Exception:
                log.warning('scanner.dll not found; addon will run in passive mode')
                self.dll = None

        if self.dll:
            try:
                self.analyze = self.dll.analyze_payload
                self.analyze.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.analyze.restype = ctypes.c_int
            except Exception as e:
                log.exception('Failed to bind analyze_payload: %s', e)
                self.analyze = None
            try:
                # Bind JSON helper and free function for richer responses
                self.analyze_json = self.dll.analyze_payload_json
                self.analyze_json.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.analyze_json.restype = ctypes.c_void_p
                self.free_cstring = self.dll.free_cstring
                self.free_cstring.argtypes = [ctypes.c_void_p]
            except Exception as e:
                log.debug('analyze_payload_json/free_cstring not available: %s', e)
                self.analyze_json = None
                self.free_cstring = None

    def _load_whitelist(self):
        try:
            if os.path.exists(self.whitelist_path):
                with open(self.whitelist_path, 'r', encoding='utf-8') as f:
                    lines = [l.strip() for l in f.readlines()]
                entries = []
                for l in lines:
                    if not l or l.startswith('#'):
                        continue
                    entries.append(l)
                self.whitelist = entries
                log.info('Loaded %d whitelist entries from %s', len(self.whitelist), self.whitelist_path)
            else:
                log.info('No whitelist file found at %s; proceeding without whitelist', self.whitelist_path)
                self.whitelist = []
        except Exception:
            log.exception('Failed to load whitelist; continuing without it')

    def request(self, flow: http.HTTPFlow):
        # Log request metadata for debugging (method, host, path, headers)
        try:
            req = flow.request
            method = req.method
            url = req.pretty_url
            host = req.host
            path = req.path
            headers = dict(req.headers) if req.headers else {}
            log.debug('Request: %s %s host=%s path=%s headers=%s', method, url, host, path, {k: headers.get(k) for k in list(headers)[:5]})
            # small body snippet
            try:
                rb = req.get_content() or b''
                if rb:
                    s = rb[:200].decode('utf-8', errors='replace')
                    log.debug('Request body snippet for %s: %s', url, re.sub(r"\s+", ' ', s))
            except Exception:
                pass
        except Exception:
            log.exception('Failed to log request metadata')

    # Configuration toggles
    REDACT_PII = True
    # Date detection and cutoff are implemented by the Rust scanner for performance and consistency.

    def _match_whitelist(self, host: str):
        """Return the matching whitelist entry if host matches, otherwise None."""
        if not host:
            return None
        h = host.lower()
        for e in self.whitelist:
            ee = e.lower()
            if ee.startswith('*.'):
                base = ee[2:]
                if h == base or h.endswith('.' + base):
                    return e
            elif ee.startswith('.'):
                base = ee[1:]
                if h == base or h.endswith('.' + base):
                    return e
            else:
                if h == ee:
                    return e
        return None

    def response(self, flow: http.HTTPFlow):
        if flow.response is None:
            return
        try:
            # Log basic response metadata to help diagnose missing bodies
            try:
                status = getattr(flow.response, 'status_code', None)
                ctype = flow.response.headers.get('Content-Type') if flow.response.headers else None
                cenc = flow.response.headers.get('Content-Encoding') if flow.response.headers else None
                raw_len = len(flow.response.raw_content) if getattr(flow.response, 'raw_content', None) is not None else None
                log.debug('Response metadata: url=%s status=%s content-type=%s content-encoding=%s raw_len=%s',
                          flow.request.pretty_url, status, ctype, cenc, raw_len)
            except Exception:
                log.debug('Failed to read response metadata for %s', flow.request.pretty_url)
            # If host is whitelisted, skip analysis entirely and log the matching pattern
            host = getattr(flow.request, 'host', None)
            matched = self._match_whitelist(host)
            if matched:
                log.info('WHITELIST HIT: pattern=%s host=%s url=%s - skipping scanner', matched, host, flow.request.pretty_url)
                return

            # derive media key for potential per-media blocking
            def extract_media_key(url: str):
                try:
                    from urllib.parse import urlparse
                    p = urlparse(url)
                    path = p.path or ''
                    # Marker-based detection temporarily disabled — previously searched for
                    # ['/segment/','/segments/','/v1/segment/','/v2/segment/'] which is Twitch-specific.
                    # for marker in ['/segment/','/segments/','/v1/segment/','/v2/segment/']:
                    #     if marker in path:
                    #         idx = path.find(marker) + len(marker)
                    #         base = path[:idx]
                    #         return f"{p.netloc}{base}"
                    if '/' in path:
                        return f"{p.netloc}{path.rsplit('/',1)[0]}/"
                    return f"{p.netloc}{path}"
                except Exception:
                    return url

            url = getattr(flow.request, 'pretty_url', '')
            media_key = extract_media_key(url)
            import time
            now = time.time()
            # If this media_key was previously blocked and still within TTL, block immediately
            if media_key in getattr(self, 'blocked_media', {}) and getattr(self, 'blocked_media', {})[media_key] > now:
                log.info('BLOCK: media_key %s previously blocked - applying block for %s', media_key, url)
                flow.response.status_code = 451
                flow.response.reason = 'Blocked'
                flow.response.headers['Content-Type'] = 'text/plain'
                flow.response.set_text('Blocked by local scanner (media)')
                return

            # Use decoded content where possible (mitmproxy will decode gzip/deflate)
            # `flow.response.content` returns the decoded bytes; fall back to raw_content.
            body = None
            try:
                body = flow.response.content
            except Exception:
                body = flow.response.raw_content or b''

            # Log when responses are empty so we can diagnose why scanner isn't called
            if not body:
                log.debug('Response has no body for %s (status=%s); skipping', flow.request.pretty_url, getattr(flow.response, 'status_code', ''))
                return

            # obtain content-type safely
            ctype = None
            try:
                ctype = flow.response.headers.get('Content-Type') if flow.response.headers else None
            except Exception:
                ctype = None
            ctype_l = ctype.lower() if ctype else ''

            if not self.analyze:
                log.warning('ANALYZER_MISSING: scanner DLL not bound; skipping analysis for %s', flow.request.pretty_url)
                return

            # Optionally redact PII before sending to analyzer
            send_body = body
            try:
                snippet = send_body[:256]
                if isinstance(snippet, bytes):
                    try:
                        s = snippet.decode('utf-8', errors='replace')
                    except Exception:
                        s = str(snippet)
                else:
                    s = str(snippet)
                log.info('Response snippet for %s: %s', flow.request.pretty_url, re.sub(r"\s+", ' ', s))
            except Exception:
                pass
            if getattr(self, 'REDACT_PII', False):
                try:
                    send_body = redact_pii(body)
                except Exception:
                    send_body = body

            # Build the probe bytes to send to the scanner. For media we scan URL + headers; for text we scan body.
            probe = b''
            is_media = False
            # Remove headers from probes so dates contained only in headers won't trigger blocks.
            # For media we send only the URL; for textual content we send only the body (redacted if enabled).
            if ctype_l.startswith(('image/','video/','audio/')) or any(s in ctype_l for s in ('octet-stream','wasm','mp2t','mpegurl','mpeg','ogg','webm')):
                is_media = True
                # Probe contains only the URL for media
                probe = url.encode('utf-8', errors='replace')
            else:
                # Textual content: send only the body (no headers)
                probe = send_body

            buf = ctypes.create_string_buffer(probe)
            # Use the length of the buffer we're actually sending (after redaction)
            try:
                decision = None
                reason = None
                matched = None
                json_used = False
                # Prefer JSON helper if available to get 'reason' and 'matched'
                if getattr(self, 'analyze_json', None):
                    ptr = self.analyze_json(ctypes.cast(buf, ctypes.c_void_p), len(probe))
                    if ptr:
                        try:
                            s = ctypes.cast(ptr, ctypes.c_char_p).value.decode('utf-8', errors='replace')
                            if getattr(self, 'free_cstring', None):
                                try:
                                    self.free_cstring(ptr)
                                except Exception:
                                    pass
                            data = None
                            try:
                                data = json.loads(s)
                            except Exception:
                                data = None
                            if data:
                                decision = data.get('decision')
                                reason = data.get('reason')
                                matched = data.get('matched')
                                json_used = True
                        except Exception:
                            try:
                                if getattr(self, 'free_cstring', None):
                                    self.free_cstring(ptr)
                            except Exception:
                                pass
                # Fallback to integer API
                if decision is None:
                    res = None
                    if getattr(self, 'analyze', None):
                        try:
                            res = self.analyze(ctypes.cast(buf, ctypes.c_void_p), len(probe))
                        except Exception:
                            res = None
                    if res == 1:
                        decision = 'block'
                        reason = 'date_after_threshold'
                    elif res == 0:
                        decision = 'allow'
                    else:
                        decision = 'allow'

                log.info('analyze decision=%s reason=%s matched=%s for %s (host=%s)', decision, reason, matched, flow.request.pretty_url, host)

                if decision == 'block':
                    # If JSON-based analyzer indicated no_dates_found, treat as allow (do not block)
                    if json_used and reason in ('no_dates_found','no_dates_found_allowed'):
                        log.info('SKIP BLOCK: analyzer reason=%s for %s (host=%s) — treating as allow', reason, flow.request.pretty_url, host)
                        decision = 'allow'
                    else:
                        # Determine subcode but never assign header-based '1.1' — header matches are ignored for blocking
                        if not json_used:
                            subcode = '1'
                        else:
                            try:
                                if is_media and matched and isinstance(matched, str) and matched in url:
                                    subcode = '1.3'
                                else:
                                    # default to text/media payload classification '1.2'
                                    subcode = '1.2'
                            except Exception:
                                subcode = '1.2'

                        # If this is media and media_key exists, mark as blocked for subsequent segments (1.4)
                        # (left commented out intentionally)
                        # if is_media and media_key:
                        #     try:
                        #         ttl = 300
                        #         if not hasattr(self, 'blocked_media'):
                        #             self.blocked_media = {}
                        #         self.blocked_media[media_key] = now + ttl
                        #         log.info('Marking media_key %s blocked for %d seconds', media_key, ttl)
                        #     except Exception:
                        #         pass

                        log.info('BLOCK: analyzer decision %s for %s (host=%s) reason=%s - replacing response with 451', subcode, flow.request.pretty_url, host, reason)
                        flow.response.status_code = 451
                        flow.response.reason = 'Blocked'
                        flow.response.headers['Content-Type'] = 'text/plain'
                        flow.response.set_text('Blocked by local scanner')
                else:
                    if decision != 'allow':
                        log.debug('Non-blocking analyzer decision %s for %s (host=%s) - allowed', decision, flow.request.pretty_url, host)
            except Exception as e:
                log.exception('ANALYZER_ERROR: exception while calling analyzer for %s (host=%s): %s', flow.request.pretty_url, host, e)
                # Do not modify response on analyzer errors; leave original content so user can see site (avoid false 451)
                return
        except Exception as e:
            log.exception('Error in scanner addon: %s', e)


addons = [ScannerAddon()]
