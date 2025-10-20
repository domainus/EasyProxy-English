import asyncio
import logging
import re
import json
from urllib.parse import urlparse
from typing import Dict, Any
import gzip
import zlib
import random
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
import zstandard  # Import the zstandard library
from aiohttp_proxy import ProxyConnector

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    """Custom exception for extraction errors."""
    pass

def unpack(p, a, c, k, e=None, d=None):
    """
    Unpacker for P.A.C.K.E.R. packed javascript.
    This is a Python port of the common Javascript unpacker.
    """
    while c > 0:
        c -= 1
        if k[c]:
            p = re.sub('\\b' + _int2base(c, a) + '\\b', k[c], p)
    return p

def _int2base(x, base):
    if x < 0:
        sign = -1
    elif x == 0:
        return '0'
    else:
        sign = 1
    
    x *= sign
    digits = []
    
    while x:
        digits.append('0123456789abcdefghijklmnopqrstuvwxyz'[x % base])
        x = int(x / base)
        
    if sign < 0:
        digits.append('-')
        
    digits.reverse()
    return ''.join(digits)

class SportsonlineExtractor:
    """Sportsonline/Sportzonline URL extractor for M3U8 streams."""

    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        }
        self.session = None
        self.mediaflow_endpoint = "hls_manifest_proxy"
        self._session_lock = asyncio.Lock()
        self.proxies = proxies or []

    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    async def _get_session(self):
        if self.session is None or self.session.closed:
            timeout = ClientTimeout(total=60, connect=30, sock_read=30)
            proxy = self._get_random_proxy()
            if proxy:
                logger.info(f"Using proxy {proxy} for Sportsonline session.")
                connector = ProxyConnector.from_url(proxy)
            else:
                connector = TCPConnector(limit=10, limit_per_host=3)

            self.session = ClientSession(
                timeout=timeout,
                connector=connector,
                headers=self.base_headers,
                cookie_jar=aiohttp.CookieJar()
            )
        return self.session

    async def _make_robust_request(self, url: str, headers: dict = None, retries=3, initial_delay=2, timeout=15):
        final_headers = headers or self.base_headers
        # Remove the Accept-Encoding header to try receiving an uncompressed response
        request_headers = final_headers.copy()
        request_headers['Accept-Encoding'] = 'gzip, deflate'

        for attempt in range(retries):
            try:
                session = await self._get_session()
                logger.info(f"Attempt {attempt + 1}/{retries} for URL: {url}")
                # Disable automatic decompression in aiohttp
                async with session.get(url, headers=request_headers, timeout=timeout, auto_decompress=False) as response:
                    response.raise_for_status()
                    content = await self._handle_response_content(response)
                    return content
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"⚠️ Connection error attempt {attempt + 1} for {url}: {str(e)}")
                if attempt < retries - 1:
                    delay = initial_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
                else:
                    raise ExtractorError(f"All {retries} attempts failed for {url}: {str(e)}")
            except Exception as e:  # Capture other potential errors during decompression/decoding
                logger.exception(f"Error in _make_robust_request for {url}")
                raise ExtractorError(f"Error in robust request: {str(e)}")
        raise ExtractorError(f"Unable to complete request for {url}")

    async def _handle_response_content(self, response: aiohttp.ClientResponse) -> str:
        """Handles manual decompression of the response body."""
        content_encoding = response.headers.get('Content-Encoding')
        raw_body = await response.read()
        
        if content_encoding == 'zstd':
            logger.info(f"Detected zstd compression for {response.url}. Manual streaming decompression.")
            dctx = zstandard.ZstdDecompressor()
            try:
                decompressed_body = dctx.decompress(raw_body)
                return decompressed_body.decode(response.charset or 'utf-8')
            except zstandard.ZstdError as zs_e:
                logger.error(f"Error during zstd decompression: {zs_e}")
                raise ExtractorError(f"zstd decompression error: {zs_e}")
        elif content_encoding == 'gzip':
            logger.info(f"Detected gzip compression for {response.url}. Manual decompression.")
            decompressed_body = gzip.decompress(raw_body)
            return decompressed_body.decode(response.charset or 'utf-8')
        elif content_encoding == 'deflate':
            logger.info(f"Detected deflate compression for {response.url}. Manual decompression.")
            decompressed_body = zlib.decompress(raw_body)
            return decompressed_body.decode(response.charset or 'utf-8')
        else:
            return raw_body.decode(response.charset or 'utf-8')

    def _detect_packed_blocks(self, html: str) -> list[str]:
        """Detects and extracts eval-packed blocks from the HTML."""
        # Robust pattern that captures the entire eval block
        pattern = re.compile(r"(eval\(function\(p,a,c,k,e,d\).*?)\s*<\/script>", re.DOTALL)
        raw_matches = pattern.findall(html)
        
        # Fallback if the previous pattern does not work
        if not raw_matches:
            pattern = re.compile(r"(eval\(function\(p,a,c,k,e,.*?\)\))", re.DOTALL)
            raw_matches = pattern.findall(html)
        
        return raw_matches

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        try:
            logger.info(f"Fetching main page: {url}")
            main_html = await self._make_robust_request(url)

            iframe_match = re.search(r'<iframe\s+src=["\']([^"\']+)["\']', main_html, re.IGNORECASE)
            if not iframe_match:
                raise ExtractorError("No iframe found on the page")

            iframe_url = iframe_match.group(1)
            if iframe_url.startswith('//'):
                iframe_url = 'https:' + iframe_url
            elif iframe_url.startswith('/'):
                parsed_main = urlparse(url)
                iframe_url = f"{parsed_main.scheme}://{parsed_main.netloc}{iframe_url}"
            
            logger.info(f"Found iframe URL: {iframe_url}")

            iframe_headers = {
                'Referer': 'https://sportzonline.st/',
                'User-Agent': self.base_headers['user-agent'],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9,it;q=0.8',
                'Cache-Control': 'no-cache'
            }
            
            iframe_html = await self._make_robust_request(iframe_url, headers=iframe_headers)
            logger.debug(f"Iframe HTML length: {len(iframe_html)}")

            packed_blocks = self._detect_packed_blocks(iframe_html)
            logger.info(f"Found {len(packed_blocks)} packed blocks")

            if not packed_blocks:
                direct_match = re.search(r'(https?://[^\s"\'<>]+?\.m3u8[^\s"\'<>]*)', iframe_html)
                if direct_match:
                    m3u8_url = direct_match.group(1)
                    logger.info(f"Found direct m3u8 URL: {m3u8_url}")
                    return {
                        "destination_url": m3u8_url,
                        "request_headers": {'Referer': iframe_url, 'User-Agent': iframe_headers['User-Agent']},
                        "mediaflow_endpoint": self.mediaflow_endpoint,
                    }
                raise ExtractorError("No packed blocks or direct m3u8 URL found")

            chosen_idx = 1 if len(packed_blocks) > 1 else 0
            m3u8_url = None

            for i in range(len(packed_blocks)):
                current_idx = (chosen_idx + i) % len(packed_blocks)
                try:
                    # Use the unpack function directly on the captured block
                    unpacked_code = unpack(packed_blocks[current_idx])
                    logger.info(f"Successfully unpacked block {current_idx}")
                    
                    patterns = [
                        r'var\s+src\s*=\s*["\']([^"\']+\.m3u8[^"\']*)["\']',
                        r'src\s*=\s*["\']([^"\']+\.m3u8[^"\']*)["\']',
                        r'file\s*:\s*["\']([^"\']+\.m3u8[^"\']*)["\']',
                        # More generic pattern for 'source:"...m3u8..."'
                        r'source\s*:\s*["\'](https?://[^\'"]+?\.m3u8[^\'"]*?)["\']',
                        # Even more generic pattern for any m3u8 URL within quotes
                        r'["\'](https?://[^"\']+\.m3u8[^"\']*)["\']',
                    ]
                    for pattern in patterns:
                        src_match = re.search(pattern, unpacked_code)
                        if src_match:
                            m3u8_url = src_match.group(1)
                            if '.m3u8' in m3u8_url:
                                logger.info(f"Found m3u8 in block {current_idx}")
                                break
                    if m3u8_url:
                        break
                except Exception as e:
                    logger.warning(f"Failed to process block {current_idx}: {e}")
                    continue

            if not m3u8_url:
                raise ExtractorError("Could not extract m3u8 URL from any packed code block")

            logger.info(f"Successfully extracted m3u8 URL: {m3u8_url}")

            return {
                "destination_url": m3u8_url,
                "request_headers": {'Referer': iframe_url, 'User-Agent': iframe_headers['User-Agent']},
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }
        except Exception as e:
            logger.exception(f"Sportsonline extraction failed for {url}")
            raise ExtractorError(f"Extraction failed: {str(e)}")

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

def unpack(packed_js):
    """
    Unpacker for P.A.C.K.E.R. packed javascript.
    This is a Python port of the common Javascript unpacker.
    """
    try:
        # Extracts the parameters p,a,c,k,e,d from the packed_js string
        match = re.search(r"}\((.*)\)\)", packed_js)
        if not match:
            raise ValueError("Cannot find packed data.")
        
        p, a, c, k, e, d = eval(f"({match.group(1)})", {"__builtins__": {}}, {})
        return _unpack_logic(p, a, c, k, e, d)
    except Exception as e:
        raise ValueError(f"Failed to unpack JS: {e}")

def _unpack_logic(p, a, c, k, e, d):
    while c > 0:
        c -= 1
        if k[c]:
            p = re.sub('\\b' + _int2base(c, a) + '\\b', k[c], p)
    return p