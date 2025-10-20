import asyncio
import logging
import re
import base64
import json
import os
import gzip
import zlib
import zstandard
import random
from urllib.parse import urlparse, quote_plus
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp_proxy import ProxyConnector
from typing import Dict, Any, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    pass

class DLHDExtractor:
    """DLHD Extractor with persistent session and advanced anti-bot handling"""

    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = {
            # ✅ User-Agent più recente per bypassare protezioni anti-bot
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
        }
        self.session = None
        self.mediaflow_endpoint = "hls_manifest_proxy"
        self._cached_base_url = None
        self._iframe_context = None
        self._session_lock = asyncio.Lock()
        self.proxies = proxies or []
        self._extraction_locks: Dict[str, asyncio.Lock] = {} # ✅ NEW: Lock to prevent multiple extractions
        self.cache_file = os.path.join(os.path.dirname(__file__), '.dlhd_cache')
        self._stream_data_cache: Dict[str, Dict[str, Any]] = self._load_cache()

    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        """Loads the cache from a Base64-encoded file at startup."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    logger.info(f"💾 Loading cache from file: {self.cache_file}")
                    encoded_data = f.read()
                    if not encoded_data:
                        return {}
                    decoded_data = base64.b64decode(encoded_data).decode('utf-8')
                    return json.loads(decoded_data)
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"❌ Error loading cache: {e}. Starting with an empty cache.")
        return {}

    def _get_random_proxy(self):
        """Restituisce un proxy casuale dalla lista."""
        return random.choice(self.proxies) if self.proxies else None

    async def _get_session(self):
        """✅ Persistent session with automatic cookie jar"""
        if self.session is None or self.session.closed:
            timeout = ClientTimeout(total=60, connect=30, sock_read=30)
            proxy = self._get_random_proxy()
            if proxy:
                logger.info(f"🔗 Using proxy {proxy} for DLHD session.")
                connector = ProxyConnector.from_url(proxy, ssl=False)
            else:
                connector = TCPConnector(
                    limit=10,
                    limit_per_host=3,
                    keepalive_timeout=30,
                    enable_cleanup_closed=True,
                    force_close=False,
                    use_dns_cache=True
                )
                logger.info("ℹ️ No specific proxy for DLHD, using direct connection.")
            # ✅ CRUCIAL: Cookie jar to maintain session like a real browser
            self.session = ClientSession(
                timeout=timeout,
                connector=connector,
                headers=self.base_headers,
                cookie_jar=aiohttp.CookieJar()
            )
        return self.session

    def _save_cache(self):
        """Saves the current cache state to a file, encoding the content in Base64."""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json_data = json.dumps(self._stream_data_cache)
                encoded_data = base64.b64encode(json_data.encode('utf-8')).decode('utf-8')
                f.write(encoded_data)
                logger.info(f"💾 Cache encoded and saved successfully to file: {self.cache_file}")
        except IOError as e:
            logger.error(f"❌ Error saving cache: {e}")

    def _get_headers_for_url(self, url: str, base_headers: dict) -> dict:
        """Automatically applies specific headers for newkso.ru"""
        headers = base_headers.copy()
        parsed_url = urlparse(url)
        
        if "newkso.ru" in parsed_url.netloc:
            if self._iframe_context:
                iframe_origin = f"https://{urlparse(self._iframe_context).netloc}"
                newkso_headers = {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                    'Referer': self._iframe_context,
                    'Origin': iframe_origin
                }
                logger.info(f"Applied newkso.ru headers with iframe context for: {url}")
            else:
                newkso_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
                newkso_headers = {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                    'Referer': newkso_origin,
                    'Origin': newkso_origin
                }
            headers.update(newkso_headers)
        
        return headers

    async def _handle_response_content(self, response: aiohttp.ClientResponse) -> str:
        """Handles manual decompression of the response body (zstd, gzip, etc.)."""
        content_encoding = response.headers.get('Content-Encoding')
        raw_body = await response.read()
        
        try:
            if content_encoding == 'zstd':
                logger.info(f"Detected zstd compression for {response.url}. Decompressing...")
                try:
                    dctx = zstandard.ZstdDecompressor()
                    # ✅ MODIFICATION: Use stream_reader to handle frames without content size.
                    # This solves the "could not determine content size in frame header" error.
                    with dctx.stream_reader(raw_body) as reader:
                        decompressed_body = reader.read()
                    return decompressed_body.decode(response.charset or 'utf-8')
                except zstandard.ZstdError as e:
                    logger.error(f"Zstd decompression error: {e}. Content may be incomplete or corrupted.")
                    raise ExtractorError(f"zstd decompression failure: {e}")
            elif content_encoding == 'gzip':
                logger.info(f"Detected gzip compression for {response.url}. Decompressing...")
                decompressed_body = gzip.decompress(raw_body)
                return decompressed_body.decode(response.charset or 'utf-8')
            elif content_encoding == 'deflate':
                logger.info(f"Detected deflate compression for {response.url}. Decompressing...")
                decompressed_body = zlib.decompress(raw_body)
                return decompressed_body.decode(response.charset or 'utf-8')
            else:
                # No compression or unsupported compression, try to decode directly
                return raw_body.decode(response.charset or 'utf-8')
        except Exception as e:
            logger.error(f"Error during decompression/decoding of content from {response.url}: {e}")
            raise ExtractorError(f"Decompression failure for {response.url}: {e}")

    async def _make_robust_request(self, url: str, headers: dict = None, retries=3, initial_delay=2):
        """✅ Requests with persistent session to avoid anti-bot"""
        final_headers = self._get_headers_for_url(url, headers or {})
        # Add zstd to accepted encodings to signal server support
        final_headers['Accept-Encoding'] = 'gzip, deflate, br, zstd'
        
        for attempt in range(retries):
            try:
                # ✅ IMPORTANT: Always reuse the same session
                session = await self._get_session()
                
                logger.info(f"Attempt {attempt + 1}/{retries} for URL: {url}")
                async with session.get(url, headers=final_headers, ssl=False, auto_decompress=False) as response:
                    response.raise_for_status()
                    content = await self._handle_response_content(response)
                    
                    class MockResponse:
                        def __init__(self, text_content, status, headers_dict):
                            self._text = text_content
                            self.status = status
                            self.headers = headers_dict
                            self.url = url
                        
                        async def text(self):
                            return self._text
                            
                        def raise_for_status(self):
                            if self.status >= 400:
                                raise aiohttp.ClientResponseError(
                                    request_info=None, 
                                    history=None,
                                    status=self.status
                                )
                        
                        async def json(self):
                            return json.loads(self._text)
                    
                    logger.info(f"✅ Request succeeded for {url} on attempt {attempt + 1}")
                    return MockResponse(content, response.status, response.headers)
                    
            except (
                aiohttp.ClientConnectionError, 
                aiohttp.ServerDisconnectedError,
                aiohttp.ClientPayloadError,
                asyncio.TimeoutError,
                OSError,
                ConnectionResetError,
            ) as e:
                logger.warning(f"⚠️ Connection error attempt {attempt + 1} for {url}: {str(e)}")
                
                # ✅ Only in case of critical error, close the session
                if attempt == retries - 1:
                    if self.session and not self.session.closed:
                        try:
                            await self.session.close()
                        except:
                            pass
                    self.session = None
                
                if attempt < retries - 1:
                    delay = initial_delay * (2 ** attempt)
                    logger.info(f"⏳ Waiting {delay} seconds before next attempt...")
                    await asyncio.sleep(delay)
                else:
                    raise ExtractorError(f"All {retries} attempts failed for {url}: {str(e)}")
                    
            except Exception as e:
                # Check if error is due to zstd and log a specific message
                if 'zstd' in str(e).lower():
                    logger.critical(f"❌ Critical error with zstd decompression. Make sure the 'zstandard' library is installed (`pip install zstandard`). Error: {e}")
                else:
                    logger.error(f"❌ Non-network error attempt {attempt + 1} for {url}: {str(e)}")
                if attempt == retries - 1:
                    raise ExtractorError(f"Final error for {url}: {str(e)}")
        await asyncio.sleep(initial_delay)

    async def extract(self, url: str, force_refresh: bool = False, **kwargs) -> Dict[str, Any]:
        """Main extraction flow: resolves the base domain, finds players, extracts the iframe, authentication parameters, and final m3u8 URL."""
        async def resolve_base_url(preferred_host: Optional[str] = None) -> str:
            """Resolves the active base URL by trying a list of known domains."""
            if self._cached_base_url and not force_refresh:
                return self._cached_base_url
            
            DOMAINS = ['https://daddylive.sx/', 'https://dlhd.dad/']
            for base in DOMAINS:
                try:
                    resp = await self._make_robust_request(base, retries=1)
                    final_url = str(resp.url)
                    if not final_url.endswith('/'): final_url += '/' # Ensure trailing slash
                    self._cached_base_url = final_url
                    logger.info(f"✅ Base domain resolved: {final_url}")
                    return final_url
                except Exception as e:
                    logger.warning(f"⚠️ Failed attempt for base domain {base}: {e}")
            
            fallback = DOMAINS[0]
            logger.warning(f"All attempts to resolve the domain failed, using fallback: {fallback}")
            self._cached_base_url = fallback
            return fallback

        def extract_channel_id(u: str) -> Optional[str]:
            patterns = [
                r'/premium(\d+)/mono\.m3u8$',
                r'/(?:watch|stream|cast|player)/stream-(\d+)\.php',
                r'watch\.php\?id=(\d+)',
                r'(?:%2F|/)stream-(\d+)\.php',
                r'stream-(\d+)\.php'
            ]
            for pattern in patterns:
                match = re.search(pattern, u, re.IGNORECASE)
                if match:
                    return match.group(1)
            return None

        async def get_stream_data(baseurl: str, initial_url: str, channel_id: str):
            def _extract_auth_params_dynamic(js: str) -> Dict[str, Any]:
                """
                Dynamically extracts authentication parameters from obfuscated JavaScript.
                Looks for a Base64 string containing a JSON object with the parameters.
                """
                # Pattern to find a variable containing a long Base64 string
                pattern = r'(?:const|var|let)\s+[A-Z0-9_]+\s*=\s*["\']([a-zA-Z0-9+/=]{50,})["\']'
                matches = re.finditer(pattern, js)
                
                for match in matches:
                    b64_data = match.group(1)
                    try:
                        json_data = base64.b64decode(b64_data).decode('utf-8')
                        obj_data = json.loads(json_data)

                        # Map alternative key names to standard ones
                        key_mappings = {
                            'auth_host': ['host', 'b_host', 'server', 'domain'],
                            'auth_php': ['script', 'b_script', 'php', 'path'],
                            'auth_ts': ['ts', 'b_ts', 'timestamp', 'time'],
                            'auth_rnd': ['rnd', 'b_rnd', 'random', 'nonce'],
                            'auth_sig': ['sig', 'b_sig', 'signature', 'sign']
                        }
                        
                        result = {}
                        is_complete = True
                        for target_key, possible_names in key_mappings.items():
                            found_key = False
                            for name in possible_names:
                                if name in obj_data:
                                    try:
                                        # Try to decode if it's also base64
                                        decoded_value = base64.b64decode(obj_data[name]).decode('utf-8')
                                        result[target_key] = decoded_value
                                    except Exception:
                                        # Otherwise use the value as is
                                        result[target_key] = obj_data[name]
                                    found_key = True
                                    break
                            if not found_key:
                                is_complete = False
                                break
                        
                        if is_complete:
                            logger.info(f"✅ Authentication parameters dynamically found with keys: {list(obj_data.keys())}")
                            return result
                            
                    except Exception:
                        continue
                
                logger.warning("No valid authentication parameters found with dynamic search.")
                return {}

            daddy_origin = urlparse(baseurl).scheme + "://" + urlparse(baseurl).netloc
            daddylive_headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
                'Referer': baseurl,
                'Origin': daddy_origin
            }

            # 1. Initial page request to find player links
            resp1 = await self._make_robust_request(initial_url, headers=daddylive_headers)
            content1 = await resp1.text()
            player_links = re.findall(r'<button[^>]*data-url="([^"]+)"[^>]*>Player\s*\d+</button>', content1)
            if not player_links:
                raise ExtractorError("No player link found in the page.")

            last_player_error = None
            iframe_url = None
            for player_url in player_links:
                try:
                    if not player_url.startswith('http'):
                        player_url = urljoin(baseurl, player_url)

                    daddylive_headers['Referer'] = player_url
                    resp2 = await self._make_robust_request(player_url, headers=daddylive_headers)
                    content2 = await resp2.text()
                    iframes2 = re.findall(r'iframe src="([^"]*)', content2)
                    if iframes2:
                        iframe_url = iframes2[0]
                        if not iframe_url.startswith('http'):
                            iframe_url = urljoin(player_url, iframe_url)
                        break
                except Exception as e:
                    last_player_error = e
                    logger.warning(f"Failed to process player link {player_url}: {e}")
                    continue

            if not iframe_url:
                if last_player_error:
                    raise ExtractorError(f"All player links failed. Last error: {last_player_error}")
                raise ExtractorError("No valid iframe found in any player page")

            # Save the iframe context for newkso.ru headers
            self._iframe_context = iframe_url
            resp3 = await self._make_robust_request(iframe_url, headers=daddylive_headers)
            iframe_content = await resp3.text()

            try:
                # Extract channel key
                channel_key = None
                channel_key_patterns = [
                    r'const\s+CHANNEL_KEY\s*=\s*["\']([^"\']+)["\']',
                    r'channelKey\s*=\s*["\']([^"\']+)["\']',
                    r'(?:let|const)\s+channelKey\s*=\s*["\']([^"\']+)["\']',
                    r'var\s+channelKey\s*=\s*["\']([^"\']+)["\']',
                    r'channel_id\s*:\s*["\']([^"\']+)["\']' # Aggiunto per nuovi formati
                ]
                for pattern in channel_key_patterns:
                    match = re.search(pattern, iframe_content)
                    if match:
                        channel_key = match.group(1)
                        break

                # Extract authentication parameters with the new dynamic function
                params = _extract_auth_params_dynamic(iframe_content)
                auth_host = params.get("auth_host")
                auth_php = params.get("auth_php")
                auth_ts = params.get("auth_ts")
                auth_rnd = params.get("auth_rnd")
                auth_sig = params.get("auth_sig")

                # Check that all parameters are present
                missing_params = []
                if not channel_key:
                    missing_params.append('channel_key')
                if not auth_ts:
                    missing_params.append('auth_ts (timestamp)')
                if not auth_rnd:
                    missing_params.append('auth_rnd (random)')
                if not auth_sig:
                    missing_params.append('auth_sig (signature)')
                if not auth_host:
                    missing_params.append('auth_host (host)')
                if not auth_php:
                    missing_params.append('auth_php (script)')

                if missing_params:
                    raise ExtractorError(f"Missing parameters: {', '.join(missing_params)}")

                # Proceed with authentication
                auth_sig_quoted = quote_plus(auth_sig)
                if auth_php:
                    normalized_auth_php = auth_php.strip().lstrip('/')
                    if normalized_auth_php == 'a.php':
                        auth_php = 'auth.php' # urljoin gestirà lo slash
                
                # Build the authentication URL
                base_auth_url = urljoin(auth_host, auth_php)
                auth_url = f'{base_auth_url}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig_quoted}'
                
                # Step 4: Auth request with iframe context headers
                iframe_origin = f"https://{urlparse(iframe_url).netloc}"
                auth_headers = daddylive_headers.copy()
                auth_headers['Referer'] = iframe_url
                auth_headers['Origin'] = iframe_origin
                try:
                    await self._make_robust_request(auth_url, headers=auth_headers, retries=1)
                except Exception as auth_error:
                    logger.warning(f"Authentication request failed: {auth_error}.")
                    if channel_id in self._stream_data_cache:
                        del self._stream_data_cache[channel_id]
                        logger.info(f"Cache for channel {channel_id} invalidated; retrying.")
                        return await get_stream_data(baseurl, initial_url, channel_id)
                    raise ExtractorError(f"Authentication failed: {auth_error}")
                
                # Step 5: Server lookup
                server_lookup_path = None # Rewritten to be more robust
                # Dynamically search for the path for server lookup
                lookup_match = re.search(r"fetchWithRetry\(['\"](/server_lookup\.(?:js|php)\?channel_id=)['\"]", iframe_content)
                if lookup_match:
                    server_lookup_path = lookup_match.group(1)
                else:
                    # Fallback to a more generic pattern if the first fails
                    lookup_match_generic = re.search(r"['\"](/server_lookup\.(?:js|php)\?channel_id=)['\"]", iframe_content)
                    if lookup_match_generic:
                        server_lookup_path = lookup_match_generic.group(1)

                if not server_lookup_path:
                    logger.error(f"❌ Unable to extract the URL for server lookup. Iframe content: {iframe_content[:1000]}")
                    raise ExtractorError("Unable to extract the URL for server lookup")
                
                server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup_path}{channel_key}"
                try:
                    lookup_resp = await self._make_robust_request(server_lookup_url, headers=daddylive_headers)
                    server_data = await lookup_resp.json()
                    server_key = server_data.get('server_key')
                    if not server_key:
                        logger.error(f"No server_key in response: {server_data}")
                        raise ExtractorError("Failed to obtain server key from lookup response")
                except Exception as lookup_error:
                    logger.error(f"Server lookup request failed: {lookup_error}")
                    raise ExtractorError(f"Server lookup failed: {str(lookup_error)}")

                logger.info(f"Server key obtained: {server_key}")
                
                referer_raw = f'https://{urlparse(iframe_url).netloc}'
                
                # Build final stream URL
                if server_key == 'top1/cdn':
                    clean_m3u8_url = f'https://top1.newkso.ru/top1/cdn/{channel_key}/mono.m3u8' # Known working domain
                elif '/' in server_key:
                    parts = server_key.split('/')
                    domain = parts[0]
                    clean_m3u8_url = f'https://{domain}.newkso.ru/{server_key}/{channel_key}/mono.m3u8'
                else:
                    # ✅ FIX: Use a more reliable fallback domain if dynamic construction fails.
                    # 'top1' is newer and more stable than 'top2'.
                    clean_m3u8_url = f'https://{server_key}new.newkso.ru/{server_key}/{channel_key}/mono.m3u8'.replace('top2new', 'top1new')
                
                # Set final headers
                if "newkso.ru" in clean_m3u8_url:
                    stream_headers = {
                        'User-Agent': daddylive_headers['User-Agent'],
                        'Referer': iframe_url,
                        'Origin': referer_raw
                    }
                else:
                    stream_headers = {
                        'User-Agent': daddylive_headers['User-Agent'],
                        'Referer': referer_raw,
                        'Origin': referer_raw
                    }
                
                logger.info(f"🔧 Final headers for stream: {stream_headers}")
                logger.info(f"✅ Final stream URL: {clean_m3u8_url}")
                
                result_data = {
                    "destination_url": clean_m3u8_url,
                    "request_headers": stream_headers,
                    "mediaflow_endpoint": self.mediaflow_endpoint,
                }
                # Save to cache
                self._stream_data_cache[channel_id] = result_data
                self._save_cache()
                logger.info(f"💾 Data for channel ID {channel_id} saved to cache.")
                return result_data
                
            except Exception as param_error:
                logger.error(f"Error in parameter extraction: {str(param_error)}")
                raise ExtractorError(f"Parameter extraction failure: {str(param_error)}")

        try:
            channel_id = extract_channel_id(url)
            if not channel_id:
                raise ExtractorError(f"Impossibile estrarre channel ID da {url}")

            # Check the cache before proceeding
            if not force_refresh and channel_id in self._stream_data_cache:
                logger.info(f"✅ Found cached data for channel ID: {channel_id}. Verifying validity...")
                cached_data = self._stream_data_cache[channel_id]
                stream_url = cached_data.get("destination_url")
                stream_headers = cached_data.get("request_headers", {})

                is_valid = False
                if stream_url:
                    try:
                        # Use a separate session for validation to not interfere
                        # with the main session and its cookies.
                        async with aiohttp.ClientSession(timeout=ClientTimeout(total=10)) as validation_session:
                            async with validation_session.head(stream_url, headers=stream_headers, ssl=False) as response:
                                # Use a HEAD request for efficiency, with a short timeout
                                if response.status == 200:
                                    is_valid = True
                                    logger.info(f"✅ Cache for channel ID {channel_id} is valid.")
                                else:
                                    logger.warning(f"⚠️ Cache for channel ID {channel_id} is not valid. Status: {response.status}. Proceeding with extraction.")
                    except Exception as e:
                        logger.warning(f"⚠️ Error during cache validation for {channel_id}: {e}. Proceeding with extraction.")
                
                if not is_valid:
                    # Remove invalid data from cache
                    if channel_id in self._stream_data_cache:
                        del self._stream_data_cache[channel_id]
                    self._save_cache()
                    logger.info(f"🗑️ Cache invalidated for channel ID {channel_id}.")
                else:
                    # ✅ NEW: Perform a "keep-alive" request to keep the session active
                    # This uses the proxy if configured, as requested.
                    try:
                        logger.info(f"🔄 Performing a keep-alive request for channel {channel_id} to keep the session active via proxy.")
                        baseurl = await resolve_base_url()
                        # Perform a lightweight request to the channel page to refresh session cookies.
                        # This ensures the proxy is used.
                        await self._make_robust_request(url, retries=1)
                        logger.info(f"✅ Session for channel {channel_id} successfully refreshed.")
                    except Exception as e:
                        logger.warning(f"⚠️ Keep-alive request failed for channel {channel_id}: {e}. The stream may not work.")
                    
                    return cached_data

            # ✅ NEW: Use a lock to prevent simultaneous extractions for the same channel
            if channel_id not in self._extraction_locks:
                self._extraction_locks[channel_id] = asyncio.Lock()
            
            lock = self._extraction_locks[channel_id]
            async with lock:
                # Recheck the cache after acquiring the lock, another process may have already populated it
                if channel_id in self._stream_data_cache:
                    logger.info(f"✅ Data for channel {channel_id} found in cache after waiting for lock.")
                    return self._stream_data_cache[channel_id]

                # Proceed with extraction
                logger.info(f"⚙️ No valid cache for {channel_id}, starting full extraction...")
                baseurl = await resolve_base_url()
                return await get_stream_data(baseurl, url, channel_id)
            
        except Exception as e:
            logger.exception(f"DLHD extraction completely failed for URL {url}")
            raise ExtractorError(f"DLHD extraction completely failed: {str(e)}")

    async def invalidate_cache_for_url(self, url: str):
        """
        Invalidates the cache for a specific URL.
        This function is called by app.py when it detects an error (e.g. AES key failure).
        """
        def extract_channel_id_internal(u: str) -> Optional[str]:
            patterns = [
                r'/premium(\d+)/mono\.m3u8$',
                r'/(?:watch|stream|cast|player)/stream-(\d+)\.php',
                r'watch\.php\?id=(\d+)',
                r'(?:%2F|/)stream-(\d+)\.php',
                r'stream-(\d+)\.php'
            ]
            for pattern in patterns:
                match = re.search(pattern, u, re.IGNORECASE)
                if match: return match.group(1)
            return None

        channel_id = extract_channel_id_internal(url)
        if channel_id and channel_id in self._stream_data_cache:
            del self._stream_data_cache[channel_id]
            self._save_cache()
            logger.info(f"🗑️ Cache for channel ID {channel_id} invalidated due to an external error (e.g. AES key).")

    async def close(self):
        """Closes the session permanently"""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
            except:
                pass
        self.session = None
