import asyncio
import logging
import re
import sys
import random
import os
import urllib.parse
from urllib.parse import urlparse, urljoin
import xml.etree.ElementTree as ET
import aiohttp
from aiohttp import web
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp_proxy import ProxyConnector
from dotenv import load_dotenv

load_dotenv() # Loads variables from the .env file

# Logging configuration
# ✅ FIX: Set a standard format and ensure that the 'aiohttp.access' logger
# is not silenced, allowing access logs to be displayed.
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s:%(name)s:%(message)s'
)

logger = logging.getLogger(__name__)

 # --- Proxy Configuration ---
def parse_proxies(proxy_env_var: str) -> list:
    """Parses a comma-separated proxy string from an environment variable."""
    proxies_str = os.environ.get(proxy_env_var, "").strip()
    if proxies_str:
        return [p.strip() for p in proxies_str.split(',') if p.strip()]
    return []

GLOBAL_PROXIES = parse_proxies('GLOBAL_PROXY')
VAVOO_PROXIES = parse_proxies('VAVOO_PROXY')
DLHD_PROXIES = parse_proxies('DLHD_PROXY')

if GLOBAL_PROXIES: logging.info(f"🌍 Loaded {len(GLOBAL_PROXIES)} global proxies.")
if VAVOO_PROXIES: logging.info(f"🎬 Loaded {len(VAVOO_PROXIES)} Vavoo proxies.")
if DLHD_PROXIES: logging.info(f"📺 Loaded {len(DLHD_PROXIES)} DLHD proxies.")

 # Add current path for module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

 # --- External Modules ---
# Imported individually for more granular feedback in case of errors.
VavooExtractor, DLHDExtractor, VixSrcExtractor, PlaylistBuilder, SportsonlineExtractor = None, None, None, None, None

try:
    from vavoo_extractor import VavooExtractor
    logger.info("✅ VavooExtractor module loaded.")
except ImportError:
    logger.warning("⚠️ VavooExtractor module not found. Vavoo functionality disabled.")

try:
    from dlhd_extractor import DLHDExtractor
    logger.info("✅ DLHDExtractor module loaded.")
except ImportError:
    logger.warning("⚠️ DLHDExtractor module not found. DLHD functionality disabled.")

try:
    from playlist_builder import PlaylistBuilder
    logger.info("✅ PlaylistBuilder module loaded.")
except ImportError:
    logger.warning("⚠️ PlaylistBuilder module not found. PlaylistBuilder functionality disabled.")
    
try:
    from vixsrc_extractor import VixSrcExtractor
    logger.info("✅ VixSrcExtractor module loaded.")
except ImportError:
    logger.warning("⚠️ VixSrcExtractor module not found. VixSrc functionality disabled.")

try:
    from sportsonline_extractor import SportsonlineExtractor
    logger.info("✅ SportsonlineExtractor module loaded.")
except ImportError:
    logger.warning("⚠️ SportsonlineExtractor module not found. Sportsonline functionality disabled.")

 # --- Unified Classes ---
class ExtractorError(Exception):
    """Custom exception for extraction errors"""
    pass

class GenericHLSExtractor:
    def __init__(self, request_headers, proxies=None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.session = None
        self.proxies = proxies or []

    def _get_random_proxy(self):
        """Returns a random proxy from the list."""
        return random.choice(self.proxies) if self.proxies else None

    async def _get_session(self):
        if self.session is None or self.session.closed:
            proxy = self._get_random_proxy()
            if proxy:
                logging.info(f"Utilizzo del proxy {proxy} per la sessione generica.")
                connector = ProxyConnector.from_url(proxy)
            else:
                connector = TCPConnector(
                    limit=20, limit_per_host=10, 
                    keepalive_timeout=60, enable_cleanup_closed=True, 
                    force_close=False, use_dns_cache=True
                )

            timeout = ClientTimeout(total=60, connect=30, sock_read=30)
            self.session = ClientSession(
                timeout=timeout, connector=connector, 
                headers={'user-agent': self.base_headers['user-agent']}
            )
        return self.session

    async def extract(self, url, **kwargs):
        # ✅ FIX: Also allows VixSrc playlist URLs that do not require an extension.
        if not any(pattern in url.lower() for pattern in ['.m3u8', '.mpd', '.ts', 'vixsrc.to/playlist']):
            raise ExtractorError("Unsupported URL (requires .m3u8, .mpd, .ts or valid VixSrc URL)")

        parsed_url = urlparse(url)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        headers = self.base_headers.copy()
        headers.update({"referer": origin, "origin": origin})

        for h, v in self.request_headers.items():
            if h.lower() in ["authorization", "x-api-key", "x-auth-token"]:
                headers[h] = v

        return {
            "destination_url": url, 
            "request_headers": headers, 
            "mediaflow_endpoint": "hls_proxy"
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

class HLSProxy:
    """HLS Proxy to handle Vavoo, DLHD, generic HLS streams, and playlist builder with AES-128 support"""
    
    def __init__(self):
        self.extractors = {}
        
        # Initialize playlist_builder if the module is available
        if PlaylistBuilder:
            self.playlist_builder = PlaylistBuilder()
            logger.info("✅ PlaylistBuilder initialized")
        else:
            self.playlist_builder = None
    
    async def get_extractor(self, url: str, request_headers: dict):
        """Gets the appropriate extractor for the URL"""
        try:
            if "vavoo.to" in url:
                key = "vavoo"
                proxies = VAVOO_PROXIES or GLOBAL_PROXIES
                if key not in self.extractors:
                    self.extractors[key] = VavooExtractor(request_headers, proxies=proxies)
                return self.extractors[key]
            elif any(domain in url for domain in ["daddylive", "dlhd"]) or re.search(r'stream-\d+\.php', url):
                key = "dlhd"
                proxies = DLHD_PROXIES or GLOBAL_PROXIES
                if key not in self.extractors:
                    self.extractors[key] = DLHDExtractor(request_headers, proxies=proxies)
                return self.extractors[key]
            # ✅ MODIFICATO: Aggiunto 'vixsrc.to/playlist' per gestire i sub-manifest come HLS generici.
            elif any(ext in url.lower() for ext in ['.m3u8', '.mpd', '.ts']) or 'vixsrc.to/playlist' in url.lower():
                key = "hls_generic"
                if key not in self.extractors:
                    self.extractors[key] = GenericHLSExtractor(request_headers, proxies=GLOBAL_PROXIES)
                return self.extractors[key]
            elif 'vixsrc.to/' in url.lower() and any(x in url for x in ['/movie/', '/tv/', '/iframe/']):
                key = "vixsrc"
                if key not in self.extractors:
                    self.extractors[key] = VixSrcExtractor(request_headers, proxies=GLOBAL_PROXIES)
                return self.extractors[key]
            elif any(domain in url for domain in ["sportzonline", "sportsonline"]):
                key = "sportsonline"
                proxies = GLOBAL_PROXIES
                if key not in self.extractors:
                    self.extractors[key] = SportsonlineExtractor(request_headers, proxies=proxies)
                return self.extractors[key]
            else:
                raise ExtractorError("Unsupported URL type")
        except (NameError, TypeError) as e:
            raise ExtractorError(f"Extractor not available - missing module: {e}")

    async def handle_proxy_request(self, request):
        """Handles main proxy requests"""
        extractor = None
        try:
            target_url = request.query.get('url')
            force_refresh = request.query.get('force', 'false').lower() == 'true'
            if not target_url:
                return web.Response(text="Missing 'url' parameter", status=400)
            
            try:
                target_url = urllib.parse.unquote(target_url)
            except:
                pass
                
            log_message = f"Proxy request for URL: {target_url}"
            if force_refresh:
                log_message += " (Forced refresh)"
            logger.info(log_message)
            
            extractor = await self.get_extractor(target_url, dict(request.headers))
            
            try:
                # Passa il flag force_refresh all'estrattore
                result = await extractor.extract(target_url, force_refresh=force_refresh)
                stream_url = result["destination_url"]
                stream_headers = result.get("request_headers", {})
                
                # Aggiungi headers personalizzati da query params
                for param_name, param_value in request.query.items():
                    if param_name.startswith('h_'):
                        header_name = param_name[2:]
                        stream_headers[header_name] = param_value
                
                logger.info(f"Resolved stream URL: {stream_url}")
                return await self._proxy_stream(request, stream_url, stream_headers)
            except ExtractorError as e:
                logger.warning(f"Extraction failed, retrying with forced refresh: {e}")
                result = await extractor.extract(target_url, force_refresh=True) # Always force refresh on second attempt
                stream_url = result["destination_url"]
                stream_headers = result.get("request_headers", {})
                logger.info(f"Resolved stream URL after refresh: {stream_url}")
                return await self._proxy_stream(request, stream_url, stream_headers)
            
        except Exception as e:
            # ✅ UPDATED: If a specific extractor (DLHD, Vavoo) fails, restart the server to force an update.
            # This is useful if the site has changed something and the extractor is outdated.
            restarting = False
            extractor_name = "unknown"
            if DLHDExtractor and isinstance(extractor, DLHDExtractor):
                restarting = True
                extractor_name = "DLHDExtractor"
            elif VavooExtractor and isinstance(extractor, VavooExtractor):
                restarting = True
                extractor_name = "VavooExtractor"

            if restarting:
                logger.critical(f"❌ Critical error with {extractor_name}: {e}. Restarting to force update...")
                await asyncio.sleep(1)  # Wait for log flush
                os._exit(1)  # Forced exit to trigger restart from process manager (Docker, Gunicorn)

            logger.exception(f"Error in proxy request: {str(e)}")
            return web.Response(text=f"Proxy error: {str(e)}", status=500)

    async def handle_key_request(self, request):
        """✅ NEW: Handles requests for AES-128 keys"""
        key_url = request.query.get('key_url')
        
        if not key_url:
            return web.Response(text="Missing key_url parameter", status=400)
        
        try:
            # Decode the URL if needed
            try:
                key_url = urllib.parse.unquote(key_url)
            except:
                pass
                
            # Initialize headers exclusively from those passed dynamically
            # via the URL. If the extractor doesn't pass them, the request
            # will be made without specific headers, relying on the extraction
            # flow correctness.
            headers = {}
            for param_name, param_value in request.query.items():
                if param_name.startswith('h_'):
                    header_name = param_name[2:].replace('_', '-')
                    headers[header_name] = param_value

            logger.info(f"🔑 Fetching AES key from: {key_url}")
            logger.debug(f"   -> with headers: {headers}")
            
            # ✅ FIX: Select the correct proxy (DLHD, Vavoo, etc.) based on the original URL.
            # If there is no specific proxy, use the global one as fallback.
            proxy_list = GLOBAL_PROXIES
            original_channel_url = request.query.get('original_channel_url')

            # If the key URL is a newkso.ru domain or the original URL is DLHD, use the DLHD proxy.
            if "newkso.ru" in key_url or (original_channel_url and any(domain in original_channel_url for domain in ["daddylive", "dlhd"])):
                proxy_list = DLHD_PROXIES or GLOBAL_PROXIES
            # Otherwise, if it's a Vavoo URL, use the Vavoo proxy.
            elif original_channel_url and "vavoo.to" in original_channel_url:
                proxy_list = VAVOO_PROXIES or GLOBAL_PROXIES
            
            proxy = random.choice(proxy_list) if proxy_list else None
            connector_kwargs = {}
            if proxy:
                connector_kwargs['proxy'] = proxy
                logger.info(f"Using proxy {proxy} for key request.")
            
            timeout = ClientTimeout(total=30)
            async with ClientSession(timeout=timeout) as session:
                async with session.get(key_url, headers=headers, **connector_kwargs) as resp:
                    if resp.status == 200:
                        key_data = await resp.read()
                        logger.info(f"✅ AES key fetched successfully: {len(key_data)} bytes")
                        
                        return web.Response(
                            body=key_data,
                            content_type="application/octet-stream",
                            headers={
                                "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Headers": "*",
                                "Cache-Control": "no-cache, no-store, must-revalidate"
                            }
                        )
                    else:
                        logger.error(f"❌ Key fetch failed with status: {resp.status}")
                        # --- AUTOMATIC INVALIDATION LOGIC ---
                        # If key retrieval fails, it's likely the extractor's cache is outdated. Invalidate it.
                        try:
                            url_param = request.query.get('original_channel_url') # ✅ FIX: Use the correct parameter
                            if url_param:
                                extractor = await self.get_extractor(url_param, {})
                                if hasattr(extractor, 'invalidate_cache_for_url'):
                                    await extractor.invalidate_cache_for_url(url_param)
                        except Exception as cache_e:
                            logger.error(f"⚠️ Error during automatic cache invalidation: {cache_e}")
                        # --- END LOGIC ---
                        return web.Response(text=f"Key fetch failed: {resp.status}", status=resp.status)
                        
        except Exception as e:
            logger.error(f"❌ Error fetching AES key: {str(e)}")
            return web.Response(text=f"Key error: {str(e)}", status=500)

    async def handle_ts_segment(self, request):
        """Handles requests for .ts segments"""
        try:
            segment_name = request.match_info.get('segment')
            base_url = request.query.get('base_url')
            
            if not base_url:
                return web.Response(text="Missing base URL for segment", status=400)
            
            base_url = urllib.parse.unquote(base_url)
            
            if base_url.endswith('/'):
                segment_url = f"{base_url}{segment_name}"
            else:
                segment_url = f"{base_url.rsplit('/', 1)[0]}/{segment_name}"
            
            # Handles the proxy response for the segment
            return await self._proxy_segment(request, segment_url, {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "referer": base_url
            }, segment_name)
            
        except Exception as e:
            logger.error(f"Error in .ts segment proxy: {str(e)}")
            return web.Response(text=f"Segment error: {str(e)}", status=500)

    async def _proxy_segment(self, request, segment_url, stream_headers, segment_name):
        """✅ NEW: Dedicated proxy for .ts segments with Content-Disposition"""
        try:
            headers = dict(stream_headers)
            
            # Passa attraverso alcuni headers del client
            for header in ['range', 'if-none-match', 'if-modified-since']:
                if header in request.headers:
                    headers[header] = request.headers[header]
            
            proxy = random.choice(GLOBAL_PROXIES) if GLOBAL_PROXIES else None
            connector_kwargs = {}
            if proxy:
                connector_kwargs['proxy'] = proxy
                logger.info(f"Using proxy {proxy} for .ts segment.")

            timeout = ClientTimeout(total=60, connect=30)
            async with ClientSession(timeout=timeout) as session:
                async with session.get(segment_url, headers=headers, **connector_kwargs) as resp:
                    response_headers = {}
                    
                    for header in ['content-type', 'content-length', 'content-range', 
                                 'accept-ranges', 'last-modified', 'etag']:
                        if header in resp.headers:
                            response_headers[header] = resp.headers[header]
                    
                    # Forza il content-type e aggiunge Content-Disposition per .ts
                    response_headers['Content-Type'] = 'video/MP2T'
                    response_headers['Content-Disposition'] = f'attachment; filename="{segment_name}"'
                    response_headers['Access-Control-Allow-Origin'] = '*'
                    response_headers['Access-Control-Allow-Methods'] = 'GET, HEAD, OPTIONS'
                    response_headers['Access-Control-Allow-Headers'] = 'Range, Content-Type'
                    
                    response = web.StreamResponse(
                        status=resp.status,
                        headers=response_headers
                    )
                    
                    await response.prepare(request)
                    
                    async for chunk in resp.content.iter_chunked(8192):
                        await response.write(chunk)
                    
                    await response.write_eof()
                    return response
                    
        except Exception as e:
            logger.error(f"Error in segment proxy: {str(e)}")
            return web.Response(text=f"Segment error: {str(e)}", status=500)

    async def _proxy_stream(self, request, stream_url, stream_headers):
        """Proxies the stream with manifest and AES-128 handling"""
        try:
            headers = dict(stream_headers)
            
            # Passa attraverso alcuni headers del client
            for header in ['range', 'if-none-match', 'if-modified-since']:
                if header in request.headers:
                    headers[header] = request.headers[header]
            
            proxy = random.choice(GLOBAL_PROXIES) if GLOBAL_PROXIES else None
            connector_kwargs = {}
            if proxy:
                connector_kwargs['proxy'] = proxy
                logger.info(f"Using proxy {proxy} for the stream.")

            timeout = ClientTimeout(total=60, connect=30)
            async with ClientSession(timeout=timeout) as session:
                async with session.get(stream_url, headers=headers, **connector_kwargs) as resp:
                    content_type = resp.headers.get('content-type', '')
                    
                    # Special handling for HLS manifests
                    if 'mpegurl' in content_type or stream_url.endswith('.m3u8'):
                        manifest_content = await resp.text()
                        
                        # ✅ CORREZIONE: Rileva lo schema e l'host corretti quando dietro un reverse proxy
                        scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
                        host = request.headers.get('X-Forwarded-Host', request.host)
                        proxy_base = f"{scheme}://{host}"
                        original_channel_url = request.query.get('url', '')
                        logger.info(f"Building proxy URL based on: {proxy_base}")
                        
                        rewritten_manifest = await self._rewrite_manifest_urls(
                            manifest_content, stream_url, proxy_base, headers, original_channel_url
                        )
                        
                        return web.Response(
                            text=rewritten_manifest,
                            headers={
                                'Content-Type': 'application/vnd.apple.mpegurl',
                                'Content-Disposition': 'attachment; filename="stream.m3u8"',
                                'Access-Control-Allow-Origin': '*',
                                'Cache-Control': 'no-cache'
                            }
                        )
                    
                    # ✅ UPDATED: Handling for MPD (DASH) manifests
                    elif 'dash+xml' in content_type or stream_url.endswith('.mpd'):
                        manifest_content = await resp.text()
                        
                        # ✅ CORREZIONE: Rileva lo schema e l'host corretti quando dietro un reverse proxy
                        scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
                        host = request.headers.get('X-Forwarded-Host', request.host)
                        proxy_base = f"{scheme}://{host}"
                        logger.info(f"Building proxy URL for MPD based on: {proxy_base}")
                        
                        rewritten_manifest = self._rewrite_mpd_manifest(manifest_content, stream_url, proxy_base, headers)
                        
                        return web.Response(
                            text=rewritten_manifest,
                            headers={
                                'Content-Type': 'application/dash+xml',
                                'Content-Disposition': 'attachment; filename="stream.mpd"',
                                'Access-Control-Allow-Origin': '*',
                                'Cache-Control': 'no-cache'
                            })
                    
                    # Normal streaming for other content types
                    response_headers = {}
                    
                    for header in ['content-type', 'content-length', 'content-range', 
                                 'accept-ranges', 'last-modified', 'etag']:
                        if header in resp.headers:
                            response_headers[header] = resp.headers[header]
                    
                    response_headers['Access-Control-Allow-Origin'] = '*'
                    response_headers['Access-Control-Allow-Methods'] = 'GET, HEAD, OPTIONS'
                    response_headers['Access-Control-Allow-Headers'] = 'Range, Content-Type'
                    
                    response = web.StreamResponse(
                        status=resp.status,
                        headers=response_headers
                    )
                    
                    await response.prepare(request)
                    
                    async for chunk in resp.content.iter_chunked(8192):
                        await response.write(chunk)
                    
                    await response.write_eof()
                    return response
                    
        except Exception as e:
            logger.error(f"Error in stream proxy: {str(e)}")
            return web.Response(text=f"Stream error: {str(e)}", status=500)

    def _rewrite_mpd_manifest(self, manifest_content: str, base_url: str, proxy_base: str, stream_headers: dict) -> str:
        """Rewrites MPD (DASH) manifests to pass through the proxy."""
        try:
            # Add default namespace if not present, for ET
            if 'xmlns' not in manifest_content:
                manifest_content = manifest_content.replace('<MPD', '<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"', 1)

            root = ET.fromstring(manifest_content)
            ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}

            # Include only relevant headers to avoid overly long URLs
            header_params = "".join([f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}" for key, value in stream_headers.items() if key.lower() in ['user-agent', 'referer', 'origin', 'authorization']])

            def create_proxy_url(relative_url):
                absolute_url = urljoin(base_url, relative_url)
                encoded_url = urllib.parse.quote(absolute_url, safe='')
                return f"{proxy_base}/proxy/manifest.m3u8?url={encoded_url}{header_params}"

            # Rewrite 'media' and 'initialization' attributes in <SegmentTemplate>
            for template_tag in root.findall('.//mpd:SegmentTemplate', ns):
                for attr in ['media', 'initialization']:
                    if template_tag.get(attr):
                        template_tag.set(attr, create_proxy_url(template_tag.get(attr)))
            
            # Rewrite 'media' attribute in <SegmentURL>
            for seg_url_tag in root.findall('.//mpd:SegmentURL', ns):
                if seg_url_tag.get('media'):
                    seg_url_tag.set('media', create_proxy_url(seg_url_tag.get('media')))

            return ET.tostring(root, encoding='unicode', method='xml')

        except Exception as e:
            logger.error(f"❌ Error while rewriting MPD manifest: {e}")
            return manifest_content # Returns original content in case of error

    async def _rewrite_manifest_urls(self, manifest_content: str, base_url: str, proxy_base: str, stream_headers: dict, original_channel_url: str = '') -> str:
        """✅ UPDATED: Rewrites URLs in HLS manifests to pass through the proxy (including AES keys)"""
        lines = manifest_content.split('\n')
        rewritten_lines = []
        
        # ✅ NEW: Special logic for VixSrc
        # Determines if the base URL is from VixSrc to apply custom logic.
        is_vixsrc_stream = False
        try:
            # Use the original request URL to determine the extractor
            # This is more reliable than `base_url` which may already be a playlist URL.
            original_request_url = stream_headers.get('referer', base_url)
            extractor = await self.get_extractor(original_request_url, {})
            if hasattr(extractor, 'is_vixsrc') and extractor.is_vixsrc:
                is_vixsrc_stream = True
                logger.info("Detected VixSrc stream. Will apply quality filtering and non-proxy logic.")
        except Exception:
            # Se l'estrattore non viene trovato, procedi normalmente.
            pass

        if is_vixsrc_stream:
            streams = []
            for i, line in enumerate(lines):
                if line.startswith('#EXT-X-STREAM-INF:'):
                    bandwidth_match = re.search(r'BANDWIDTH=(\d+)', line)
                    if bandwidth_match:
                        bandwidth = int(bandwidth_match.group(1))
                        streams.append({'bandwidth': bandwidth, 'inf': line, 'url': lines[i+1]})
            
            if streams:
                # Filter for the highest quality
                highest_quality_stream = max(streams, key=lambda x: x['bandwidth'])
                logger.info(f"VixSrc: Found highest quality with bandwidth {highest_quality_stream['bandwidth']}.")
                
                # Rebuild the manifest only with the highest quality and original URLs
                rewritten_lines.append('#EXTM3U')
                for line in lines:
                    if line.startswith('#EXT-X-MEDIA:') or line.startswith('#EXT-X-STREAM-INF:') or (line and not line.startswith('#')):
                        continue # Skip old stream and media tags
                
                # Add media tags and the highest quality stream
                rewritten_lines.extend([line for line in lines if line.startswith('#EXT-X-MEDIA:')])
                rewritten_lines.append(highest_quality_stream['inf'])
                rewritten_lines.append(highest_quality_stream['url'])
                return '\n'.join(rewritten_lines)

        # Standard logic for all other streams
        header_params = "".join([f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}" for key, value in stream_headers.items() if key.lower() in ['user-agent', 'referer', 'origin', 'authorization']])

        for line in lines:
            line = line.strip()
            
            # ✅ NEW: AES-128 key handling
            if line.startswith('#EXT-X-KEY:') and 'URI=' in line:
                # Find and replace the AES key URI
                uri_start = line.find('URI="') + 5
                uri_end = line.find('"', uri_start)
                
                if uri_start > 4 and uri_end > uri_start:
                    original_key_url = line[uri_start:uri_end]
                    
                    # ✅ FIX: Use urljoin to safely build the absolute key URL.
                    absolute_key_url = urljoin(base_url, original_key_url)
                    
                    # Create proxy URL for the key
                    encoded_key_url = urllib.parse.quote(absolute_key_url, safe='')
                    # ✅ AGGIUNTO: Passa l'URL originale del canale per l'invalidazione della cache
                    encoded_original_channel_url = urllib.parse.quote(original_channel_url, safe='')
                    proxy_key_url = f"{proxy_base}/key?key_url={encoded_key_url}&original_channel_url={encoded_original_channel_url}"

                    # Add necessary headers as h_ parameters
                    # This allows the key handler to use the correct context
                    # ✅ FIX: Pass all relevant headers to the key request
                    # to ensure correct authentication.
                    key_header_params = "".join(
                        [f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}" 
                         for key, value in stream_headers.items() if key.lower() in ['user-agent', 'referer', 'origin', 'authorization']]
                    )
                    proxy_key_url += key_header_params
                    
                    # Replace the URI in the EXT-X-KEY tag
                    new_line = line[:uri_start] + proxy_key_url + line[uri_end:]
                    rewritten_lines.append(new_line)
                    logger.info(f"🔄 Redirected AES key: {absolute_key_url} -> {proxy_key_url}")
                else:
                    rewritten_lines.append(line)
            
            # ✅ NEW: Handling for subtitles and other media in #EXT-X-MEDIA tag
            elif line.startswith('#EXT-X-MEDIA:') and 'URI=' in line:
                uri_start = line.find('URI="') + 5
                uri_end = line.find('"', uri_start)
                
                if uri_start > 4 and uri_end > uri_start:
                    original_media_url = line[uri_start:uri_end]
                    
                    # Build the absolute URL and then the proxy URL
                    absolute_media_url = urljoin(base_url, original_media_url)
                    encoded_media_url = urllib.parse.quote(absolute_media_url, safe='')
                    
                    # Subtitles are manifests, so they use the main proxy endpoint
                    proxy_media_url = f"{proxy_base}/proxy/manifest.m3u8?url={encoded_media_url}{header_params}"
                    
                    # Replace the URI in the tag
                    new_line = line[:uri_start] + proxy_media_url + line[uri_end:]
                    rewritten_lines.append(new_line)
                    logger.info(f"🔄 Redirected Media URL: {absolute_media_url} -> {proxy_media_url}")
                else:
                    rewritten_lines.append(line)

            # Handling video segments (.ts) and sub-manifests (.m3u8), both relative and absolute
            elif line and not line.startswith('#') and ('http' in line or not any(c in line for c in ' =?')):
                # ✅ FINAL FIX: Distinguish between manifests and segments.
                # Manifests (.m3u8) and vixsrc playlists go to the main proxy endpoint.
                if '.m3u8' in line or 'vixsrc.to/playlist' in line:
                    absolute_url = urljoin(base_url, line) if not line.startswith('http') else line
                    encoded_url = urllib.parse.quote(absolute_url, safe='')
                    proxy_url = f"{proxy_base}/proxy/manifest.m3u8?url={encoded_url}{header_params}"
                    rewritten_lines.append(proxy_url)
                # .ts segments are handled as direct streams via the same endpoint,
                # but logic in `handle_proxy_request` and `get_extractor` will route them correctly.
                elif '.ts' in line:
                    absolute_url = urljoin(base_url, line) if not line.startswith('http') else line
                    encoded_url = urllib.parse.quote(absolute_url, safe='')
                    # Use the same endpoint; logic in `get_extractor` and `_proxy_stream` will distinguish content-type.
                    proxy_url = f"{proxy_base}/proxy/manifest.m3u8?url={encoded_url}{header_params}"
                    rewritten_lines.append(proxy_url)
                else:
                    rewritten_lines.append(line) # Leave other absolute URLs unchanged
            else:
                rewritten_lines.append(line)
        
        return '\n'.join(rewritten_lines)

    async def handle_playlist_request(self, request):
        """Handles requests for the playlist builder"""
        if not self.playlist_builder:
            return web.Response(text="❌ Playlist Builder not available - missing module", status=503)
            
        try:
            url_param = request.query.get('url')
            
            if not url_param:
                return web.Response(text="Missing 'url' parameter", status=400)
            
            if not url_param.strip():
                return web.Response(text="'url' parameter cannot be empty", status=400)
            
            playlist_definitions = [def_.strip() for def_ in url_param.split(';') if def_.strip()]
            if not playlist_definitions:
                return web.Response(text="No valid playlist definition found", status=400)
            
            # ✅ FIX: Detect correct scheme and host when behind a reverse proxy
            scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
            host = request.headers.get('X-Forwarded-Host', request.host)
            base_url = f"{scheme}://{host}"
            
            async def generate_response():
                async for line in self.playlist_builder.async_generate_combined_playlist(
                    playlist_definitions, base_url
                ):
                    yield line.encode('utf-8')
            
            response = web.StreamResponse(
                status=200,
                headers={
                    'Content-Type': 'application/vnd.apple.mpegurl',
                    'Content-Disposition': 'attachment; filename=\"playlist.m3u\"',
                    'Access-Control-Allow-Origin': '*'
                }
            )
            
            await response.prepare(request)
            
            async for chunk in generate_response():
                await response.write(chunk)
            
            await response.write_eof()
            return response
            
        except Exception as e:
            logger.error(f"General error in playlist handler: {str(e)}")
            return web.Response(text=f"Error: {str(e)}", status=500)

    def _read_template(self, filename: str) -> str:
        """Helper function to read a template file."""
        template_path = os.path.join(os.path.dirname(__file__), 'templates', filename)
        with open(template_path, 'r', encoding='utf-8') as f:
            return f.read()

    async def handle_root(self, request):
        """Serves the main index.html page."""
        try:
            html_content = self._read_template('index.html')
            return web.Response(text=html_content, content_type='text/html')
        except Exception as e:
            logger.error(f"❌ Critical error: unable to load 'index.html': {e}")
            return web.Response(text="<h1>Error 500</h1><p>Page not found.</p>", status=500, content_type='text/html')

    async def handle_builder(self, request):
        """Handles the web interface for the playlist builder."""
        try:
            html_content = self._read_template('builder.html')
            return web.Response(text=html_content, content_type='text/html')
        except Exception as e:
            logger.error(f"❌ Critical error: unable to load 'builder.html': {e}")
            return web.Response(text="<h1>Error 500</h1><p>Unable to load builder interface.</p>", status=500, content_type='text/html')

    async def handle_info_page(self, request):
        """Serves the info HTML page."""
        try:
            html_content = self._read_template('info.html')
            return web.Response(text=html_content, content_type='text/html')
        except Exception as e:
            logger.error(f"❌ Critical error: unable to load 'info.html': {e}")
            return web.Response(text="<h1>Error 500</h1><p>Unable to load info page.</p>", status=500, content_type='text/html')

    async def handle_options(self, request):
        """Handles OPTIONS requests for CORS"""
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
            'Access-Control-Allow-Headers': 'Range, Content-Type',
            'Access-Control-Max-Age': '86400'
        }
        return web.Response(headers=headers)

    async def handle_api_info(self, request):
        """API endpoint that returns server information in JSON format."""
        info = {
            "proxy": "HLS Proxy Server",
            "version": "2.5.0",  # Updated for AES-128 support
            "status": "✅ Working",
            "features": [
                "✅ Proxy HLS streams",
                "✅ AES-128 key proxying",  # ✅ NEW
                "✅ Playlist building",
                "✅ Proxy support (SOCKS5, HTTP/S)",
                "✅ Multi-extractor support",
                "✅ CORS enabled"
            ],
            "extractors_loaded": list(self.extractors.keys()),
            "modules": {
                "playlist_builder": PlaylistBuilder is not None,
                "vavoo_extractor": VavooExtractor is not None,
                "dlhd_extractor": DLHDExtractor is not None,
                "vixsrc_extractor": VixSrcExtractor is not None,
                "sportsonline_extractor": SportsonlineExtractor is not None,
            },
            "proxy_config": {
                "global": f"{len(GLOBAL_PROXIES)} proxies loaded",
                "vavoo": f"{len(VAVOO_PROXIES)} proxies loaded",
                "dlhd": f"{len(DLHD_PROXIES)} proxies loaded",
            },
            "endpoints": {
                "/proxy/manifest.m3u8": "Main proxy - ?url=<URL>",
                "/key": "AES-128 keys proxy - ?key_url=<URL>",  # ✅ NEW
                "/playlist": "Playlist builder - ?url=<definitions>",
                "/builder": "Web interface for playlist builder",
                "/segment/{segment}": "Proxy for .ts segments - ?base_url=<URL>",
                "/info": "HTML page with server information",
                "/api/info": "JSON endpoint with server information"
            },
            "usage_examples": {
                "proxy": "/proxy/manifest.m3u8?url=https://example.com/stream.m3u8",
                "aes_key": "/key?key_url=https://server.com/key.bin",  # ✅ NEW
                "playlist": "/playlist?url=http://example.com/playlist1.m3u8;http://example.com/playlist2.m3u8",
                "custom_headers": "/proxy/manifest.m3u8?url=<URL>&h_Authorization=Bearer%20token"
            }
        }
        return web.json_response(info)

    async def cleanup(self):
        """Resource cleanup"""
        try:
            for extractor in self.extractors.values():
                if hasattr(extractor, 'close'):
                    await extractor.close()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

# --- Startup Logic ---
def create_app():
    """Creates and configures the aiohttp application."""
    proxy = HLSProxy()
    
    app = web.Application()
    
    # Register routes
    app.router.add_get('/', proxy.handle_root)
    app.router.add_get('/builder', proxy.handle_builder)
    app.router.add_get('/info', proxy.handle_info_page)
    app.router.add_get('/api/info', proxy.handle_api_info)
    app.router.add_get('/key', proxy.handle_key_request)
    app.router.add_get('/proxy/manifest.m3u8', proxy.handle_proxy_request)
    app.router.add_get('/playlist', proxy.handle_playlist_request)
    app.router.add_get('/segment/{segment}', proxy.handle_ts_segment)
    
    # Generic OPTIONS handler for CORS
    app.router.add_route('OPTIONS', '/{tail:.*}', proxy.handle_options)
    
    async def cleanup_handler(app):
        await proxy.cleanup()
    app.on_cleanup.append(cleanup_handler)
    
    return app

# Create the "private" instance of the aiohttp application.
app = create_app()

def main():
    """Main function to start the server."""
    print("🚀 Starting HLS Proxy Server...")
    print("📡 Server available at: http://localhost:7860")
    print("📡 Or: http://server-ip:7860")
    print("🔗 Endpoints:")
    print("   • / - Main page")
    print("   • /builder - Web interface for playlist builder")
    print("   • /info - Server information page")
    print("   • /proxy/manifest.m3u8?url=<URL> - Main proxy for streams")
    print("   • /playlist?url=<definitions> - Playlist generator")
    print("=" * 50)
    
    web.run_app(
        app, # Use the original aiohttp instance for the built-in runner
        host='0.0.0.0',
        port=7860
    )

if __name__ == '__main__':
    main()
