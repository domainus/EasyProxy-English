import asyncio
import logging
import re
import json
from urllib.parse import urlparse
from typing import Dict, Any
import random
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp_proxy import ProxyConnector

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    """Custom exception for extraction errors."""
    pass

class VixSrcExtractor:
    """VixSrc URL extractor to resolve VixSrc links."""
    
    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "accept-encoding": "gzip, deflate",
            "connection": "keep-alive",
        }
        self.session = None
        self.mediaflow_endpoint = "hls_manifest_proxy"
        self._session_lock = asyncio.Lock()
        self.proxies = proxies or []
        self.is_vixsrc = True # Flag to identify this extractor

    def _get_random_proxy(self):
        """Returns a random proxy from the list."""
        return random.choice(self.proxies) if self.proxies else None

    async def _get_session(self):
        """Gets a persistent HTTP session."""
        if self.session is None or self.session.closed:
            timeout = ClientTimeout(total=60, connect=30, sock_read=30)
            proxy = self._get_random_proxy()
            if proxy:
                logger.info(f"Using proxy {proxy} for the VixSrc session.")
                connector = ProxyConnector.from_url(proxy)
            else:
                connector = TCPConnector(
                    limit=10,
                    limit_per_host=3,
                    keepalive_timeout=30,
                    enable_cleanup_closed=True,
                    force_close=False,
                    use_dns_cache=True
                )
            self.session = ClientSession(
                timeout=timeout,
                connector=connector,
                headers=self.base_headers,
                cookie_jar=aiohttp.CookieJar()
            )
        return self.session

    async def _make_robust_request(self, url: str, headers: dict = None, retries=3, initial_delay=2):
        """Performs robust HTTP requests with automatic retry."""
        final_headers = headers or {}
        
        for attempt in range(retries):
            try:
                session = await self._get_session()
                logger.info(f"Attempt {attempt + 1}/{retries} for URL: {url}")
                
                async with session.get(url, headers=final_headers) as response:
                    response.raise_for_status()
                    content = await response.text()
                    
                    class MockResponse:
                        def __init__(self, text_content, status, headers_dict, url):
                            self._text = text_content
                            self.status = status
                            self.headers = headers_dict
                            self.url = url
                            self.status_code = status
                            self.text = text_content
                        
                        async def text_async(self):
                            return self._text
                        
                        def raise_for_status(self):
                            if self.status >= 400:
                                raise aiohttp.ClientResponseError(
                                    request_info=None,
                                    history=None,
                                    status=self.status
                                )
                    
                    logger.info(f"✅ Request succeeded for {url} on attempt {attempt + 1}")
                    return MockResponse(content, response.status, response.headers, response.url)
                    
            except (
                aiohttp.ClientConnectionError,
                aiohttp.ServerDisconnectedError,
                aiohttp.ClientPayloadError,
                asyncio.TimeoutError,
                OSError,
                ConnectionResetError
            ) as e:
                logger.warning(f"⚠️ Connection error attempt {attempt + 1} for {url}: {str(e)}")
                
                if attempt == retries - 1:
                    if self.session and not self.session.closed:
                        try:
                            await self.session.close()
                        except:
                            pass
                        self.session = None
                
                if attempt < retries - 1:
                    delay = initial_delay * (2 ** attempt)
                    logger.info(f"⏳ Waiting {delay} seconds before the next attempt...")
                    await asyncio.sleep(delay)
                else:
                    raise ExtractorError(f"All {retries} attempts failed for {url}: {str(e)}")
                    
            except Exception as e:
                logger.error(f"❌ Non-network error attempt {attempt + 1} for {url}: {str(e)}")
                if attempt == retries - 1:
                    raise ExtractorError(f"Error final for {url}: {str(e)}")
                await asyncio.sleep(initial_delay)

    async def _parse_html_simple(self, html_content: str, tag: str, attrs: dict = None):
        """Simple HTML parser without BeautifulSoup."""
        try:
            if tag == "div" and attrs and attrs.get("id") == "app":
                # Searches for div with id="app"
                pattern = r'<div[^>]*id="app"[^>]*data-page="([^"]*)"[^>]*>'
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    return {"data-page": match.group(1)}
                    
            elif tag == "iframe":
                # Searches for iframe src
                pattern = r'<iframe[^>]*src="([^"]*)"[^>]*>'
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    return {"src": match.group(1)}
                    
            elif tag == "script":
                # Searches for the first script tag in the body
                pattern = r'<body[^>]*>.*?<script[^>]*>(.*?)</script>'
                match = re.search(pattern, html_content, re.DOTALL | re.IGNORECASE)
                if match:
                    return match.group(1)
                    
        except Exception as e:
            logger.error(f"HTML parsing error: {e}")
            
        return None

    async def version(self, site_url: str) -> str:
        """Gets the version of the parent VixSrc site."""
        base_url = f"{site_url}/request-a-title"
        
        response = await self._make_robust_request(
            base_url,
            headers={
                "Referer": f"{site_url}/",
                "Origin": f"{site_url}",
            },
        )
        
        if response.status_code != 200:
            raise ExtractorError("Outdated URL")
        
        # Simple HTML parser
        app_div = await self._parse_html_simple(response.text, "div", {"id": "app"})
        if app_div and app_div.get("data-page"):
            try:
                # Decode HTML entities if necessary
                data_page = app_div["data-page"].replace("&quot;", '"')
                data = json.loads(data_page)
                return data["version"]
            except (KeyError, json.JSONDecodeError, AttributeError) as e:
                raise ExtractorError(f"Failed to parse version: {e}")
        else:
            raise ExtractorError("Unable to find version data")

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        """Extracts VixSrc URL."""
        try:
            version = None
            response = None
            
            # ✅ NEW: Handling for playlist URLs that do not require extraction.
            # If the URL is already a manifest, it returns it directly.
            if "vixsrc.to/playlist" in url:
                logger.info("URL is already a VixSrc manifest, extraction not required.")
                return {
                    "destination_url": url,
                    "request_headers": self.base_headers,
                    "mediaflow_endpoint": self.mediaflow_endpoint,
                }

            if "iframe" in url:
                # Handle iframe URLs
                site_url = url.split("/iframe")[0]
                version = await self.version(site_url)
                
                # First request with Inertia headers
                response = await self._make_robust_request(
                    url, 
                    headers={
                        "x-inertia": "true", 
                        "x-inertia-version": version,
                        **self.base_headers
                    }
                )
                
                # Search for iframe src
                iframe_data = await self._parse_html_simple(response.text, "iframe")
                if iframe_data and iframe_data.get("src"):
                    iframe_url = iframe_data["src"]
                    
                    # Second request to the iframe
                    response = await self._make_robust_request(
                        iframe_url, 
                        headers={
                            "x-inertia": "true", 
                            "x-inertia-version": version,
                            **self.base_headers
                        }
                    )
                else:
                    raise ExtractorError("No iframe found in the response")
                    
            elif "movie" in url or "tv" in url:
                # Handle direct movie/tv URLs
                response = await self._make_robust_request(url)
            else:
                raise ExtractorError("Unsupported VixSrc URL type")
            
            if response.status_code != 200:
                raise ExtractorError("Failed to extract URL components, invalid request")
            
            # Extract script from the body
            script_content = await self._parse_html_simple(response.text, "script")
            if not script_content:
                raise ExtractorError("No script found in the body")
            
            # Extract parameters from JavaScript script
            try:
                token_match = re.search(r"'token':\s*'(\w+)'", script_content)
                expires_match = re.search(r"'expires':\s*'(\d+)'", script_content)
                server_url_match = re.search(r"url:\s*'([^']+)'", script_content)
                
                if not all([token_match, expires_match, server_url_match]):
                    raise ExtractorError("Missing parameters in JS script")
                
                token = token_match.group(1)
                expires = expires_match.group(1)
                server_url = server_url_match.group(1)
                
                # Build the final URL
                if "?b=1" in server_url:
                    final_url = f'{server_url}&token={token}&expires={expires}'
                else:
                    final_url = f"{server_url}?token={token}&expires={expires}"
                
                # Check for FHD support
                if "window.canPlayFHD = true" in script_content:
                    final_url += "&h=1"
                
                # Prepare final headers
                stream_headers = self.base_headers.copy()
                stream_headers["referer"] = url
                
                logger.info(f"✅ VixSrc URL successfully extracted: {final_url}")
                
                return {
                    "destination_url": final_url,
                    "request_headers": stream_headers,
                    "mediaflow_endpoint": self.mediaflow_endpoint,
                }
                
            except Exception as e:
                raise ExtractorError(f"Error parsing JavaScript script: {e}")
                
        except Exception as e:
            logger.error(f"❌ VixSrc extraction failed: {str(e)}")
            raise ExtractorError(f"VixSrc extraction completely failed: {str(e)}")

    async def close(self):
        """Permanently closes the session."""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
            except:
                pass
            self.session = None