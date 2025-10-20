import asyncio
import logging
import json
import urllib.parse
from aiohttp import ClientSession, ClientTimeout
from typing import Iterator, List, Dict

logger = logging.getLogger(__name__)

class PlaylistBuilder:
    """Builder for M3U playlist with support for multiple sources"""
    
    def __init__(self):
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    def rewrite_m3u_links_streaming(self, m3u_lines_iterator: Iterator[str], base_url: str) -> Iterator[str]:
        current_ext_headers: Dict[str, str] = {}
        
        for line_with_newline in m3u_lines_iterator:
            line_content = line_with_newline.rstrip('\n')
            logical_line = line_content.strip()
            
            is_header_tag = False
            if logical_line.startswith('#EXTVLCOPT:'):
                is_header_tag = True
                try:
                    option_str = logical_line.split(':', 1)[1]
                    if '=' in option_str:
                        key_vlc, value_vlc = option_str.split('=', 1)
                        key_vlc = key_vlc.strip()
                        value_vlc = value_vlc.strip()
                        if key_vlc == 'http-header' and ':' in value_vlc:
                            header_key, header_value = value_vlc.split(':', 1)
                            header_key = header_key.strip()
                            header_value = header_value.strip()
                            current_ext_headers[header_key] = header_value
                        elif key_vlc.startswith('http-'):
                            header_key = '-'.join(word.capitalize() for word in key_vlc[len('http-'):].split('-'))
                            current_ext_headers[header_key] = value_vlc
                except Exception as e:
                    logger.error(f"⚠️ Error parsing #EXTVLCOPT '{logical_line}': {e}")
            
            elif logical_line.startswith('#EXTHTTP:'):
                is_header_tag = True
                try:
                    json_str = logical_line.split(':', 1)[1]
                    current_ext_headers = json.loads(json_str)
                except Exception as e:
                    logger.error(f"⚠️ Error parsing #EXTHTTP '{logical_line}': {e}")
                    current_ext_headers = {}
            
            if is_header_tag:
                yield line_with_newline
                continue
            
            if logical_line and not logical_line.startswith('#') and \
               ('http://' in logical_line or 'https://' in logical_line):
                
                processed_url_content = logical_line
                
                if 'pluto.tv' in logical_line:
                    processed_url_content = logical_line
                elif 'vavoo.to' in logical_line:
                    encoded_url = urllib.parse.quote(logical_line, safe='')
                    processed_url_content = f"{base_url}/proxy/manifest.m3u8?url={encoded_url}"
                elif '.m3u8' in logical_line:
                    encoded_url = urllib.parse.quote(logical_line, safe='')
                    processed_url_content = f"{base_url}/proxy/manifest.m3u8?url={encoded_url}"
                elif '.mpd' in logical_line:
                    encoded_url = urllib.parse.quote(logical_line, safe='')
                    processed_url_content = f"{base_url}/proxy/manifest.m3u8?url={encoded_url}"
                elif '.php' in logical_line:
                    encoded_url = urllib.parse.quote(logical_line, safe='')
                    processed_url_content = f"{base_url}/proxy/manifest.m3u8?url={encoded_url}"
                else:
                    encoded_url = urllib.parse.quote(logical_line, safe='')
                    processed_url_content = f"{base_url}/proxy/manifest.m3u8?url={encoded_url}"
                
                if current_ext_headers:
                    header_params_str = "".join([f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}" for key, value in current_ext_headers.items()])
                    processed_url_content += header_params_str
                    current_ext_headers = {}
                
                yield processed_url_content + '\n'
            else:
                yield line_with_newline

    async def async_download_m3u_playlist(self, url: str) -> List[str]:
        headers = {
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        lines = []
        try:
            timeout = ClientTimeout(total=30, connect=10)
            async with ClientSession(timeout=timeout) as client:
                async with client.get(url, headers=headers) as response:
                    response.raise_for_status()
                    content = await response.text()
                    lines = [line + '\n' if line else '' for line in content.split('\n')]
        except Exception as e:
            logger.error(f"Error downloading playlist (async): {str(e)}")
            raise
        return lines

    async def async_generate_combined_playlist(self, playlist_definitions: List[str], base_url: str):
        playlist_urls = []
        for definition in playlist_definitions:
            if '&' in definition:
                parts = definition.split('&', 1)
                playlist_url_str = parts[1] if len(parts) > 1 else parts[0]
            else:
                playlist_url_str = definition
            playlist_urls.append(playlist_url_str)
        
        results = await asyncio.gather(*[self.async_download_m3u_playlist(url) for url in playlist_urls], return_exceptions=True)
        
        first_playlist_header_handled = False
        for idx, lines in enumerate(results):
            if isinstance(lines, Exception):
                yield f"# ERROR processing playlist {playlist_urls[idx]}: {str(lines)}\n"
                continue
            
            playlist_lines: List[str] = lines
            first_line_of_this_segment = True
            
            rewritten_lines_iter = self.rewrite_m3u_links_streaming(iter(playlist_lines), base_url)
            for line in rewritten_lines_iter:
                is_extm3u_line = line.strip().startswith('#EXTM3U')
                
                if not first_playlist_header_handled:
                    yield line
                    if is_extm3u_line:
                        first_playlist_header_handled = True
                else:
                    if first_line_of_this_segment and is_extm3u_line:
                        pass
                    else:
                        yield line
                first_line_of_this_segment = False
