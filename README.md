# EasyProxy – Universal Server Proxy for HLS Streaming

> **A universal server proxy for HLS, M3U8, and IPTV**  
> Native support for Vavoo, DaddyLive HD, and all streaming services  
> Built‑in web UI and zero‑config

---

## Table of Contents  
- ✨ Main Features  
- 🚀 Quick Setup  
- ☁️ Cloud Deployment  
- 🖥️ Local Installation  
- ⚙️ Proxy Configuration  
- 🧭 Using the Proxy  
- 🔧 Configuration  
- 🏗️ Architecture  

---

## ✨ Main Features

| Feature | Description |
|--------|-------------|
| **Universal Proxy** | HLS, M3U8, MPD, DLHD streams, VIXSRC |
| **Specialized Extractors** | Vavoo, DLHD, Sportsonline, VixSrc |
| **Performance** | Async connections & keep‑alive |
| **Multi‑format** | Supports `#EXTVLCOPT` and `#EXTHTTP` |
| **Retry Logic** | Automatic retries built in |
| **Scalability** | Async server design |
| **Integrated Builder** | Combine M3U playlists into one |
| **Web Interface** | Full dashboard included |
| **Playlist Manager** | Automatic header management for playlists |

---

## 🚀 Quick Setup

### Docker (Recommended)
```bash
git clone https://github.com/nzo66/EasyProxy.git
cd EasyProxy
docker build -t EasyProxy .
docker run -d -p 7860:7860 --name EasyProxy EasyProxy
```

### Direct Python
```bash
git clone https://github.com/nzo66/EasyProxy.git
cd EasyProxy
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:7860 --workers 4 --worker-class aiohttp.worker.GunicornWebWorker app:app
```

Access the server at: `http://localhost:7860`

---

## ☁️ Cloud Deployment

### ▶︎ Render
1. In Render dashboard: **New → Web Service → Public Git Repository**  
2. Repository: `https://github.com/nzo66/EasyProxy`  
3. Build Command: `pip install -r requirements.txt`  
4. Start Command:  
   `gunicorn --bind 0.0.0.0:7860 --workers 4 --worker-class aiohttp.worker.GunicornWebWorker app:app`  
5. Deploy.

### HuggingFace Spaces
1. Create a **Space** using SDK: *Docker*  
2. Upload all repository files  
3. Auto‑deploy  
4. Done!

### Railway / Heroku
```bash
# Railway
railway login && railway init && railway up

# Heroku
heroku create EasyProxy && git push heroku main
```

### Cloud configuration (Optimized)
- Works without extra configuration  
- Suitable for: free platforms (HuggingFace, Render), small servers (512 MB–1 GB RAM)  
- Direct streaming, no cache required  
- Maximum compatibility with streaming services

---

## 🖥️ Local Installation

### Requirements
- Python 3.8+  
- aiohttp  
- gunicorn  

### Full Setup
```bash
git clone https://github.com/nzo66/EasyProxy.git
cd EasyProxy
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:7860 --workers 4 --worker-class aiohttp.worker.GunicornWebWorker app:app
```

### Termux (Android)
```bash
pkg update && pkg upgrade
pkg install python git -y
git clone https://github.com/nzo66/EasyProxy.git
cd EasyProxy
pip install -r requirements.txt
gunicorn --bind 0.0.0.0:7860 --workers 4 --worker-class aiohttp.worker.GunicornWebWorker app:app
```

### Advanced Docker
```bash
docker build -t EasyProxy .
docker run -d -p 7860:7860 --name EasyProxy EasyProxy
docker run -d -p 7860:7860 -v $(pwd)/logs:/app/logs --name EasyProxy EasyProxy
```

---

## ⚙️ Proxy Configuration

Create a `.env` file in the root (or rename `.env.example`) and configure variables.

**Example `.env`:**
```env
# Global proxy for all traffic
GLOBAL_PROXY=http://user:pass@myproxy.com:8080

# Multiple proxies for DLHD (random pick)
DLHD_PROXY=socks5://proxy1.com:1080,socks5://proxy2.com:1080

# Proxy specific to Vavoo
VAVOO_PROXY=socks5://vavoo-proxy.net:9050
```

Supported variables:
- `GLOBAL_PROXY`: fallback proxy for all requests  
- `VAVOO_PROXY`: proxy for Vavoo requests  
- `DLHD_PROXY`: proxy(s) for DaddyLiveHD  

---

## 🧭 Using the Proxy

Replace `<server>` with your server’s IP or domain.

### Main Web UI  
```
http://<server>:7860/
```

### Universal HLS Proxy
```
http://<server>:7860/proxy/manifest.m3u8?url=<ENCODED_STREAM_URL>
```

Supports:
- HLS (.m3u8) – live & VOD  
- M3U playlists – IPTV channel lists  
- MPD (DASH) – adaptive streaming  
- DLHD streams – dynamic streams  
- VIXSRC – VOD streaming  
- Sportsonline – sports streams  

**Examples:**
```bash
http://server:7860/proxy/manifest.m3u8?url=https://example.com/stream.m3u8
http://server:7860/playlist?url=https://iptv-provider.com/playlist.m3u
http://server:7860/proxy/manifest.m3u8?url=https://stream.com/video.m3u8&h_user-agent=VLC&h_referer=https://site.com
```

### Vavoo Auto‑Extraction
- Auto‑resolves `vavoo.to` links to direct streams  
- Automatic API authentication  
- Pre‑configured headers for streaming  

### DaddyLive HD Auto‑Resolution
- Resolves `DaddyLive HD` links  
- Bypass restrictions automatically  
- Optimised for stream quality  

### Sportsonline / Sportzonline Auto‑Resolution
- Resolves `sportsonline.*` & `sportzonline.*` links  
- Automatic iframe handling  
- Supports JavaScript decoding (P.A.C.K.E.R.)  

### Playlist Builder
```
http://<server>:7860/builder
```
Full interface for:
- Merging multiple playlists  
- Auto‑handling Vavoo & DLHD  
- Supporting `#EXTVLCOPT` and `#EXTHTTP`  
- Automatic proxying for all streams  
- Compatible with VLC, Kodi, IPTV players  

### Custom Headers
Append `h_` prefixed query vars for custom headers:
```
http://server:7860/proxy/manifest.m3u8?
  url=STREAM_URL
  &h_user-agent=CustomUA
  &h_referer=https://site.com
  &h_authorization=Bearer token123
```
Supported:
- `h_user-agent` – custom User‑Agent  
- `h_referer` – Referer header  
- `h_authorization` – Authorization token  
- `h_origin` – Origin header  
- `h_*` – any additional custom header  

---

## 🏗️ Architecture

### Processing Flow
1. Client sends stream request → universal proxy endpoint  
2. Service detection (Vavoo / DLHD / Generic)  
3. URL extraction (resolve real stream URL)  
4. Proxy stream forwarding with optimised headers  
5. Serve asset to client  

### ⚡ Async System
- Uses `aiohttp` — non‑blocking HTTP client  
- Connection pooling for reuse  
- Automatic retry logic for reliability  

### Authentication Handling
- Vavoo: automatic signature system  
- DaddyLive: specialised header treatment  
- Generic: standard Authorization support  

---

## 🧪 Practical Examples

### IPTV Player
```
http://your-server:7860/proxy/manifest.m3u8?url=STREAM_URL
```

### VLC
```bash
vlc "http://your-server:7860/proxy/manifest.m3u8?url=https://example.com/stream.m3u8"
```

### Kodi
```
http://your-server:7860/proxy/manifest.m3u8?url=PLAYLIST_URL
```

### Browser
```
http://your-server:7860/proxy/manifest.m3u8?url=https://stream.example.com/live.m3u8
```

---

## 🐳 Docker Management
```bash
# View logs
docker logs -f EasyProxy

# Restart container
docker restart EasyProxy

# Stop and start
docker stop EasyProxy
docker start EasyProxy

# Remove container
docker rm -f EasyProxy
```

---

## 📈 Performance

### Typical Benchmarks
| Metric       | Value        | Description                    |
|--------------|--------------|-------------------------------|
| Latency      | < 50 ms       | Minimal proxy overhead         |
| Throughput   | Unlimited     | Limited only by your bandwidth |
| Connections  | 1000+         | High concurrent connection support |
| Memory       | 50–200 MB     | Typical usage under load       |

### ⚡ Optimizations
- Connection pooling for HTTP requests  
- Async I/O for non‑blocking operations  
- Keep‑Alive persistent connections  
- DNS caching for faster lookups  

---

## 🤝 Contributing

1. Fork the repository  
2. Create a feature branch: `git checkout -b feature/AmazingFeature`  
3. Commit your changes: `git commit -m 'Add some AmazingFeature'`  
4. Push branch: `git push origin feature/AmazingFeature`  
5. Open a Pull Request.

### Bug Reports
Please include:
- Proxy version  
- Operating system  
- Test URL causing issue  
- Full error logs  

### Feature Requests
Please include:
- Desired functionality  
- Specific use‑case  
- Priority (low/medium/high)  

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for details.

---

**⭐ If this project helps you, give it a star! ⭐**  
> **Enjoy your streaming!**  
> Access your favourite content anywhere, without restrictions, with full control and optimised performance.
