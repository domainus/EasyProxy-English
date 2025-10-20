# EasyProxy – Universal Server Proxy for HLS Streaming

> **A universal server proxy for HLS, M3U8, and IPTV**  
> Native support for Vavoo, DaddyLive HD, and all streaming services  
> Built-in web UI and zero-config

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
| **Performance** | Async connections & keep-alive |
| **Multi-format** | Supports `#EXTVLCOPT` and `#EXTHTTP` |
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