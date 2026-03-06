# 🎬 MediaVault — Professional File Hosting

A self-hosted, professional media & file hosting platform.
Upload videos, audio, images, archives — get direct streaming URLs.

---

## ⚡ Quick Start

### 1. Install Python Dependencies
```bash
pip install flask werkzeug
# or
pip install -r requirements.txt
```

### 2. Run the Server
```bash
python app.py
```

### 3. Open in Browser
- Local:   http://localhost:5000
- Network: http://YOUR-IP:5000  (shown in terminal on start)

---

## 🚀 Features (15+)

| # | Feature | Description |
|---|---------|-------------|
| 1 | **File Upload** | Drag & drop, multi-file, progress bar |
| 2 | **Video Streaming** | HTTP Range requests — smooth playback |
| 3 | **Direct Raw URL** | `/raw/<id>` — embeds directly in players/apps |
| 4 | **Image Preview** | Full-size viewer in browser |
| 5 | **Audio Player** | HTML5 audio with controls |
| 6 | **Archive Inspector** | View ZIP/TAR contents without extracting |
| 7 | **Force Download** | `/download/<id>` forces browser download |
| 8 | **Delete Files** | Single or bulk delete |
| 9 | **Rename Files** | Modal rename with extension preservation |
| 10 | **Tags & Description** | Organize and annotate files |
| 11 | **Search** | Live client-side + URL-based search |
| 12 | **Dashboard** | Stats, file type breakdown, activity chart |
| 13 | **REST API** | JSON API for all files and individual files |
| 14 | **QR Code** | QR code generator for any file URL |
| 15 | **Network Share** | LAN URL shown — share with phone on same WiFi |
| 16 | **Embed Codes** | HTML embed code for video files |
| 17 | **Sort & Filter** | By type, date, size, name |
| 18 | **Bulk Delete** | Select multiple files and delete at once |

---

## 📡 Direct URLs

After uploading, each file gets:

| URL | Use |
|-----|-----|
| `http://IP:5000/raw/<id>` | **Direct stream** — paste in video player, VLC, wget |
| `http://IP:5000/file/<id>` | View page with player |
| `http://IP:5000/download/<id>` | Force download |

### Example — play in VLC:
```
vlc http://localhost:5000/raw/abc123def456
```

### Example — embed in HTML:
```html
<video controls>
  <source src="http://YOUR-IP:5000/raw/abc123def456" type="video/mp4">
</video>
```

---

## 🌐 API

### List all files
```
GET /api/files
```

### Get file info
```
GET /api/file/<id>
```

### Upload via API (curl)
```bash
curl -X POST http://localhost:5000/api/upload \
  -F "file=@/path/to/video.mp4"
```

Response:
```json
{
  "success": true,
  "id": "abc123def456",
  "raw_url": "http://localhost:5000/raw/abc123def456",
  "view_url": "http://localhost:5000/file/abc123def456",
  "download_url": "http://localhost:5000/download/abc123def456",
  "name": "video.mp4",
  "size": "42.3 MB",
  "type": "video"
}
```

---

## 📁 Project Structure

```
mediahost/
├── app.py              ← Main Flask server
├── requirements.txt    ← Python deps
├── metadata.json       ← Auto-created file database
├── uploads/            ← Auto-created uploads folder
└── templates/
    ├── base.html       ← Base layout
    ├── index.html      ← Homepage + gallery
    ├── file.html       ← File view/player page
    ├── dashboard.html  ← Stats dashboard
    ├── qr.html         ← QR code generator
    └── 404.html        ← Error page
```

---

## 🔧 Configuration

In `app.py`, you can change:
- `PORT`: Default is 5000 → change in `app.run(port=5000)`
- `MAX_CONTENT_LENGTH`: Default 10GB
- `UPLOAD_FOLDER`: Where files are stored

---

## 🌍 Hosting on a Server

To host publicly (e.g., on a VPS):

```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Or with nginx proxy + gunicorn for production
```

For HTTPS and domain, use nginx as a reverse proxy.
