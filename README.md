# 🚨 Frigate Signal — Incident Console

A local-first incident correlation, visualization, and AI analysis console for Frigate NVR events.

## ✨ Features
- 🔗 Event correlation across cameras
- 🧠 AI-powered incident summaries
- 👁 Visual validation of subjects
- 🎬 Automatic MP4 incident video generation
- 🧭 Timeline UI with adjustable density

---

## 🚀 Quick Start

### Run locally
```bash
python app.py
```

Then open:
http://localhost:5001

---

### 🐳 Docker
```bash
docker build -t frigate-signal .
docker run -p 5001:5001 --env-file .env frigate-signal
```

---

## ⚙️ Configuration

Create a `.env` file with:

- MQTT settings
- Frigate base URL
- LLM endpoint
- Video generation settings

---

## 🔌 API

- `/api/incidents`
- `/api/events`
- `/api/health`

---

## 🛠 Notes

- Requires **FFmpeg installed**
- Works with **OpenAI-compatible APIs** (OpenClaw, OpenRouter)

---

## 📈 Next Steps

- Add screenshots / GIF preview
- Add docker-compose support
- Add alerting integrations

