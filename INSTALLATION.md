# Destro — Installation Guide

## What You're Getting

A completely redesigned threat intelligence dashboard with:
- ✨ Professional minimal UI with blue/gray theme
- 📄 5 new dedicated pages (Dashboard, Threats, Agents, Settings, Reports)
- 🎨 Real icons (Font Awesome), transparent backgrounds, smooth animations
- 📱 Fully responsive design for mobile/tablet/desktop
- 🌙 Dark mode support
- ⚡ Interactive buttons with proper hover states
- 📊 Real-time data updates
- 📥 File upload, data export, and reporting

## Quick Start (3 Steps)

### 1. Download & Extract
```bash
unzip destro-updated.zip
cd project
```

### 2. Configure API Key
Edit `.env` and add your OpenRouter API key:
```env
OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

### 3. Run
```bash
python app.py
```

Opens automatically at: **http://127.0.0.1:5000/dashboard**

---

## File Structure

```
project/
├── app.py                   # Updated Flask app
├── templates/
│   ├── base.html           # Navigation & shared layout
│   ├── dashboard.html      # Main overview
│   ├── threats.html        # Threat management
│   ├── agents.html         # Agent monitoring
│   ├── settings.html       # Configuration
│   └── reports.html        # Analytics
├── .env                    # Configuration
└── README_UPDATE.md        # Full docs
```

---

## Navigation

| Page | URL | Purpose |
|------|-----|---------|
| 📊 Dashboard | `/dashboard` | Overview & quick actions |
| ⚠️ Threats | `/threats` | Manage incidents |
| 🤖 Agents | `/agents` | Monitor agents |
| 📄 Reports | `/reports` | Analytics & export |
| ⚙️ Settings | `/settings` | Configuration |

---

## Features

✅ Professional blue/gray theme
✅ Real Font Awesome icons
✅ Glassmorphism design (transparent backgrounds)
✅ Responsive mobile-friendly layout
✅ Dark mode support
✅ Real-time data updates
✅ Interactive modals & buttons
✅ File upload & export
✅ Search & filtering
✅ Status management

---

## Browser Support

Chrome 90+ | Firefox 88+ | Safari 14+ | Mobile ✅

---

## Setup API Key

1. Get key from: https://openrouter.ai
2. Edit `.env` and paste your key
3. Or use Settings page in dashboard

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Port 5000 taken | Change port in app.py line 589 |
| No data | Configure API key in Settings |
| Buttons stuck | Clear cache (Ctrl+Shift+Del) |
| Theme not saving | Enable localStorage |

---

## Customize

Change colors in `templates/base.html`:
```css
--primary: #3b82f6;
--success: #10b981;
--warning: #f59e0b;
--error: #ef4444;
```

---

**See README_UPDATE.md for full documentation**
