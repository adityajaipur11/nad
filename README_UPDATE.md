# Destro — Threat Intelligence Dashboard

**Modern, Professional UI Redesign**

## What's New ✨

### 🎨 Design Improvements
- **Professional Minimal Theme** — Blue/gray color scheme with transparent glassmorphism effects
- **Real Icons** — Font Awesome 6.4 icons throughout (no emojis)
- **Responsive Layout** — Works perfectly on mobile, tablet, and desktop
- **Dark Mode Support** — Toggle in top-right corner
- **Smooth Animations** — Hover effects, transitions, and loading states
- **Modern Components** — Badges, cards, modals, and alerts

### 📄 New Pages

#### 1. **Dashboard** (`/dashboard`)
- Live threat statistics
- Recent activity monitoring
- File upload for threat analysis
- Quick-start scan button
- Summary of latest threats

#### 2. **Threats & Incidents** (`/threats`)
- Complete threat list with filters
- Severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Search and filter capabilities
- Threat status management (acknowledge, dismiss, reopen)
- Export threats as CSV
- Real-time updates

#### 3. **AI Agents** (`/agents`)
- Monitor all threat detection agents
- Real-time agent status (Active/Idle/Warning)
- Risk scores for each agent
- Task completion tracking
- Individual agent updates and refresh controls

#### 4. **Reports & Analytics** (`/reports`)
- Executive summary generation
- Severity distribution charts
- Threat category breakdown
- Historical statistics
- Download reports as TXT

#### 5. **Settings** (`/settings`)
- API key configuration
- Preferences (auto-refresh interval, theme)
- Attack mode toggle
- Usage statistics
- System preferences

### 🎯 Enhanced Features

✅ **Interactive Buttons** — All buttons have proper icons and hover states
✅ **Real-time Updates** — Dashboard auto-refreshes every 3-5 seconds
✅ **Modal Dialogs** — File upload modal with validation
✅ **Data Export** — Export threats to CSV
✅ **Status Management** — Acknowledge, dismiss, or reopen threats
✅ **Error Handling** — User-friendly error messages and alerts
✅ **Loading States** — Visual feedback for async operations
✅ **Empty States** — Helpful messages when no data available

## File Structure

```
project/
├── app.py                          # Updated Flask app with new routes
├── templates/
│   ├── base.html                   # Base template with navigation
│   ├── dashboard.html              # Dashboard page
│   ├── threats.html                # Threats/incidents page
│   ├── agents.html                 # Agents monitoring page
│   ├── settings.html               # Settings page
│   └── reports.html                # Reports/analytics page
├── attack_detector/                # (Existing modules)
├── attack_state/
├── threat_analyzer/
├── web_scraper/
├── summarizing_agent/
├── .env                            # Configuration (keep your API keys)
└── README_UPDATE.md                # This file
```

## Installation

### 1. Copy the Updated Files
Copy the entire `project/` folder to your local environment:
```bash
# Replace your old project folder with this one
cp -r destro-updated/* /path/to/your/project/
```

### 2. Install Dependencies (if needed)
```bash
pip install -r requirements.txt
```

### 3. Configure API Key
Edit `.env` and add your OpenRouter API key:
```env
OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

### 4. Run the Application
```bash
python app.py
```

The dashboard will automatically open at: `http://127.0.0.1:5000/dashboard`

## Color Scheme

Professional blue & gray palette:
- **Primary**: #3b82f6 (Bright Blue)
- **Success**: #10b981 (Green)
- **Warning**: #f59e0b (Amber)
- **Error**: #ef4444 (Red)
- **Info**: #06b6d4 (Cyan)

## Navigation

The sidebar provides quick access to:
- 📊 **Dashboard** — Main overview
- ⚠️ **Threats** — Incident management
- 🤖 **Agents** — Agent monitoring
- 📄 **Reports** — Analytics & export
- ⚙️ **Settings** — Configuration

## Key Features

### Smart Filtering
- Filter threats by severity
- Search across all threat data
- Real-time list updates

### Interactive Components
- Upload files for analysis
- Manage threat statuses
- Start/refresh scans
- Configure preferences
- Toggle attack mode

### Real-time Updates
All pages auto-refresh data every few seconds:
- Dashboard: 3 seconds
- Threats: 5 seconds
- Agents: 4 seconds
- Reports: 5 seconds

## API Endpoints (Unchanged)

All existing API endpoints work the same:
- `GET /api/status` — System status
- `GET /api/threats` — Threat list
- `GET /api/agents` — Agent list
- `POST /api/scan` — Start scan
- `POST /api/upload` — Upload file
- `POST /api/threat-action` — Update threat status
- `POST /api/set-key` — Configure API key
- `POST /api/test-key` — Test API connectivity

## Browser Support

✅ Chrome/Edge 90+
✅ Firefox 88+
✅ Safari 14+
✅ Mobile browsers (iOS Safari, Chrome Mobile)

## Customization

### Change Colors
Edit the CSS variables in `templates/base.html`:
```css
:root {
  --primary: #3b82f6;
  --success: #10b981;
  /* ... customize as needed */
}
```

### Change Refresh Interval
In Settings page, adjust auto-refresh timing or modify in JavaScript:
```javascript
setInterval(loadStats, 3000); // 3 seconds
```

## Troubleshooting

**No data showing?**
- Ensure API key is configured in Settings
- Run a scan from Dashboard
- Check browser console for errors

**Buttons not responding?**
- Clear browser cache
- Check network tab in DevTools
- Verify Flask app is running

**Theme not saving?**
- Check localStorage in browser (DevTools > Application)
- Browser may have disabled localStorage

## Support

For issues or feature requests, check:
- Browser console for JavaScript errors
- Flask server logs
- Network tab in browser DevTools

---

**Built with ❤️ using Flask, Chart.js, and Font Awesome**
