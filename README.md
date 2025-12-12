# Minecraft Server Status Monitor

Advanced Minecraft Server Status Monitor with Discord Bot Integration, Real-time Dashboard, and Analytics.

## Features

- 📊 Real-time server status monitoring
- 🤖 Discord bot with slash commands
- 🌐 Web dashboard with EJS templates
- 📈 Performance analytics and history
- 🔒 Security features (Helmet, CORS, Rate Limiting)
- 💾 Intelligent caching system
- 📱 Responsive design
- 🔄 Automatic monitoring with configurable intervals
- 📊 Multiple API endpoint support (mcsrvstat.us, mcstatus.io)

## Prerequisites

- Node.js 16.x or higher
- npm 7.x or higher
- Discord Bot Token
- Discord Application Client ID

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/minecraft-server-status-monitor.git
cd minecraft-server-status-monitor

Install dependencies:

bash
npm install
Configure environment variables:

bash
cp .env.example .env
# Edit .env file with your configuration
Start the application:

bash
# Development
npm run dev

# Production
npm start
