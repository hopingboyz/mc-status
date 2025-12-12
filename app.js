import express from 'express';
import axios from 'axios';
import { 
    Client, 
    IntentsBitField, 
    EmbedBuilder, 
    SlashCommandBuilder, 
    REST, 
    Routes, 
    ActionRowBuilder, 
    ButtonBuilder, 
    ButtonStyle,
    ActivityType,
    MessageFlags
} from 'discord.js';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import morgan from 'morgan';
import winston from 'winston';
import NodeCache from 'node-cache';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced logging configuration
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log',
            maxsize: 5242880,
            maxFiles: 5
        }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.printf(({ timestamp, level, message, stack }) => {
                    return `${timestamp} ${level}: ${message}${stack ? `\n${stack}` : ''}`;
                })
            )
        })
    ]
});

// Create logs directory if it doesn't exist
import fs from 'fs';
import { promisify } from 'util';
import { readFile, writeFile } from 'fs/promises';
const fsExists = promisify(fs.exists);
const fsMkdir = promisify(fs.mkdir);

if (!fs.existsSync('logs')) {
    fs.mkdirSync('logs', { recursive: true });
}

// Environment validation
const REQUIRED_ENV = ['DISCORD_TOKEN', 'DISCORD_CLIENT_ID'];
const missingEnv = REQUIRED_ENV.filter(env => !process.env[env]);
if (missingEnv.length > 0) {
    logger.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
    process.exit(1);
}

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            connectSrc: ["'self'", "https://api.mcsrvstat.us", "https://api.mcstatus.io"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.use(compression());
app.use(cors());
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public'), { maxAge: '1h' }));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', join(__dirname, 'views'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 100, // 15 minutes
    max: 10000000000000, // Limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests from this IP, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/', limiter);
app.use('/', limiter);

// Default icon URL with proper format
const DEFAULT_ICON = 'https://static.wikia.nocookie.net/minecraft_gamepedia/images/5/51/Server-icon.png/revision/latest?cb=20180803191309';

// Helper function to validate and clean URLs
function validateIconUrl(url) {
    if (!url || typeof url !== 'string') {
        return DEFAULT_ICON;
    }
    
    // Remove any control characters or spaces
    url = url.trim();
    
    // Check if it's a valid URL
    try {
        const urlObj = new URL(url);
        // Ensure it's HTTP/HTTPS
        if (!['http:', 'https:'].includes(urlObj.protocol)) {
            return DEFAULT_ICON;
        }
        
        // Clean up common issues
        url = url.replace(/\s+/g, '');
        
        // Check if it looks like a valid image URL (basic check)
        if (!url.match(/\.(png|jpg|jpeg|gif|webp)(\?.*)?$/i) && !url.includes('data:image')) {
            return DEFAULT_ICON;
        }
        
        return url;
    } catch {
        return DEFAULT_ICON;
    }
}

// Helper function to safely set thumbnail
function setEmbedThumbnail(embed, url) {
    try {
        const validatedUrl = validateIconUrl(url);
        embed.setThumbnail(validatedUrl);
        return true;
    } catch (error) {
        logger.warn(`Failed to set thumbnail with URL: ${url}. Using default. Error:`, error.message);
        try {
            embed.setThumbnail(DEFAULT_ICON);
            return true;
        } catch (fallbackError) {
            logger.error('Failed to set default thumbnail:', fallbackError);
            return false;
        }
    }
}

// Configuration with validation
const parseHosts = () => {
    try {
        const hosts = JSON.parse(process.env.SERVER_HOSTS || '[{"ip":"play.unixnodes.xyz","port":"19136"}]');
        return hosts.map(host => ({
            ip: String(host.ip || 'play.unixnodes.xyz'),
            port: String(host.port || '19136')
        }));
    } catch (error) {
        logger.error('Error parsing SERVER_HOSTS:', error);
        return [{ ip: 'play.unixnodes.xyz', port: '19136' }];
    }
};

const SERVER_CONFIG = {
    name: process.env.SERVER_NAME || "UnixMc",
    version: process.env.SERVER_VERSION || "1.8+",
    description: process.env.SERVER_DESCRIPTION || "A Best Survival Server",
    serverType: (process.env.SERVER_TYPE || "Java").toLowerCase(),
    hosts: parseHosts(),
    website: process.env.SERVER_WEBSITE || "https://unixnodes.xyz",
    discord: process.env.DISCORD_INVITE || "https://discord.gg/gXA6r99Fky",
    location: process.env.SERVER_LOCATION || "India",
    region: process.env.SERVER_REGION || "Asia/Kolkata",
    owner: process.env.SERVER_OWNER || "UnixMc Team",
    started: process.env.SERVER_STARTED || "2025-12-09",
    features: ["Survival", "Economy", "Quests", "Custom Items", "Friendly Community"],
    gamemodes: ["Survival" ],
    social: {
        discord: process.env.DISCORD_INVITE || "https://discord.gg/gXA6r99Fky",
        website: process.env.SERVER_WEBSITE || "https://unixnodes.xyz",
        twitter: process.env.TWITTER_URL || "",
        youtube: process.env.YOUTUBE_URL || "https://www.youtube.com/@hopingboyz",
        telegram: process.env.TELEGRAM_URL || "",
        instagram: process.env.INSTAGRAM_URL || "https://www.instagram.com/hopingboyz/",
        vote: process.env.VOTE_URL || ""
    }
};

// Validate server type
if (!['java', 'bedrock'].includes(SERVER_CONFIG.serverType)) {
    logger.warn(`Invalid server type: ${SERVER_CONFIG.serverType}, defaulting to java`);
    SERVER_CONFIG.serverType = 'java';
}

// Enhanced cache system
const cache = new NodeCache({
    stdTTL: 15, // 15 seconds default
    checkperiod: 10,
    useClones: false,
    deleteOnExpire: true
});

// Performance and analytics
const analytics = {
    requests: {
        total: 0,
        success: 0,
        failed: 0,
        byEndpoint: {}
    },
    uptime: {
        startTime: Date.now(),
        lastDowntime: null,
        downtimeHistory: []
    },
    performance: {
        averageResponseTime: 0,
        peakPlayers: 0,
        averageTPS: 20,
        lowTPSEvents: 0,
        memoryUsage: []
    },
    discord: {
        commandsUsed: 0,
        interactions: 0,
        lastCommand: null
    }
};

// API endpoint configurations
const API_ENDPOINTS = {
    java: [
        {
            name: 'mcsrvstat_v3',
            url: (ip, port) => `https://api.mcsrvstat.us/3/${ip}:${port}`,
            parser: (data) => {
                try {
                    const players = data.players || {};
                    let playerList = [];
                    
                    // Handle different player list formats
                    if (players.list && Array.isArray(players.list)) {
                        playerList = players.list
                            .filter(p => p && typeof p === 'string')
                            .map(p => p.trim());
                    } else if (players.sample && Array.isArray(players.sample)) {
                        playerList = players.sample
                            .filter(p => p && p.name && typeof p.name === 'string')
                            .map(p => p.name.trim());
                    }
                    
                    // Clean and validate icon URL
                    const icon = data.icon ? validateIconUrl(data.icon) : DEFAULT_ICON;
                    
                    return {
                        online: data.online || false,
                        players: {
                            online: Number(players.online) || 0,
                            max: Number(players.max) || 0,
                            list: playerList,
                            sample: players.sample || []
                        },
                        version: data.version || 'Unknown',
                        motd: {
                            raw: data.motd?.raw || [],
                            clean: Array.isArray(data.motd?.clean) ? data.motd.clean : [data.motd?.clean || 'No MOTD']
                        },
                        icon: icon,
                        software: data.software || 'Unknown',
                        plugins: data.plugins?.names || [],
                        mods: data.mods?.names || [],
                        map: data.map || 'Unknown',
                        debug: data.debug || {}
                    };
                } catch (error) {
                    logger.error('Error parsing mcsrvstat_v3 data:', error);
                    throw error;
                }
            }
        },
        {
            name: 'mcstatus_java',
            url: (ip, port) => `https://api.mcstatus.io/v2/status/java/${ip}:${port}`,
            parser: (data) => {
                try {
                    const players = data.players || {};
                    let playerList = [];
                    
                    // Handle mcstatus.io player format
                    if (players.list && Array.isArray(players.list)) {
                        playerList = players.list
                            .filter(p => p && (p.name || p.name_clean))
                            .map(p => {
                                const name = p.name_clean || p.name || 'Unknown';
                                return typeof name === 'string' ? name.trim() : 'Unknown';
                            });
                    }
                    
                    // Clean and validate icon URL
                    const icon = data.icon ? validateIconUrl(data.icon) : DEFAULT_ICON;
                    
                    return {
                        online: data.online || false,
                        players: {
                            online: Number(players.online) || 0,
                            max: Number(players.max) || 0,
                            list: playerList,
                            sample: players.list || []
                        },
                        version: data.version?.name_clean || data.version?.name || 'Unknown',
                        motd: {
                            raw: data.motd?.raw || [],
                            clean: Array.isArray(data.motd?.clean) ? data.motd.clean : [data.motd?.clean || 'No MOTD']
                        },
                        icon: icon,
                        software: data.software || 'Unknown'
                    };
                } catch (error) {
                    logger.error('Error parsing mcstatus_java data:', error);
                    throw error;
                }
            }
        }
    ],
    bedrock: [
        {
            name: 'mcsrvstat_bedrock',
            url: (ip, port) => `https://api.mcsrvstat.us/bedrock/3/${ip}:${port}`,
            parser: (data) => ({
                online: data.online || false,
                players: {
                    online: Number(data.players?.online) || 0,
                    max: Number(data.players?.max) || 0,
                    list: [], // Bedrock typically doesn't provide player lists
                    sample: []
                },
                version: data.version || 'Unknown',
                motd: {
                    raw: data.motd?.raw || [],
                    clean: Array.isArray(data.motd?.clean) ? data.motd.clean : [data.motd?.clean || 'No MOTD']
                },
                icon: DEFAULT_ICON,
                gamemode: data.gamemode || 'Survival'
            })
        },
        {
            name: 'mcstatus_bedrock',
            url: (ip, port) => `https://api.mcstatus.io/v2/status/bedrock/${ip}:${port}`,
            parser: (data) => ({
                online: data.online || false,
                players: {
                    online: Number(data.players?.online) || 0,
                    max: Number(data.players?.max) || 0,
                    list: [],
                    sample: []
                },
                version: data.version?.name_clean || data.version?.name || 'Unknown',
                motd: {
                    raw: data.motd?.raw || [],
                    clean: Array.isArray(data.motd?.clean) ? data.motd.clean : [data.motd?.clean || 'No MOTD']
                },
                icon: DEFAULT_ICON
            })
        }
    ]
};

// Enhanced server status fetcher
class ServerStatusFetcher {
    constructor(config) {
        this.config = config;
        this.endpoints = API_ENDPOINTS[config.serverType] || API_ENDPOINTS.java;
        this.timeout = 10000; // 10 seconds timeout
    }

    async fetchStatus() {
        const startTime = Date.now();
        const results = [];
        const errors = [];

        for (const host of this.config.hosts) {
            for (const endpoint of this.endpoints) {
                try {
                    const url = endpoint.url(host.ip, host.port);
                    const response = await axios.get(url, {
                        timeout: this.timeout,
                        headers: {
                            'User-Agent': `Minecraft-Server-Status/2.0.0 (+https://github.com/your-repo)`,
                            'Accept': 'application/json'
                        },
                        validateStatus: (status) => status < 500 // Accept 4xx errors
                    });

                    if (response.status === 200) {
                        const parsed = endpoint.parser(response.data);
                        results.push({
                            data: parsed,
                            endpoint: endpoint.name,
                            host: `${host.ip}:${host.port}`,
                            responseTime: Date.now() - startTime,
                            timestamp: Date.now()
                        });
                    } else {
                        errors.push({
                            endpoint: endpoint.name,
                            host: `${host.ip}:${host.port}`,
                            error: `HTTP ${response.status}: ${response.statusText}`
                        });
                    }
                } catch (error) {
                    const errorMsg = error.response 
                        ? `HTTP ${error.response.status}: ${error.response.statusText}`
                        : error.message;
                    
                    errors.push({
                        endpoint: endpoint.name,
                        host: `${host.ip}:${host.port}`,
                        error: errorMsg
                    });
                }
            }
        }

        return this.aggregateResults(results, errors, startTime);
    }

    aggregateResults(results, errors, startTime) {
        if (results.length === 0) {
            return {
                online: false,
                players: { online: 0, max: 0, list: [], sample: [] },
                version: this.config.version,
                motd: { clean: ['Server offline or unreachable'], raw: [] },
                icon: DEFAULT_ICON,
                responseTime: Date.now() - startTime,
                lastUpdated: new Date().toISOString(),
                errors: errors,
                dataSource: 'fallback',
                hostUsed: this.config.hosts[0] ? `${this.config.hosts[0].ip}:${this.config.hosts[0].port}` : 'Unknown'
            };
        }

        // Prioritize online responses with player lists
        const onlineResults = results.filter(r => r.data.online);
        let bestResult;

        if (onlineResults.length > 0) {
            // Sort by: has player list, then response time
            bestResult = onlineResults.sort((a, b) => {
                const aHasList = a.data.players.list.length > 0;
                const bHasList = b.data.players.list.length > 0;
                if (aHasList && !bHasList) return -1;
                if (!aHasList && bHasList) return 1;
                return a.responseTime - b.responseTime;
            })[0];
        } else {
            bestResult = results.sort((a, b) => a.responseTime - b.responseTime)[0];
        }

        const result = {
            ...bestResult.data,
            responseTime: bestResult.responseTime,
            lastUpdated: new Date().toISOString(),
            dataSource: bestResult.endpoint,
            hostUsed: bestResult.host,
            errors: errors.length > 0 ? errors : undefined
        };

        // Ensure player.list is always an array of strings
        if (result.players && result.players.list) {
            result.players.list = result.players.list
                .filter(p => p && typeof p === 'string')
                .map(p => p.trim());
        } else {
            result.players.list = [];
        }

        return result;
    }
}

// Initialize fetcher
const fetcher = new ServerStatusFetcher(SERVER_CONFIG);

// Monitoring service
class MonitoringService {
    constructor() {
        this.history = [];
        this.maxHistory = 500;
        this.monitoringInterval = null;
    }

    start(interval = 15000) {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
        }
        
        this.monitoringInterval = setInterval(async () => {
            await this.updateStatus();
        }, interval);
        
        // Initial update
        this.updateStatus();
        logger.info(`Monitoring started with ${interval}ms interval`);
    }

    async updateStatus() {
        try {
            const status = await fetcher.fetchStatus();
            
            // Update cache
            cache.set('server_status', status, 30); // 30 seconds TTL
            
            // Update history
            this.history.unshift({
                timestamp: Date.now(),
                online: status.online,
                players: status.players.online,
                maxPlayers: status.players.max,
                responseTime: status.responseTime,
                tps: status.debug?.tps || 20
            });

            // Trim history
            if (this.history.length > this.maxHistory) {
                this.history = this.history.slice(0, this.maxHistory);
            }

            // Calculate average TPS from recent history
            const recentHistory = this.history.slice(0, 10);
            if (recentHistory.length > 0) {
                analytics.performance.averageTPS = recentHistory.reduce((sum, entry) => sum + (entry.tps || 20), 0) / recentHistory.length;
            }

            // Update analytics
            analytics.requests.total++;
            if (status.online) {
                analytics.requests.success++;
                if (status.players.online > analytics.performance.peakPlayers) {
                    analytics.performance.peakPlayers = status.players.online;
                }
                if (status.debug?.tps < 15) {
                    analytics.performance.lowTPSEvents++;
                }
            } else {
                analytics.requests.failed++;
                analytics.uptime.lastDowntime = new Date().toISOString();
                analytics.uptime.downtimeHistory.push({
                    start: new Date().toISOString(),
                    duration: 0
                });
            }
            
            // Update Discord bot status if available
            if (client?.user) {
                this.updateBotStatus(status);
            }

            logger.debug(`Status updated: ${status.online ? 'Online' : 'Offline'} - ${status.players.online}/${status.players.max} players`);
        } catch (error) {
            logger.error('Monitoring error:', error);
        }
    }

    updateBotStatus(status) {
        try {
            const activity = status.online
                ? `${status.players.online}/${status.players.max} players online`
                : 'Server offline';
            
            client.user.setPresence({
                activities: [{
                    name: activity,
                    type: ActivityType.Watching
                }],
                status: status.online ? 'online' : 'dnd'
            });
        } catch (error) {
            logger.error('Error updating bot status:', error);
        }
    }

    getUptime() {
        if (this.history.length === 0) return 100;
        
        const last24Hours = this.history.filter(entry => 
            Date.now() - entry.timestamp < 24 * 60 * 60 * 1000
        );
        
        if (last24Hours.length === 0) return 100;
        
        const onlineCount = last24Hours.filter(entry => entry.online).length;
        return ((onlineCount / last24Hours.length) * 100).toFixed(2);
    }

    stop() {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
            logger.info('Monitoring stopped');
        }
    }
}

// Initialize monitoring
const monitor = new MonitoringService();

// Discord Bot
const client = new Client({
    intents: [
        IntentsBitField.Flags.Guilds,
        IntentsBitField.Flags.GuildMessages,
        IntentsBitField.Flags.MessageContent
    ],
    presence: {
        status: 'online',
        activities: [{
            name: 'Loading...',
            type: ActivityType.Watching
        }]
    }
});

// Discord Commands
const discordCommands = [
    new SlashCommandBuilder()
        .setName('status')
        .setDescription('Get server status')
        .addBooleanOption(option =>
            option.setName('detailed')
                .setDescription('Show detailed information')
                .setRequired(false)),

    new SlashCommandBuilder()
        .setName('players')
        .setDescription('Show online players'),

    new SlashCommandBuilder()
        .setName('serverinfo')
        .setDescription('Get server information'),

    new SlashCommandBuilder()
        .setName('performance')
        .setDescription('View server performance stats'),

    new SlashCommandBuilder()
        .setName('help')
        .setDescription('Show all available commands'),

    new SlashCommandBuilder()
        .setName('ping')
        .setDescription('Check bot latency'),

    new SlashCommandBuilder()
        .setName('join')
        .setDescription('Get server connection details'),

    new SlashCommandBuilder()
        .setName('socials')
        .setDescription('Get all social media links'),

    new SlashCommandBuilder()
        .setName('vote')
        .setDescription('Vote for our server'),

    new SlashCommandBuilder()
        .setName('report')
        .setDescription('Report an issue')
        .addStringOption(option =>
            option.setName('issue')
                .setDescription('Describe the issue')
                .setRequired(true)),

    new SlashCommandBuilder()
        .setName('stats')
        .setDescription('View bot statistics')
].map(cmd => cmd.toJSON());

// Discord event handlers
client.once('ready', async () => {
    logger.info(`Discord bot logged in as ${client.user.tag}`);
    
    // Update bot status
    try {
        const status = await fetcher.fetchStatus();
        monitor.updateBotStatus(status);
    } catch (error) {
        logger.error('Failed to update bot status on ready:', error);
    }
    
    // Register commands
    try {
        const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);
        await rest.put(
            Routes.applicationCommands(process.env.DISCORD_CLIENT_ID),
            { body: discordCommands }
        );
        logger.info(`Registered ${discordCommands.length} Discord commands`);
    } catch (error) {
        logger.error('Failed to register commands:', error);
    }
});

// FIXED: Helper function to reply with proper flags
async function safeReply(interaction, options) {
    try {
        // Handle flags properly - MessageFlags is a bitfield
        if (options.ephemeral && !options.flags) {
            options.flags = MessageFlags.Ephemeral;
        }
        
        if (interaction.replied || interaction.deferred) {
            await interaction.editReply(options);
        } else {
            await interaction.reply(options);
        }
    } catch (error) {
        logger.error('Error in safeReply:', error);
        try {
            if (!interaction.replied && !interaction.deferred) {
                await interaction.reply({
                    content: 'An error occurred while processing your request.',
                    flags: MessageFlags.Ephemeral
                });
            }
        } catch (e) {
            logger.error('Failed to send error response:', e);
        }
    }
}

client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;

    analytics.discord.interactions++;
    analytics.discord.lastCommand = {
        command: interaction.commandName,
        user: interaction.user.tag,
        timestamp: new Date().toISOString()
    };

    try {
        const command = interaction.commandName;
        const status = cache.get('server_status') || await fetcher.fetchStatus();

        switch (command) {
            case 'status':
                await handleStatusCommand(interaction, status);
                break;
            case 'players':
                await handlePlayersCommand(interaction, status);
                break;
            case 'serverinfo':
                await handleServerInfoCommand(interaction);
                break;
            case 'performance':
                await handlePerformanceCommand(interaction);
                break;
            case 'ping':
                await handlePingCommand(interaction);
                break;
            case 'join':
                await handleJoinCommand(interaction);
                break;
            case 'socials':
                await handleSocialsCommand(interaction);
                break;
            case 'help':
                await handleHelpCommand(interaction);
                break;
            case 'vote':
                await handleVoteCommand(interaction);
                break;
            case 'report':
                await handleReportCommand(interaction);
                break;
            case 'stats':
                await handleStatsCommand(interaction);
                break;
            default:
                await safeReply(interaction, { 
                    content: 'Command not implemented', 
                    flags: MessageFlags.Ephemeral 
                });
        }

        analytics.discord.commandsUsed++;
    } catch (error) {
        logger.error(`Command error (${interaction.commandName}):`, error);
        await safeReply(interaction, { 
            content: 'An error occurred while processing your command.', 
            flags: MessageFlags.Ephemeral 
        });
    }
});

// Command handlers
async function handleStatusCommand(interaction, status) {
    try {
        const embed = new EmbedBuilder()
            .setTitle(`${SERVER_CONFIG.name} Status`)
            .setColor(status.online ? 0x00FF00 : 0xFF0000)
            .addFields(
                { name: 'Status', value: status.online ? '🟢 Online' : '🔴 Offline', inline: true },
                { name: 'Players', value: `${status.players.online}/${status.players.max}`, inline: true },
                { name: 'Version', value: status.version, inline: true },
                { name: 'Response Time', value: `${status.responseTime}ms`, inline: true }
            )
            .setFooter({ text: `Last updated: ${new Date(status.lastUpdated).toLocaleString()}` });

        // Safely set thumbnail
        setEmbedThumbnail(embed, status.icon);

        if (interaction.options.getBoolean('detailed')) {
            const motdText = Array.isArray(status.motd.clean) 
                ? status.motd.clean.join('\n').substring(0, 1024) 
                : String(status.motd.clean || 'No MOTD').substring(0, 1024);
            
            embed.addFields(
                { name: 'MOTD', value: motdText || 'No MOTD' },
                { name: 'Software', value: status.software || 'Unknown' },
                { name: 'Host', value: status.hostUsed || 'Unknown' }
            );
            
            if (status.debug?.tps) {
                embed.addFields({ name: 'TPS', value: status.debug.tps.toString(), inline: true });
            }
        }

        const row = new ActionRowBuilder()
            .addComponents(
                new ButtonBuilder()
                    .setCustomId('refresh_status')
                    .setLabel('🔄 Refresh')
                    .setStyle(ButtonStyle.Primary),
                new ButtonBuilder()
                    .setURL(SERVER_CONFIG.discord)
                    .setLabel('Join Discord')
                    .setStyle(ButtonStyle.Link),
                new ButtonBuilder()
                    .setCustomId('copy_ip')
                    .setLabel('Copy IP')
                    .setStyle(ButtonStyle.Secondary)
            );

        await safeReply(interaction, { embeds: [embed], components: [row] });
    } catch (error) {
        logger.error('Error in handleStatusCommand:', error);
        throw error;
    }
}

async function handlePlayersCommand(interaction, status) {
    try {
        if (!status.online) {
            return await safeReply(interaction, { 
                content: 'Server is currently offline.', 
                flags: MessageFlags.Ephemeral 
            });
        }

        const players = Array.isArray(status.players.list) 
            ? status.players.list.filter(p => p && typeof p === 'string' && p.trim())
            : [];

        const embed = new EmbedBuilder()
            .setTitle(`Online Players (${status.players.online})`)
            .setColor(0x0099FF);

        // Safely set thumbnail
        setEmbedThumbnail(embed, status.icon);

        if (players.length > 0) {
            // Group players for better display (max 1024 characters per field)
            let currentField = '';
            const fields = [];
            
            for (const player of players) {
                const playerEntry = player + ', ';
                if (currentField.length + playerEntry.length > 1024) {
                    fields.push(currentField.trim().replace(/,\s*$/, ''));
                    currentField = playerEntry;
                } else {
                    currentField += playerEntry;
                }
            }
            
            if (currentField) {
                fields.push(currentField.trim().replace(/,\s*$/, ''));
            }
            
            fields.forEach((field, index) => {
                embed.addFields({
                    name: index === 0 ? 'Player List' : `Players (Cont.)`,
                    value: field || 'No players',
                    inline: false
                });
            });
        } else if (status.players.online > 0) {
            embed.setDescription(`${status.players.online} player${status.players.online !== 1 ? 's' : ''} online, but player list is not available from the server.`);
        } else {
            embed.setDescription('No players online.');
        }

        await safeReply(interaction, { embeds: [embed] });
    } catch (error) {
        logger.error('Error in handlePlayersCommand:', error);
        throw error;
    }
}

async function handleServerInfoCommand(interaction) {
    const embed = new EmbedBuilder()
        .setTitle(SERVER_CONFIG.name)
        .setColor(0x5865F2)
        .addFields(
            { name: 'Description', value: SERVER_CONFIG.description, inline: false },
            { name: 'Version', value: SERVER_CONFIG.version, inline: true },
            { name: 'Type', value: SERVER_CONFIG.serverType.toUpperCase(), inline: true },
            { name: 'Location', value: `${SERVER_CONFIG.location} (${SERVER_CONFIG.region})`, inline: true },
            { name: 'Owner', value: SERVER_CONFIG.owner, inline: true },
            { name: 'Started', value: SERVER_CONFIG.started, inline: true },
            { name: 'Gamemodes', value: SERVER_CONFIG.gamemodes.join(', ') || 'None', inline: false },
            { name: 'Features', value: SERVER_CONFIG.features.slice(0, 5).join(', ') + (SERVER_CONFIG.features.length > 5 ? '...' : ''), inline: false }
        )
        .setFooter({ text: `Server IP: ${SERVER_CONFIG.hosts[0].ip}:${SERVER_CONFIG.hosts[0].port}` });

    // Safely set thumbnail
    setEmbedThumbnail(embed, DEFAULT_ICON);

    await safeReply(interaction, { embeds: [embed] });
}

async function handlePerformanceCommand(interaction) {
    const uptime = monitor.getUptime();
    const embed = new EmbedBuilder()
        .setTitle('Server Performance')
        .setColor(0xFFA500)
        .addFields(
            { name: 'Uptime (24h)', value: `${uptime}%`, inline: true },
            { name: 'Average TPS', value: analytics.performance.averageTPS.toFixed(2), inline: true },
            { name: 'Peak Players', value: analytics.performance.peakPlayers.toString(), inline: true },
            { name: 'Total Requests', value: analytics.requests.total.toString(), inline: true },
            { name: 'Success Rate', value: `${((analytics.requests.success / Math.max(analytics.requests.total, 1)) * 100).toFixed(1)}%`, inline: true },
            { name: 'Low TPS Events', value: analytics.performance.lowTPSEvents.toString(), inline: true },
            { name: 'Memory Usage', value: `${(process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2)} MB`, inline: true },
            { name: 'Bot Uptime', value: `${Math.floor(process.uptime() / 3600)}h ${Math.floor((process.uptime() % 3600) / 60)}m`, inline: true }
        );

    await safeReply(interaction, { embeds: [embed] });
}

async function handlePingCommand(interaction) {
    const ping = client.ws.ping;
    const embed = new EmbedBuilder()
        .setTitle('🏓 Pong!')
        .setDescription(`Bot Latency: ${ping}ms\nAPI Latency: ${Date.now() - interaction.createdTimestamp}ms`)
        .setColor(0x00FF00);

    await safeReply(interaction, { embeds: [embed] });
}

async function handleJoinCommand(interaction) {
    const host = SERVER_CONFIG.hosts[0];
    const embed = new EmbedBuilder()
        .setTitle('Join Our Server!')
        .setColor(0x00FF00)
        .setDescription(`**IP:** \`${host.ip}:${host.port}\`\n**Version:** ${SERVER_CONFIG.version}\n**Type:** ${SERVER_CONFIG.serverType.toUpperCase()}`)
        .addFields(
            { name: 'Quick Connect', value: `\`/connect ${host.ip}:${host.port}\` (Java)\n\`Add Server > ${host.ip} ${host.port}\` (Bedrock)` },
            { name: 'Need Help?', value: `Join our [Discord](${SERVER_CONFIG.discord}) for assistance` }
        );

    // Safely set thumbnail
    setEmbedThumbnail(embed, DEFAULT_ICON);

    await safeReply(interaction, { embeds: [embed] });
}

async function handleSocialsCommand(interaction) {
    const { social } = SERVER_CONFIG;
    const embed = new EmbedBuilder()
        .setTitle(`${SERVER_CONFIG.name} Social Links`)
        .setColor(0x5865F2)
        .setDescription('Connect with us on these platforms:')
        .addFields(
            { name: 'Discord', value: social.discord ? `[Join](${social.discord})` : 'Not available', inline: true },
            { name: 'Website', value: social.website ? `[Visit](${social.website})` : 'Not available', inline: true },
            { name: 'Twitter', value: social.twitter ? `[Follow](${social.twitter})` : 'Not available', inline: true },
            { name: 'YouTube', value: social.youtube ? `[Subscribe](${social.youtube})` : 'Not available', inline: true },
            { name: 'Telegram', value: social.telegram ? `[Join](${social.telegram})` : 'Not available', inline: true },
            { name: 'Instagram', value: social.instagram ? `[Follow](${social.instagram})` : 'Not available', inline: true },
            { name: 'Vote', value: social.vote ? `[Vote](${social.vote})` : 'Not available', inline: true }
        );

    await safeReply(interaction, { embeds: [embed] });
}

async function handleHelpCommand(interaction) {
    const embed = new EmbedBuilder()
        .setTitle('Bot Commands Help')
        .setColor(0x5865F2)
        .setDescription('Here are all available commands:')
        .addFields(
            { name: '/status', value: 'Check server status', inline: true },
            { name: '/players', value: 'Show online players', inline: true },
            { name: '/serverinfo', value: 'Server information', inline: true },
            { name: '/performance', value: 'Performance statistics', inline: true },
            { name: '/join', value: 'Get server IP', inline: true },
            { name: '/socials', value: 'Social media links', inline: true },
            { name: '/ping', value: 'Check bot latency', inline: true },
            { name: '/vote', value: 'Vote for server', inline: true },
            { name: '/report', value: 'Report an issue', inline: true },
            { name: '/stats', value: 'Bot statistics', inline: true }
        )
        .setFooter({ text: 'Use /command for more information about each command' });

    await safeReply(interaction, { embeds: [embed], flags: MessageFlags.Ephemeral });
}

async function handleVoteCommand(interaction) {
    const voteUrl = SERVER_CONFIG.social.vote;
    if (!voteUrl) {
        return await safeReply(interaction, { 
            content: 'No vote link available at the moment.', 
            flags: MessageFlags.Ephemeral 
        });
    }
    
    const embed = new EmbedBuilder()
        .setTitle(`Vote for ${SERVER_CONFIG.name}!`)
        .setDescription('Your vote helps us grow the community!')
        .setColor(0x00FF00)
        .addFields(
            { name: 'Vote Now', value: `[Click Here to Vote](${voteUrl})` }
        );

    // Safely set thumbnail
    setEmbedThumbnail(embed, DEFAULT_ICON);

    await safeReply(interaction, { embeds: [embed] });
}

async function handleReportCommand(interaction) {
    const issue = interaction.options.getString('issue');
    logger.warn(`BUG REPORT from ${interaction.user.tag} (${interaction.user.id}): ${issue}`);
    
    await safeReply(interaction, { 
        content: 'Thank you for your report! It has been logged and our team will review it soon.', 
        flags: MessageFlags.Ephemeral 
    });
}

async function handleStatsCommand(interaction) {
    const cacheStats = cache.getStats();
    const embed = new EmbedBuilder()
        .setTitle('Bot Statistics')
        .setColor(0x9C27B0)
        .addFields(
            { name: 'Commands Used', value: analytics.discord.commandsUsed.toString(), inline: true },
            { name: 'Total Interactions', value: analytics.discord.interactions.toString(), inline: true },
            { name: 'Uptime', value: `${Math.floor(process.uptime() / 3600)}h ${Math.floor((process.uptime() % 3600) / 60)}m`, inline: true },
            { name: 'Server Uptime', value: `${monitor.getUptime()}%`, inline: true },
            { name: 'Cache Hits', value: cacheStats.hits.toString(), inline: true },
            { name: 'Cache Misses', value: cacheStats.misses.toString(), inline: true },
            { name: 'Cache Keys', value: cacheStats.keys.toString(), inline: true }
        );

    await safeReply(interaction, { embeds: [embed] });
}

// Button interactions
client.on('interactionCreate', async interaction => {
    if (!interaction.isButton()) return;

    try {
        switch (interaction.customId) {
            case 'refresh_status':
                await interaction.deferUpdate();
                const status = await fetcher.fetchStatus();
                const embed = new EmbedBuilder()
                    .setTitle('Status Refreshed')
                    .setColor(status.online ? 0x00FF00 : 0xFF0000)
                    .setDescription(`Status: ${status.online ? '🟢 Online' : '🔴 Offline'}\nPlayers: ${status.players.online}/${status.players.max}`);
                
                await interaction.editReply({ embeds: [embed] });
                break;

            case 'copy_ip':
                const host = SERVER_CONFIG.hosts[0];
                await safeReply(interaction, { 
                    content: `Server IP: \`${host.ip}:${host.port}\`\nCopy this to connect!`, 
                    flags: MessageFlags.Ephemeral 
                });
                break;
        }
    } catch (error) {
        logger.error('Button interaction error:', error);
        if (!interaction.replied && !interaction.deferred) {
            await safeReply(interaction, { 
                content: 'An error occurred while processing your request.', 
                flags: MessageFlags.Ephemeral 
            });
        }
    }
});

// Error handling for Discord client
client.on('error', error => {
    logger.error('Discord client error:', error);
});

client.on('warn', warning => {
    logger.warn('Discord client warning:', warning);
});

// Web routes
app.get('/', async (req, res) => {
    try {
        let status = cache.get('server_status');
        if (!status) {
            status = await fetcher.fetchStatus();
            cache.set('server_status', status, 30);
        }

        // Ensure player list is properly formatted for EJS template
        if (status.players && status.players.list) {
            status.players.list = status.players.list
                .filter(p => p && typeof p === 'string')
                .map(p => p.trim());
        } else {
            status.players.list = [];
        }

        res.render('index', {
            server: status,
            config: SERVER_CONFIG,
            analytics: analytics,
            uptime: monitor.getUptime(),
            history: monitor.history.slice(0, 50),
            timestamp: new Date().toISOString(),
            isOnline: status.online
        });
    } catch (error) {
        logger.error('Homepage error:', error);
        res.status(500).render('error', { 
            error: 'Failed to load server status',
            message: process.env.NODE_ENV === 'development' ? error.message : 'Please try again later.'
        });
    }
});

app.get('/api/status', async (req, res) => {
    try {
        const useCache = req.query.cache !== 'false';
        let status;

        if (useCache) {
            status = cache.get('server_status');
        }

        if (!status) {
            status = await fetcher.fetchStatus();
            cache.set('server_status', status, 30);
        }

        res.json({
            success: true,
            data: status,
            cached: useCache && cache.has('server_status'),
            cacheAge: cache.getTtl('server_status') ? Math.max(0, (cache.getTtl('server_status') - Date.now()) / 1000) : 0,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('API status error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch status',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

app.get('/api/players', async (req, res) => {
    try {
        const status = cache.get('server_status') || await fetcher.fetchStatus();
        
        res.json({
            online: status.players.online,
            max: status.players.max,
            list: Array.isArray(status.players.list) ? status.players.list.filter(p => typeof p === 'string') : [],
            sample: status.players.sample || [],
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            error: 'Failed to fetch players',
            timestamp: new Date().toISOString()
        });
    }
});

app.get('/api/performance', (req, res) => {
    try {
        res.json({
            success: true,
            uptime: monitor.getUptime(),
            analytics: analytics,
            history: monitor.history.slice(0, 100),
            charts: {
                players: monitor.history.slice(0, 50).map(h => ({
                    x: new Date(h.timestamp).toISOString(),
                    y: h.players
                })),
                status: monitor.history.slice(0, 50).map(h => ({
                    x: new Date(h.timestamp).toISOString(),
                    y: h.online ? 1 : 0
                }))
            },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Performance API error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch performance data' 
        });
    }
});

app.get('/api/health', (req, res) => {
    const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        services: {
            discord: client.isReady() ? 'connected' : 'disconnected',
            monitoring: monitor.monitoringInterval ? 'running' : 'stopped',
            cache: 'operational',
            web: 'running'
        },
        metrics: {
            uptime: process.uptime(),
            memory: {
                heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                heapTotal: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
                rss: Math.round(process.memoryUsage().rss / 1024 / 1024)
            },
            cache: cache.getStats(),
            requests: analytics.requests
        }
    };

    res.json(health);
});

// Admin endpoints (basic implementation)
app.get('/admin/panel', (req, res) => {
    // Simple authentication check
    const auth = req.headers.authorization;
    if (!auth || auth !== process.env.ADMIN_TOKEN) {
        return res.status(401).render('error', { error: 'Unauthorized' });
    }

    res.render('admin', {
        config: SERVER_CONFIG,
        analytics: analytics,
        monitor: {
            history: monitor.history.slice(0, 100),
            uptime: monitor.getUptime()
        },
        cache: cache.getStats(),
        timestamp: new Date().toISOString()
    });
});

app.post('/admin/clear-cache', (req, res) => {
    const auth = req.headers.authorization;
    if (!auth || auth !== process.env.ADMIN_TOKEN) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    cache.flushAll();
    res.json({ success: true, message: 'Cache cleared', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    
    const statusCode = err.status || 500;
    const errorResponse = {
        error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!',
        timestamp: new Date().toISOString()
    };
    
    if (req.accepts('html')) {
        res.status(statusCode).render('error', errorResponse);
    } else {
        res.status(statusCode).json(errorResponse);
    }
});

// 404 handler
app.use((req, res) => {
    if (req.accepts('html')) {
        res.status(404).render('404', {
            path: req.path,
            timestamp: new Date().toISOString()
        });
    } else {
        res.status(404).json({
            error: 'Not Found',
            path: req.path,
            timestamp: new Date().toISOString()
        });
    }
});

// Graceful shutdown
function gracefulShutdown(signal) {
    logger.info(`Received ${signal}, starting graceful shutdown...`);
    
    monitor.stop();
    
    if (client.isReady()) {
        client.destroy();
        logger.info('Discord bot disconnected');
    }
    
    // Give time for ongoing requests to complete
    setTimeout(() => {
        logger.info('Shutdown complete');
        process.exit(0);
    }, 5000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    // Don't exit immediately, let the error handlers deal with it
});

// Start everything
async function start() {
    try {
        // Start monitoring
        monitor.start();
        logger.info('Monitoring service started');
        
        // Login Discord bot
        await client.login(process.env.DISCORD_TOKEN);
        logger.info('Discord bot logged in successfully');
        
        // Start web server
        app.listen(PORT, () => {
            logger.info(`Server running on port ${PORT}`);
            logger.info(`Status page: http://localhost:${PORT}`);
            logger.info(`API available at: http://localhost:${PORT}/api/status`);
            logger.info(`Health check: http://localhost:${PORT}/api/health`);
        });
    } catch (error) {
        logger.error('Failed to start application:', error);
        process.exit(1);
    }
}

// Only start if this file is being run directly
if (import.meta.url === `file://${process.argv[1]}`) {
    start();
}

export { app, client, monitor, fetcher, SERVER_CONFIG };