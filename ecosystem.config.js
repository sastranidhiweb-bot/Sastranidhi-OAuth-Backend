// ecosystem.config.js
// Usage: pm2 start ecosystem.config.js --env production
module.exports = {
  apps: [
    {
      name: 'sastranidhi-oauth',
      script: 'src/server.js',
      instances: 1, // bump once the auth flow is stateless-safe to scale horizontally
      exec_mode: 'fork',
      watch: false,
      max_memory_restart: '300M',
      env: {
        NODE_ENV: 'development',
      },
      env_production: {
        NODE_ENV: 'production',
      },
      error_file: 'logs/pm2-error.log',
      out_file: 'logs/pm2-out.log',
      merge_logs: true,
      time: true,
    },
  ],
};
