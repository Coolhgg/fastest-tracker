module.exports = {
  apps: [
    {
      name: "kenmei-api",
      script: "npm",
      args: "start",
      autorestart: true,
      max_memory_restart: "1G",
      env: {
        NODE_ENV: "production",
        PORT: 3002,
        TZ: "UTC"
      },
      error_file: "logs/api-error.log",
      out_file: "logs/api-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss"
    },
    {
      name: "kenmei-workers",
      script: "npm",
      args: "run worker",
      exec_mode: "fork",
      // HORIZONTAL SCALING: Set instances > 1 to scale workers
      // Safe because:
      // - BullMQ handles job distribution automatically
      // - Deterministic jobIds prevent duplicate processing
      // - DB unique constraints prevent duplicate data
      // - Scheduler uses distributed lock (only 1 instance runs it)
      instances: process.env.WORKER_INSTANCES ? parseInt(process.env.WORKER_INSTANCES) : 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "900M",
      kill_timeout: 30000,
      listen_timeout: 10000,
      restart_delay: 5000,
      exp_backoff_restart_delay: 1000,
      env: {
        NODE_ENV: "production",
        TZ: "UTC"
      },
      error_file: "logs/workers-error.log",
      out_file: "logs/workers-out.log",
      log_date_format: "YYYY-MM-DD HH:mm:ss"
    }
  ],
  deploy: {
    production: {
      user: "root",
      host: "localhost",
      ref: "origin/main",
      repo: "git@github.com:user/repo.git",
      path: "/var/www/kenmei",
      "post-deploy": "npm install && npm run build && npm run db:migrate && pm2 reload ecosystem.config.js --env production && pm2 save"
    }
  }
}
