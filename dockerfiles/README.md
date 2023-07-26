# Docker compose deploy

## Standalone

You need to `cp .env.example .env` and edit `.env` to adapt it to your particular deployment

Then:

```sh
docker compose up -d
```

Note that the RESTART variable can be set to change the behaviour across restarts. To ensure the node is started after a reboot, set it to `always` or `unless-stopped`
