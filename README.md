![GitHub](https://img.shields.io/github/license/samuelba/traefik_crowdsec_bouncer)
[![ci](https://github.com/samuelba/traefik_crowdsec_bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelba/traefik_crowdsec_bouncer/actions/workflows/ci.yml)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/samuelba/traefik_crowdsec_bouncer)
![Docker Image Size (latest semver)](https://img.shields.io/docker/image-size/samuelba/traefik_crowdsec_bouncer)

# Traefik CrowdSec Bouncer

This projects implements a simple HTTP server that acts as a bouncer for the Traefik ForwardAuth middleware. 
It uses the CrowdSec API to check if the IP address of the request is banned or not.

The service support three modes "stream", "live" and "none". 
The mode can be configured with the `CROWDSEC_MODE` environment variable.

| Mode    | Description                                                                                                         |
|---------|---------------------------------------------------------------------------------------------------------------------|
| stream  | Periodically, every `STREAM_UPDATE_INTERVAL` seconds, fetch the list of blocked IP addresses from the CrowdSec API. |
| live    | Call the CrowdSec API for every unknown IP address and store it for `LIVE_CACHE_EXPIRATION` seconds in the cache.   |
| none    | Call the CrowdSec API for every request (not very resource friendly).                                               |

## Usage

### Docker Compose

Example `docker-compose.yml` file

```yaml
version: '3.7'

services:
  traefik-crowdsec-bouncer:
    # Build the image locally.
    build:
        context: .
        dockerfile: Dockerfile
    image: traefik-crowdsec-bouncer:latest

    # Use the image from Docker Hub.
    # image: samuelba/traefik_crowdsec_bouncer:latest

    container_name: traefik-crowdsec-bouncers
    restart: unless-stopped
    environment:
      # CrowdSec API key. Get it with e.g. `docker exec -it crowdsec cscli bouncers add traefik-crowdsec-bouncer`.
      - CROWDSEC_API_KEY=abc123
      # CrowdSec API host including the port e.g. crowdsec:8080.
      - CROWDSEC_HOST=crowdsec:8080
      # Call CrowdSec API over HTTPS (true) or HTTP (false).
      - CROWDSEC_HTTPS=false
      # The mode to verify the IP address. Can be either "stream", "live" or "none".
      # In "stream" mode the service will periodically fetch the list of blocked IP addresses from the CrowdSec API.
      # In "live" mode the service will call the CrowdSec API for every unknown IP address and store it for 'LIVE_CACHE_EXPIRATION' seconds in the cache.
      # In "none" mode the service will call the CrowdSec API for every request. Not very resource friendly.
      - CROWDSEC_MODE=stream
      # Stream update interval in seconds. Only needed in "stream" mode.
      - STREAM_UPDATE_INTERVAL=5
      # The cache expiration time in seconds. Only needed in "live" mode.
      - LIVE_CACHE_EXPIRATION=5
      # The port the service should listen on. Default is 8080.
      - PORT=8080
```

## Roadmap

* [ ] Add support for log level.
* [ ] Add support for trusted proxies.
