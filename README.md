# Go-API-Gateway

This is an API Gateway built in Go. It includes various essential features commonly found in production API Gateways.

Features:

-   [x] URL Rewriting
-   [x] Rate Limiting (ref: https://pkg.go.dev/golang.org/x/time/rate & https://blog.logrocket.com/rate-limiting-go-application/)
-   [x] Authentication (ref: https://konghq.com/blog/engineering/jwt-kong-gateway)
-   [x] Caching (ref: https://github.com/patrickmn/go-cache)
-   [x] TLS Termination
-   [x] IP Whitelisting
-   [x] Circuit Breaker (ref: https://github.com/sony/gobreaker)
-   [x] Logging (ref: https://betterstack.com/community/guides/logging/logging-in-go/ & https://pkg.go.dev/golang.org/x/exp/slog)
-   [x] Tracing / Metrics (ref: https://prometheus.io/docs/guides/go-application/)
-   [ ] Orchestration/Aggregation (Ambitious feature) (really cool tho)
-   [ ] Protocol Translation
-   [ ] Throttling
## Getting Started

To get started with go-api-gateway, clone the repository and follow the setup instructions below.

### Prerequisites

-   Go (version 1.22 or later)
-   Docker (for containerization and deployment)

### Installation

1. Install dependencies

```sh
go mod download
```

2. Build and run the gateway

```sh
make run
```

This will start the gateway(locally) on port 8080.

OR

```sh
make image
make run_image
```

This will build the docker image and run the gateway in a container.

### Configuration

Configuration options can be found in the `config.yaml` file. Customize it as needed for your environment/use case.

### Contributing

Let me know incase of any suggestions!
