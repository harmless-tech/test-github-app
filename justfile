default:
    just -l

fmt:
    cargo +nightly fmt

check:
    cargo +nightly fmt --check
    cargo clippy --all-targets --all-features --workspace -- -D warnings

redis-start:
    docker run -d --rm --name test-redis-ga -p 6379:6379 redis:alpine

redis-stop:
    docker stop test-redis-ga

init:
    export REDIS_URL=redis://default@localhost:6379
    export WEBHOOK_SLUG=testing
    export WEBHOOK_SECRET=tty
    export GH_APP_KEY="$(cat priv-key.pem)"

dbuild:
    docker buildx build -f Dockerfile --build-arg BUILD_PROFILE=dev -t test-gh-app .

dbuild-release:
    docker buildx build -f Dockerfile -t test-gh-app .

redis_ip := `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' test-redis-ga | xargs basename`
drun:
    docker run --rm --name test-app-ga -p 3000:3000 -e REDIS_URL=redis://default@{{redis_ip}}:6379 -e WEBHOOK_SLUG -e WEBHOOK_SECRET -e GH_APP_KEY test-gh-app

dd:
    just dbuild
    just drun
