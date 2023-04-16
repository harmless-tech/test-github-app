default:
    just -l

redis-start:
    export REDIS_URL=redis://default@localhost:6379
    docker run -d --name test-redis-ga --rm -p 6379:6379 redis:alpine

redis-stop:
    docker stop test-redis-ga
