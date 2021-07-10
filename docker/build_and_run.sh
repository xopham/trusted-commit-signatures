docker build -t commit-verifier -f docker/Dockerfile .
docker run -v $(git rev-parse --show-toplevel):/tmp commit-verifier
