docker build -t signer -f docker/Dockerfile .
docker run -ti -v $(pwd):/tmp signer /bin/bash
