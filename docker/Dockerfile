FROM ubuntu:20.04

RUN apt-get update && apt-get install -y  gnupg git

COPY verify_commits.sh /tmp/
WORKDIR /tmp/repo

CMD ["/bin/bash", "/tmp/verify_commits.sh"]

