FROM ubuntu:20.04

RUN apt-get update && apt-get install -y  gnupg git

WORKDIR /tmp
COPY verify_commits.sh /tmp/

CMD ["/bin/bash", "/tmp/verify_commits.sh"]

