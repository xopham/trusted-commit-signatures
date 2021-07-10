# trusted-commit-signatures

```
. docker/build_and_run.sh
```

```
mkdir ~/.gnupg
echo "use-agent 
pinentry-mode loopback" > ~/.gnupg/gpg.conf
echo "allow-loopback-pinentry" > ~/.gnupg/gpg-agent.conf
echo RELOADAGENT | gpg-connect-agent

gpg --full-generate-key
# Password: test1234

gpg --list-secret-keys --keyid-format=long
# gpg: checking the trustdb
# gpg: marginals needed: 3  completes needed: 1  trust model: pgp
# gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
# /root/.gnupg/pubring.kbx
# ------------------------
# sec   rsa4096/0C579BD96E991F8F 2021-07-10 [SC]
#       E2A688D9A90F0ACE8C30F4BD0C579BD96E991F8F
# uid                 [ultimate] Signer One <signer.one@xhostservice.xyz>
# ssb   rsa4096/A733CB119010B966 2021-07-10 [E]

cd /tmp
gpg --armor --export 0C579BD96E991F8F > .pubkeys/signer1.gpg.pub
# public key

git config --global user.email "signer.one@xhostervice.xyz"
git config --global user.name "Signer One"
git config --global user.signingkey 0C579BD96E991F8F

git commit -S -m "signer1: signed commit"
```

```
mkdir .ephemeral_gnupg
GNUPGHOME=/media/sf_trusted-commit-signatures/.ephemeral_gnupg/ gpg --import .pubkeys/signer1.gpg.pub
GNUPGHOME=/media/sf_trusted-commit-signatures/.ephemeral_gnupg/ git log --oneline --show-signature
GNUPGHOME=/media/sf_trusted-commit-signatures/.ephemeral_gnupg/ git verify-commit dd4cae5

```
