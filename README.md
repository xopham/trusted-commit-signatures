# trusted-commit-signatures

```
. docker/build_and_run.sh
```

```
gpg --full-generate-key
# Password: testing1234

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
gpg --armor --export 0C579BD96E991F8F > .pubkeys/pkey_signer1
# public key

git config --global user.email "signer.one@xhostervice.xyz"
git config --global user.name "Signer One"
git config --global user.signingkey 0C579BD96E991F8F
```
