# trusted-commit-signatures

Validate Integrity and Provenance of Git Commits by Trust Pinning Commit Signatures to Public Keys maintained within the Repository.

## Intro

Let's briefly review some basics and thoughts on commit signing...

### The idea

In general, code should be signed to ensure integrity and provenance and thus protect against tampering or unauthorized code injection.
One solution is to sign git commits and verify those within the repository.
To do so, one can for example use GitHub [Commit Signature Verification](https://docs.github.com/en/github/authenticating-to-github/managing-commit-signature-verification/about-commit-signature-verification).
In essence, a GPG key pair is created and the public key added to the GitHub account and local git configuration:

```bash
# generate the key (configuration)
gpg --full-generate-key
> follow the configuration prompt

# list new key
gpg --list-secret-keys --keyid-format=long
> gpg: checking the trustdb
> gpg: marginals needed: 3  completes needed: 1  trust model: pgp
> gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
> /root/.gnupg/pubring.kbx
> ------------------------
> sec   rsa4096/0C579BD96E991F8F 2021-07-10 [SC]
>       E2A688D9A90F0ACE8C30F4BD0C579BD96E991F8F
> uid                 [ultimate] Signer One <signer.one@xhostservice.xyz>
> ssb   rsa4096/A733CB119010B966 2021-07-10 [E]

# export key (select your own key ID) - add this key to you GitHub account
gpg --armor --export 0C579BD96E991F8F > .pubkeys/signer1.gpg.pub
> -----BEGIN PGP PUBLIC KEY BLOCK-----
> mQINBGDqLaMBEADJyBjsdyebTvzFHs6N2noqOFjvD8P9ANaFNPQseEmHHlGqRqgk
> (...)
> flEpbxq/Fo4D1nIOTM9qqMd9D3PHuYY2anU1mFMHV1aqHMMItan56rStMfqCa+sj
> 8X59tQ==
> =vplr
> -----END PGP PUBLIC KEY BLOCK-----

git config --global user.signingkey 0C579BD96E991F8F
```

Now, you can sign your commits using:

```bash
git commit -S -m "signer1: signed commit"
```

GitHub allows you to enforce valid signatures on protected branches and ... tada!? :tada: ... the world has become a safer place.

### The problem

But did it really?
As argued by [Dan Lorenc](https://twitter.com/lorenc_dan) in [this blog post](https://dlorenc.medium.com/should-you-sign-git-commits-f068b07e1b1f), the keys -- that are meant to serve as a new root of trust -- are only authorized by adding them to the GitHub account and thus relying on your GitHub account security.
As a result, if an attacker manages to gain access to your account, that same attacker can also simply add a new key and will forth on be happily signing malicious commits in your name that show up as `verified` by GitHub.
As also outlined in the blog post, a common solution is to have some form of out-of-band verification of the key like a PKI, but that seems to be barely ever the case and as a result the `verified` tag on your commit seems to add little value beyond a false sense of security.

### The solution

However, this statement that an external source of trust is required to make commit signatures useful got me intrigued to create this little project:

> "Unless you store and distribute your public keys using some other system (in a separate trust domain from GitHub), you don’t really gain any protections from having your account compromised here."

Inspired by DNSSEC as opposed to delegating trust to an external party, it is possible to pin the trust to public keys that are directly maintained within the GitHub repository itself.
By adding your public key to the repository say the `.pubkeys` folder with the initial commit, all subsequent commits can be verified against that public key.
A *trusted contributor* is then a contributor with a private key to a public key within the `.pubkeys` folder.

If we go one step further and verify each commit signature against the public keys within the previous commit, we can also add and revoke public keys for new or former contributors by having a trusted contributor add or remove the corresponding public key to/from the `.pubkeys` folder:

```bash
 Step 1  Step 2  Step 3  S...
 verify  verify  verify  v...
 |     \ |     \ |     \ |
C0 ---> C1 ---> C2 ---> C3...
```

Using trusted commits can protect against contributor account compromise or a malicious code plattform provider.

## Howto

To test trusted commits, you can clone this repository:

```bash
git clone https://github.com/xopham/trusted-commit-signatures.git
cd trusted-commit-signatures
```

There is 3 ways to run `verify_commits.sh`:

- directly run it on your machine: `./verify_commits.sh`
> :warning: Please be a bit careful as the code is not extensively tested :wink:
- Build and run it as a docker container: `./docker/build_and_run.sh`
- Run the pre-built container: `docker run -v $(git rev-parse --show-toplevel):/tmp docker.io/xoph/commit-verifier`

The output should looks similar to:

```bash
INFO: Temporary gnupg home '.ephemeral_gnupg' created.
Current Branch: main
Number of commits to verify: 4
Commits: 1e915b5fc5397eaebacff455eca0d3eda7961e71 b1ac78388be4eba7852262704ac430ddcd70dc16 9d9eaf00c505238ead719a49900bfc23ad046971 92d9c78b6d5ca0945ad6576a6e1cd36995313b2d

3 92d9c78b6d5ca0945ad6576a6e1cd36995313b2d
STATUS 0: Verifying commit 9d9eaf00c505238ead719a49900bfc23ad046971: 'feat: add github action.
INFO: git - HEAD is now at 92d9c78b6d5ca0945ad6576a6e1cd36995313b2d.
INFO: Temporary gnupg home '/home/xoph/code/trusted-commit-signatures/.gpg/3' created.
STATUS 0: SUCCESSFUL VAlIDATION of 9d9eaf00c505238ead719a49900bfc23ad046971.

2 9d9eaf00c505238ead719a49900bfc23ad046971
STATUS 1: Verifying commit b1ac78388be4eba7852262704ac430ddcd70dc16: 'xoph: signed commit.
INFO: git - HEAD is now at 9d9eaf00c505238ead719a49900bfc23ad046971.
INFO: Temporary gnupg home '/home/xoph/code/trusted-commit-signatures/.gpg/2' created.
STATUS 1: SUCCESSFUL VAlIDATION of b1ac78388be4eba7852262704ac430ddcd70dc16.

1 b1ac78388be4eba7852262704ac430ddcd70dc16
STATUS 2: Verifying commit 1e915b5fc5397eaebacff455eca0d3eda7961e71: 'update readme.
INFO: git - HEAD is now at b1ac78388be4eba7852262704ac430ddcd70dc16.
INFO: Temporary gnupg home '/home/xoph/code/trusted-commit-signatures/.gpg/1' created.
STATUS 2: SUCCESSFUL VAlIDATION of 1e915b5fc5397eaebacff455eca0d3eda7961e71.

### RESULTS ###
Trust all the commits!?
```

The script fails in case you now make a change and create a commit without signature or with your own key and then run `verify_commits.sh` again.

This repository also contains a GitHub action that checks all PRs for trusted commits.
While this can for example also check all incoming PRs or validate the repository frequently, there seems no way to protect an action from just being removed by the next commit.
Consequently, the commit verification currently has to happen locally.

## Examples

A few simple examples for usage of trusted commit signatures are provided.

### Untrusted commits

As an example for untrusted commits, checkout the `untrusted-commits` branch:

```bash
git checkout untrusted-commits
```

If you run `verify_commits.sh` over the untrusted commits, you will get:

```bash
INFO: Temporary gnupg home '.gpg' created.
Current Branch: untrusted-commits
Number of commits to verify: 5
Commits: 790253d815ff60c57620cda94014e02e32531138 9ddce6a924a113f1fbcffd736483993683f17514 1ed772c057e81a547d1c770c7e63100251036fd0 97dd197a48b3e45bb1c87165a1f5daf3c67c0407 05d0c20738935421c1315024a31e4ffd88e38b21

4 05d0c20738935421c1315024a31e4ffd88e38b21
STATUS 0: Verifying commit 97dd197a48b3e45bb1c87165a1f5daf3c67c0407: 'feat: add github action.
INFO: git - HEAD is now at 05d0c20738935421c1315024a31e4ffd88e38b21.
INFO: Temporary gnupg home '/tmp/.gpg/4' created.
STATUS 0: SUCCESSFUL VAlIDATION of 97dd197a48b3e45bb1c87165a1f5daf3c67c0407.

3 97dd197a48b3e45bb1c87165a1f5daf3c67c0407
STATUS 1: Verifying commit 1ed772c057e81a547d1c770c7e63100251036fd0: 'xoph: signed commit.
INFO: git - HEAD is now at 97dd197a48b3e45bb1c87165a1f5daf3c67c0407.
INFO: Temporary gnupg home '/tmp/.gpg/3' created.
STATUS 1: SUCCESSFUL VAlIDATION of 1ed772c057e81a547d1c770c7e63100251036fd0.

2 1ed772c057e81a547d1c770c7e63100251036fd0
STATUS 2: Verifying commit 9ddce6a924a113f1fbcffd736483993683f17514: 'signer1: unsigned commit.
INFO: git - HEAD is now at 1ed772c057e81a547d1c770c7e63100251036fd0.
INFO: Temporary gnupg home '/tmp/.gpg/2' created.
ERROR: VALIDATION FAILED for 9ddce6a924a113f1fbcffd736483993683f17514.

1 9ddce6a924a113f1fbcffd736483993683f17514
STATUS 3: Verifying commit 790253d815ff60c57620cda94014e02e32531138: 'signer1: signed commit BEFORE key is added.
INFO: git - HEAD is now at 9ddce6a924a113f1fbcffd736483993683f17514.
INFO: Temporary gnupg home '/tmp/.gpg/1' created.
ERROR: VALIDATION FAILED for 790253d815ff60c57620cda94014e02e32531138.

0 790253d815ff60c57620cda94014e02e32531138
Your branch is up to date with 'origin/untrusted-commits'.

### RESULTS ###
ERROR: 2 untrusted commits.
9ddce6a924a113f1fbcffd736483993683f17514: 'signer1: unsigned commit
790253d815ff60c57620cda94014e02e32531138: 'signer1: signed commit BEFORE key is added.
```

### Adding and removing another public key

To see how a public key can be added and removed, checkout the `add-remove-pubkeys` branch:

```bash
git checkout add-remove-pubkeys
```

If you run `verify_commits.sh` over this branch, you will get:

```bash
INFO: Temporary gnupg home '.gpg' created.
Current Branch: trusted-commits
Number of commits to verify: 7
Commits: 013d8c0ff0a882f3bf7852bad2a2432aacbf52d9 f144a153eabb537d8c5c399eb3352a7e04ad165d 3c877ca1e970604f05e98ffbb0ee78f03fb1e4e6 fed793b74f07ded5215134b7496a9ca46d3bfdc5 1ed772c057e81a547d1c770c7e63100251036fd0 97dd197a48b3e45bb1c87165a1f5daf3c67c0407 05d0c20738935421c1315024a31e4ffd88e38b21

6 05d0c20738935421c1315024a31e4ffd88e38b21
STATUS 0: Verifying commit 97dd197a48b3e45bb1c87165a1f5daf3c67c0407: 'feat: add github action.
INFO: git - HEAD is now at 05d0c20738935421c1315024a31e4ffd88e38b21.
INFO: Temporary gnupg home '/tmp/.gpg/6' created.
STATUS 0: SUCCESSFUL VAlIDATION of 97dd197a48b3e45bb1c87165a1f5daf3c67c0407.

5 97dd197a48b3e45bb1c87165a1f5daf3c67c0407
STATUS 1: Verifying commit 1ed772c057e81a547d1c770c7e63100251036fd0: 'xoph: signed commit.
INFO: git - HEAD is now at 97dd197a48b3e45bb1c87165a1f5daf3c67c0407.
INFO: Temporary gnupg home '/tmp/.gpg/5' created.
STATUS 1: SUCCESSFUL VAlIDATION of 1ed772c057e81a547d1c770c7e63100251036fd0.

4 1ed772c057e81a547d1c770c7e63100251036fd0
STATUS 2: Verifying commit fed793b74f07ded5215134b7496a9ca46d3bfdc5: 'xoph: signed commit - add public key of signer1.
INFO: git - HEAD is now at 1ed772c057e81a547d1c770c7e63100251036fd0.
INFO: Temporary gnupg home '/tmp/.gpg/4' created.
STATUS 2: SUCCESSFUL VAlIDATION of fed793b74f07ded5215134b7496a9ca46d3bfdc5.

3 fed793b74f07ded5215134b7496a9ca46d3bfdc5
STATUS 3: Verifying commit 3c877ca1e970604f05e98ffbb0ee78f03fb1e4e6: 'signer1: signed commit AFTER key is added.
INFO: git - HEAD is now at fed793b74f07ded5215134b7496a9ca46d3bfdc5.
INFO: Temporary gnupg home '/tmp/.gpg/3' created.
STATUS 3: SUCCESSFUL VAlIDATION of 3c877ca1e970604f05e98ffbb0ee78f03fb1e4e6.

2 3c877ca1e970604f05e98ffbb0ee78f03fb1e4e6
STATUS 4: Verifying commit f144a153eabb537d8c5c399eb3352a7e04ad165d: 'xoph: signed commit - remove public key of signer1.
INFO: git - HEAD is now at 3c877ca1e970604f05e98ffbb0ee78f03fb1e4e6.
INFO: Temporary gnupg home '/tmp/.gpg/2' created.
STATUS 4: SUCCESSFUL VAlIDATION of f144a153eabb537d8c5c399eb3352a7e04ad165d.

1 f144a153eabb537d8c5c399eb3352a7e04ad165d
STATUS 5: Verifying commit 013d8c0ff0a882f3bf7852bad2a2432aacbf52d9: 'signer1: signed commit AFTER key is removed.
INFO: git - HEAD is now at f144a153eabb537d8c5c399eb3352a7e04ad165d.
INFO: Temporary gnupg home '/tmp/.gpg/1' created.
ERROR: VALIDATION FAILED for 013d8c0ff0a882f3bf7852bad2a2432aacbf52d9.

0 013d8c0ff0a882f3bf7852bad2a2432aacbf52d9
Your branch is up to date with 'origin/add-remove-pubkeys'.

### RESULTS ###
ERROR: 1 untrusted commits.
013d8c0ff0a882f3bf7852bad2a2432aacbf52d9: 'signer1: signed commit AFTER key is removed.
```

## Security considerations

- **Initial commit tampering**: The `Initial commit` does not exhibit a prior commit as trust root and can thus not be verified. An attacker can just inject their own key into the initial commit. A few mitigations for this threat exist:
    - The attack only works without creating noise when the repository is cloned for the first time, soft of trust on first use (TOFU). Rewriting history will create a conflict for each user that cloned the repository prior to tampering. In most practical cases the `main` branch is a protected branch and will maintain a linear history.
    - The initial commit could be rigidly pinned to the creator's public key that could for example be configured into the `commit-verifier` container image and shared separately.
    - The code repository provider (e.g. GitHub) could for example template new projects with the public key of the provider and disallow modifying the initial commit (though that is incompatible with `git`).
- **`verify_commits.sh` tampering**: When the actual verification code (e.g. `verify_commit.sh`) is maintained within the same repository, an attacker could modify the script to for example ignore their malicious commits. This can be mitigated by:
    - Sharing the verification code on a separate system, e.g. as an OS package or as part of git itself.
    - Provisioning a dedicated container image that is to be used for code verification (could also contain the public key for the initial commit).
- **Key revocation complexity**: If a user key is compromised, revocation would require removing the corresponding public key from all repositories which is impractical and slow. Solutions might be:
    - The code repository provider could inform maintainers of key changes within contributor accounts and provide key removal commit templates.
- **Contributors must be trusted**: Essentially, each contributor can add keys for any number of other potential contributors. However:
    - There still is the standard access management and a user authorization is required to push commits.
    - The verification script could warn whenever keys are added or removed from the repository.
    - Editing `.pubkeys` folder could be restricted to maintainers or owners.
- **Malicious contributor removes all keys**: Essentially, a contributor can manage all other keys as well and could for example remove all public keys except their own and lock all others out. Mitigations might be:
    - The initial public key could be made an eternal public key that cannot be removed, i.e. `verify_commits.sh` considers that key valid independent of whether it is still in the `.pubkeys` folder.
    - In most cases, PRs and approvals should mitigate this.
    - Editing `.pubkeys` folder could be restricted to maintainers or owners.
- **Lack of platform validation**: As the commits have to be verified locally, it could happen that untrusted commits are added to a protected branch by accident which would break the trust history.
    - One could allow adding a list of excluded commits that can be edited after the fact and only be appended, but requires a valid signature from a prior signed commit.
    - Code repository providers (e.g. GitHub) could build a verification enforcement for protected branches based on the self-contained trusted-commit signature scheme.
    - The provided GitHub action in this repository allows verification and passing check could be enforced for a protected branch.

## Potential development next steps

1. Implement trust pinning for initial commit to a provided public key, e.g. via `commit-verifier` container.
2. Implement trusted-commit-signatures as git hook to automatically validate upon cloning or pull.
3. Locally maintain verified history to avoid re-evaluating all commits each time.
4. Visualize history of public keys.
5. Inform on changes to `.pubkeys` folder.
