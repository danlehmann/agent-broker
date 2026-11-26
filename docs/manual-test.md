# Manual test

Automated tests impersonate accounts. This checks the real thing: kernel identity, file
permissions and GitHub. You need the broker account, two agent accounts, and a scratch GitHub
repo with a fine-grained token (contents and pull requests: write; actions: read).

## Set up

```sh
cargo build --release --features dev-seed
sudo install -m 755 target/release/agent-broker /usr/local/bin/
sudo useradd --system --create-home --shell /usr/sbin/nologin agent-broker
sudo chmod 700 ~agent-broker
sudo install -d -o agent-broker -m 755 /run/agent-broker

b() { sudo -u agent-broker -H agent-broker "$@"; }
b dev add-user --user daniel
b dev add-repo --user daniel --repo OWNER/NAME --prefix daniel/    # paste the token
b daemon                                                           # leave running
```

Link an agent account (A); leave the other one (B) unlinked:

```sh
b dev link-code --user daniel
sudo -u A -H agent-broker link                                     # type the code
b dev confirm --user daniel --account A
```

## Check

- [ ] `sudo -u B -H agent-broker mcp` with
      `{"id":1,"method":"tools/call","params":{"name":"github_repos"}}` says the account is
      not linked. The same as A lists the repo.
- [ ] As A: reading `~agent-broker/data` fails, and so does creating or removing a file in
      `/run/agent-broker`.
- [ ] As A, through an agent: push a `daniel/` branch, fetch, open a PR (it is a draft),
      comment, read CI status and logs.
- [ ] Pushing to a branch without the prefix is refused.
- [ ] While a push of a large branch runs, `ps auxww | grep -i -e basic -e github_pat` as A
      shows no token.
- [ ] `sudo grep -c github_pat ~agent-broker/data/broker.db-wal ~agent-broker/data/broker.db`
      finds the token only as stored credential: none in the `audit` table.
- [ ] Starting the daemon with sudo as root, with a data dir of mode 755, or twice is refused.
- [ ] Deleting and recreating A under the same uid but another name makes it unlinked.

Repeat on macOS; nothing has been compiled or run there yet.
