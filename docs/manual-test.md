# Manual test

Automated tests impersonate accounts. This checks the real thing: kernel identity, file
permissions and GitHub. You need a scratch GitHub repo with a fine-grained token (contents and
pull requests: write; actions: read) and four accounts, named here by role:

- `BROKER`: a system account that only runs the daemon; its home is mode 700
- `YOU`: your own login, the broker user that owns the repo entry
- `A` and `B`: two agent accounts, without sudo and outside groups such as `docker` and `lxd`

## Set up

```sh
cargo build --release
sudo install -m 755 target/release/agent-broker /usr/local/bin/
sudo useradd --system --create-home --shell /usr/sbin/nologin BROKER
sudo chmod 700 ~BROKER
sudo install -d -o BROKER -m 755 /run/agent-broker

b() { sudo -u BROKER -H agent-broker "$@"; }
b daemon                                                           # leave running
b init                                                             # in another terminal
```

`init` asks for the name of the first admin (`YOU`) and prints a one-time link and the line
that forwards the web interface. Open the link, set a password and log in. Then, in the
browser:

- **Repos:** add `OWNER/NAME` with the token and the branch prefix `YOU/`.
- **Linked accounts:** get a link code, run `sudo -u A -H agent-broker link`, type the code,
  and confirm on the page. Leave `B` unlinked.

## Check

- [ ] `sudo -u B -H agent-broker mcp` with
      `{"id":1,"method":"tools/call","params":{"name":"github_repos"}}` says the account is
      not linked. The same as A lists the repo.
- [ ] As A: reading `~BROKER/data` fails, and so does creating or removing a file in
      `/run/agent-broker`.
- [ ] As A, through an agent: push a `YOU/` branch, fetch, open a PR (it is a draft),
      comment, read CI status and logs.
- [ ] Pushing to a branch without the prefix is refused.
- [ ] While a push of a large branch runs, `ps auxww | grep -i -e basic -e github_pat` as A
      shows no token.
- [ ] `sudo grep -c github_pat ~BROKER/data/broker.db-wal ~BROKER/data/broker.db`
      finds the token only as stored credential: none in the `audit` table.
- [ ] `/run/agent-broker/admin.sock`, opened without the forward's port and name (for
      example `curl --unix-socket ... http://other.example/`), is refused; a second browser
      profile that has the link of a logged-in page but no cookie gets the login page.
- [ ] No page shows a token, and `sudo grep -c` for the session cookie's value in
      `~BROKER/data/broker.db*` finds nothing.
- [ ] `b reset-login YOU` prints a link that sets a new password and ends the old sessions.
- [ ] Starting the daemon with sudo as root, with a data dir of mode 755, or twice is refused.
- [ ] Deleting and recreating A under the same uid but another name makes it unlinked.

Repeat on macOS; nothing has been compiled or run there yet.
