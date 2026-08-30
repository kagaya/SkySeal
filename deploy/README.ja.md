# SkySeal 本番配置手順（Phase 3）

## 標準構成

公開署名サービスと、Google Drive のファイル本文を読むエージェントを別ホストにする。

| ホスト | 保持・処理するもの | 保持しないもの |
|---|---|---|
| 公開 Linux VPS | ORCID iD、Passkey 公開鍵、本人登録証明、ハッシュ、署名証明、SQLite | Drive のファイル本文・ファイル名、Passkey 秘密鍵 |
| 信頼できる Ubuntu 機 | Drive から取得した一時バイト列、非公開エージェント状態、API 秘密情報 | Passkey 秘密鍵、恒久的な原ファイル複製 |
| iPhone / iPad | Passkey と利用者の承認操作 | Drive/GitHub の長期 API トークン |

Drive エージェントから公開サービスへ送るのは、厳格形式のハッシュ一覧と件数だけである。
ファイル名、Drive ID、フォルダ構造は送らない。

固定値は `deploy/production-profile.json` に機械可読形式でも記録している。WebAuthn登録後に
originまたはRP IDを変更すると既存Passkeyが使えなくなるため、変更は新しい本人登録を伴う
移行として扱う。

## 先生が用意するもの

秘密値そのものをチャット、GitHub Issue、Git リポジトリへ貼らないこと。

1. 親ドメイン `excyberlab.net` と、`proof.excyberlab.net` を向けられる Linux VPS。
2. ORCID Public API の client ID / secret。登録 callback は
   `https://proof.excyberlab.net/api/v1/orcid/callback` と完全一致させる。
3. Google Cloud の service account JSON。Drive API v3 を有効にし、監視専用フォルダだけを
   service account のメールアドレスへ閲覧者として共有する。Domain-wide delegation は使わない。
4. `kagaya/SkySeal` のみに限定し `Contents: write` だけを与えた fine-grained GitHub token。
5. iCloudキーチェーンのPasskeyを利用できるiPhoneまたはiPad。本人登録の有効化と、各sealの
   承認時に画面ロック解除によるユーザー確認を行う。

VPS は、1 GB以上のメモリ、固定グローバル IPv4、20 GB以上の永続ディスク、対応中の
Ubuntu LTS、外部パケットフィルターを備える最小構成でよい。外部着信は SSH（接続元を
制限）、HTTP 80、HTTPS 443 だけにする。

## 公開サービスホスト

以下は Ubuntu 系 OS を前提とする。リポジトリは `/opt/skyseal`、専用ユーザーは
`skyseal`、秘密設定は `/etc/skyseal`、状態は `/var/lib/skyseal` に置く。

### VPS 初期設定の自動化

最初に管理ユーザーの公開鍵ログインを別ターミナルから確認する。確認後、次のスクリプトで
OS更新、必要パッケージ、ホスト名、SSHの公開鍵認証限定、UFW、専用ユーザーとディレクトリを
まとめて設定できる。スクリプトは冪等であり、同じVPSで再実行できる。

```bash
sudo bash deploy/bootstrap_vps.sh
```

SSH鍵の初回登録、DNS、再起動、ORCIDやGoogleの秘密情報は自動化しない。スクリプトは
`ubuntu`（または `--admin-user` で指定したユーザー）の `authorized_keys` に有効な公開鍵が
あることを確認してから、パスワード認証とrootログインを無効にする。SSH設定は構文と
実効値の検査に通った場合だけ再読み込みする。実行中の接続は閉じず、完了後に別ターミナルで
公開鍵ログインを再確認する。

すでにOS更新を別途済ませている場合は、パッケージ全体の更新を省略できる。

```bash
sudo bash deploy/bootstrap_vps.sh --skip-upgrade
```

以下はスクリプトが行う内容を個別に確認または復旧するときの手動手順である。

```bash
sudo adduser --system --group --home /nonexistent --no-create-home skyseal
sudo install -d -o root -g root -m 0755 /opt/skyseal
sudo install -d -o skyseal -g skyseal -m 0700 /etc/skyseal
sudo install -d -o skyseal -g skyseal -m 0700 /var/lib/skyseal
```

リポジトリを `/opt/skyseal` に配置した後、Python 仮想環境を作る。

```bash
sudo python3 -m venv /opt/skyseal/.venv
sudo /opt/skyseal/.venv/bin/pip install -r /opt/skyseal/verifier/requirements.txt
sudo install -o skyseal -g skyseal -m 0600 \
  /opt/skyseal/service/env.example /etc/skyseal/service.env
sudoedit /etc/skyseal/service.env
```

`service.env` の ORCID client ID / secret を実値にする。公開URLとRP IDはすでに
`proof.excyberlab.net` に固定してある。
`SKYSEAL_HOST=127.0.0.1` と3個の `SKYSEAL_DEV_*` 無効状態は変えない。

```bash
sudo cp /opt/skyseal/deploy/skyseal.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now skyseal.service
sudo systemctl status skyseal.service --no-pager
```

起動前に systemd の `ExecStartPre` が秘密値を表示せず設定を診断する。失敗した場合は
`sudo journalctl -u skyseal.service --no-pager` で、秘密値を含まない診断結果を確認する。

Caddy の公式パッケージを導入し、`deploy/Caddyfile.example` を
`/etc/caddy/Caddyfile` に配置する。DNS の `proof.excyberlab.net` A/AAAA レコードを
VPS に向け、TCP 80/443
だけを公開する。Python の 8787 番ポートは公開しない。Caddy の access log は有効にしない。
ORCID callback の query に短時間有効な認可 code が含まれるためである。

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
curl -I https://proof.excyberlab.net/
```

## 初回本人登録

1. iPhone / iPad の Safari で `https://proof.excyberlab.net/` を開く。
2. ORCID でログインする。サービスは認証済みORCID iDだけを保持し、OAuthトークンは破棄する。
3. Passkey を登録し、表示されたリカバリーコードをiPhoneの「パスワード」へ保存する。
4. PWA の「パスキーで本人登録を有効化」を押し、Face ID、Touch IDまたは端末コードで
   ユーザー確認済みの署名を行う。
5. 画面が「本人登録: 有効」になったことを確認する。

この操作で公開可能な `identity-activation.json` が生成される。内容はORCID、genesisの
ダイジェスト、固定RP ID、nonce、作成時刻、およびPasskey署名であり、raw credential IDや
user handleは含まない。`identity-genesis.json` は任意で保管してよいが、OpenPGP署名や
署名用PCは本番運用の必須条件ではない。

## Drive エージェントホスト

研究室内など、原データを読ませてよい常時稼働 Ubuntu 機にだけ配置する。WSL はスリープや
ログアウトで停止し得るため、常時監視ホストにはしない。

```bash
sudo adduser --system --group --home /nonexistent --no-create-home skyseal
sudo install -d -o root -g root -m 0755 /opt/skyseal
sudo install -d -o skyseal -g skyseal -m 0700 /etc/skyseal
sudo install -d -o skyseal -g skyseal -m 0700 /var/lib/skyseal
sudo python3 -m venv /opt/skyseal/.venv
sudo /opt/skyseal/.venv/bin/pip install -r /opt/skyseal/verifier/requirements.txt
sudo /opt/skyseal/.venv/bin/pip install -r /opt/skyseal/drive_agent/requirements.txt
sudo install -o skyseal -g skyseal -m 0600 \
  /opt/skyseal/drive_agent/env.example /etc/skyseal/agent.env
sudoedit /etc/skyseal/agent.env
```

OS パッケージとして `flock` と OpenTimestamps の `ots` command を用意する。
次の3ファイルを `/etc/skyseal` に配置する。

- `google-service-account.json`（600）
- `github.token`（1行、600）
- `drive-agent.token`（1行、600）

3秘密ファイルは `skyseal:skyseal` 所有、mode 600 にする。専用ユーザー以外へ
読み取り権限を与えない。

Drive agent token は、本人登録を有効化した後、公開サービスホストで一度だけ生成する。

```bash
sudo -u skyseal /opt/skyseal/.venv/bin/python \
  /opt/skyseal/service/create_agent_token.py \
  --database /var/lib/skyseal/skyseal.sqlite3 \
  --orcid 0000-0000-0000-0000 \
  --output /var/lib/skyseal/drive-agent.token.export
```

この export ファイルを安全な手段でエージェントホストの
`/etc/skyseal/drive-agent.token` へ一度だけ転送し、`skyseal:skyseal`、mode 600 にする。
転送確認後、公開サービスホスト上の export ファイルは削除する。
`agent.env` の公開ホスト名とRP IDは `proof.excyberlab.net` に固定済みである。
Drive folder ID を実値にする。

```bash
sudo cp /opt/skyseal/deploy/skyseal-drive-agent.service /etc/systemd/system/
sudo cp /opt/skyseal/deploy/skyseal-drive-agent.timer /etc/systemd/system/
sudo cp /opt/skyseal/deploy/skyseal-ots-upgrade.service /etc/systemd/system/
sudo cp /opt/skyseal/deploy/skyseal-ots-upgrade.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start skyseal-drive-agent.service
sudo journalctl -u skyseal-drive-agent.service --no-pager
sudo systemctl enable --now skyseal-drive-agent.timer skyseal-ots-upgrade.timer
```

## Phase 4 受入試験

1. 専用 Drive フォルダ直下へ、公開しても内容を推測されないテストファイルを1個置く。
2. 120秒変更せず待つ。
3. iPhone / iPad の PWA に、ファイル名なしで到着時刻とハッシュ件数だけが出ることを確認する。
4. Passkey で承認する。
5. GitHub の `evidence/YYYY/MM/<opaque-seal-id>/` に、ハッシュ一覧、seal署名、
   `identity-genesis.json`、`identity-activation.json`、両OpenTimestamps証明、および
   manifestが公開されることを確認する。
6. 元ファイルを第三者へ渡さずに公開 verifier が成立し、別途同一ファイルを与えた場合だけ照合できることを確認する。

本番の論文・データセットを入れるのは、このテストに合格してからにする。
