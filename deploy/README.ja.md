# SkySeal 本番配置手順（Phase 3）

本番構成を短時間で思い出すための要約、Windows/macOS/Linuxの管理端末設定、定常更新、
障害対応、バックアップ、秘密情報の境界は
[`../docs/operations-and-maintenance.ja.md`](../docs/operations-and-maintenance.ja.md)を参照する。
この文書は主に初回構築と受入試験を扱う。

## 標準構成

標準運用では、公開署名サービスとGoogle Driveエージェントを同じ常時稼働VPSへ置く。
ただし別Linuxユーザーと秘密ディレクトリで分離する。原ファイルの正本はGoogle Driveに
残り、エージェントはハッシュ計算時に内容をストリームで読むだけで、原ファイルの複製を
VPSディスクへ保存しない。

| ホスト | 保持・処理するもの | 保持しないもの |
|---|---|---|
| 公開 Linux VPS (`skyseal`) | ORCID iD、Passkey 公開鍵、本人登録証明、ハッシュ、署名証明、SQLite | Drive API鍵、Driveのファイル名、Passkey秘密鍵 |
| 同一VPSのエージェント (`skyseal-agent`) | Driveからストリーム取得した一時バイト列、非公開処理状態、専用API秘密情報、任意の非公開台帳root名 | Passkey秘密鍵、恒久的な原ファイル複製 |
| iPhone / iPad | Passkey と利用者の承認操作 | Drive/GitHub の長期 API トークン |

Drive エージェントから公開サービスへ送るのは、厳格形式のハッシュ一覧と件数だけである。
ファイル名、Drive ID、フォルダ構造は公開サービスへ送らない。任意の非公開台帳を有効にした場合も、
公開サービスへ送るのはsalt付きreceiptのSHA-256だけである。

同一VPS方式では、ホストまたはroot権限が侵害されると専用Inboxを読み取られる可能性がある。
Googleサービスアカウントは `SkySeal Inbox` だけのViewerとし、Domain-wide delegationを
禁止する。VPSも原ファイル内容を一切読めない境界が必要な場合だけ、エージェントを研究室の
別Ubuntu機へ配置する。

固定値は `deploy/production-profile.json` に機械可読形式でも記録している。WebAuthn登録後に
originまたはRP IDを変更すると既存Passkeyが使えなくなるため、変更は新しい本人登録を伴う
移行として扱う。

## 先生が用意するもの

秘密値そのものをチャット、GitHub Issue、Git リポジトリへ貼らないこと。

1. 親ドメイン `excyberlab.net` と、`proof.excyberlab.net` を向けられる Linux VPS。
2. ORCID Public API の client ID / secret。登録 callback は
   `https://proof.excyberlab.net/api/v1/orcid/callback` と完全一致させる。
3. Google Cloud の service account JSON。Drive API v3（非公開台帳を使う場合はSheets APIも）を有効にし、監視専用フォルダだけを
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

### 定常更新

初回構築と秘密情報の配置が完了したVPSでは、以後の更新を次の一コマンドにまとめる。

```bash
sudo skyseal-update
```

このコマンドは `origin/main` のfast-forward取得、両SQLiteのオンラインバックアップ、
Python依存関係とsystemd unitの更新、既存証拠のVPS配置、サービス再起動、公開URLの
疎通確認を順に行う。Caddyfileは最後に配置したハッシュを記録し、手修正がある場合は
上書きせず停止する。バックアップは各状態ディレクトリの `backups/` にcommit単位で
mode 600保存する。

更新コマンド自体を初めて登録するときだけ、最新のcheckoutから次を実行する。

```bash
sudo install -o root -g root -m 0755 \
  /opt/skyseal/deploy/skyseal-update /usr/local/sbin/skyseal-update
sudo skyseal-update
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

## 同一VPSへのDriveエージェント自動配置

次の3秘密ファイルを一時配置してから、一つのスクリプトを実行する。

- GoogleサービスアカウントJSON：`SkySeal Inbox` だけをViewer共有したアカウント
- GitHub token：`kagaya/SkySeal` の `Contents: write` だけを持つ一行ファイル
- Drive agent token：本人登録後にVPSで生成した一行ファイル

入力ファイルは所有者以外が読めないmode 600または400にする。スクリプトは入力を
`/etc/skyseal-agent` へmode 600でコピーするが、元ファイルは削除しない。

```bash
sudo bash /opt/skyseal/deploy/bootstrap_agent_vps.sh --google-key /path/to/google-service-account.json --github-token /path/to/github.token --agent-token /var/lib/skyseal/drive-agent.token.export --drive-folder-id DRIVE_FOLDER_ID
```

このスクリプトは次をまとめて行う。

1. 専用Linuxユーザー `skyseal-agent` とmode 700の設定・状態ディレクトリを作る。
2. 公開サービスとは別のPython仮想環境へDrive APIとOpenTimestampsを導入する。
3. 秘密ファイルと固定設定をmode 600で配置する。
4. systemd sandbox設定を検査し、初回Drive scanを実行する。
5. VPS公開領域 `/var/lib/skyseal-public` を作成する。
6. 1分ごとの監視timerと毎日のOpenTimestamps upgrade timerを有効化する。

公開Webサービスの `skyseal` ユーザーは `/etc/skyseal-agent` を読めない。systemdサービスは
原ファイルを書き出さず、非公開SQLiteと作業領域を `/var/lib/skyseal-agent` に保持する。
公開専用の `/var/lib/skyseal-public` には検証済み証拠だけを先に不可変保存し、GitHubは
その後に作るミラーとして扱う。公開一覧は `https://proof.excyberlab.net/proofs/` で確認できる。

Drive agent token は、本人登録を有効化した後、公開サービスホストで一度だけ生成する。

```bash
sudo -u skyseal /opt/skyseal/.venv/bin/python \
  /opt/skyseal/service/create_agent_token.py \
  --database /var/lib/skyseal/skyseal.sqlite3 \
  --orcid 0000-0000-0000-0000 \
  --output /var/lib/skyseal/drive-agent.token.export
```

自動配置の成功後、最終配置ファイルと一致することを確認してから、一時配置した秘密ファイルと
`/var/lib/skyseal/drive-agent.token.export` を削除する。

## Phase 4 受入試験

1. 専用 Drive フォルダ直下へ、公開しても内容を推測されないテストファイルを1個置く。
2. 120秒変更せず待つ。
3. iPhone / iPad の PWA に、ファイル名なしで到着時刻、ハッシュ件数、ひまわり観測時刻が
   出ることを確認する。
4. Passkey で承認する。
5. `https://proof.excyberlab.net/proofs/` に証拠が現れ、各証拠ファイルをVPSから取得できることを確認する。
6. GitHub の `evidence/YYYY/MM/<opaque-seal-id>/` に、ハッシュ一覧、seal署名、
   `identity-genesis.json`、`identity-activation.json`、両OpenTimestamps証明、
   `sky-witness.json`、`sky-witness.jpg`、およびmanifestが公開されることを確認する。
7. 公開詳細ページにひまわり赤外全球画像と観測時刻が表示されることを確認する。
8. 元ファイルを第三者へ渡さずに公開 verifier が成立し、別途同一ファイルを与えた場合だけ照合できることを確認する。

本番の論文・データセットを入れるのは、このテストに合格してからにする。
