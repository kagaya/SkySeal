# SkySeal Windows Desktop 0.2 — 開発版

SkySeal の処理を Windows PC 内で実行するデスクトップアプリです。対象ファイルの保存コピー、SHA-256 集合、本人承認の署名、ひまわり画像、時刻証明、処理履歴をローカルに保存します。既存の SkySeal VPS、Google Drive、公開サイトへの接続は通常の封緘に必要ありません。

この版の新しい証拠形式は **`skyseal-local-desktop-v0.1-draft`** です。既存 Web サービス用の資格情報をそのまま移す方式ではありません。Windows 用インストーラーをビルドする設定は含まれますが、配布用コード署名と Windows Hello／ORCID の実機受け入れ試験は別の完了条件です。

## インストール

1. [Windows ビルドの実行一覧](https://github.com/kagaya/SkySeal/actions/workflows/desktop-windows.yml)で、対象のコミットの成功した実行を開きます。
2. 成果物 `SkySeal-Windows-x64-development-unsigned` をダウンロードして ZIP を展開します。GitHub へのログインが必要です。
3. ZIP 内の `SkySeal_0.2.0_x64-setup.exe` を実行し、現在の Windows ユーザー用にインストールします。開発用の Python、Node.js、Rust は不要です。
4. SkySeal を起動し、以下の「最初の設定」を行います。本人登録前でもファイルの保存コピーと履歴の確認は利用できます。

この開発版インストーラーは未署名のため、Windows に発行元未確認の警告が表示される場合があります。成果物には照合用の `SHA256SUMS.txt` も含めます。

## 利用する外部サービス

| 接続先 | 用途 | 送信する情報 |
|---|---|---|
| ORCID | 初回の本人登録、認証署名鍵の取得 | 認証要求、公開鍵に結び付いた nonce。パスワードは ORCID の標準ブラウザ画面に入力 |
| 気象庁 | ひまわり赤外画像の取得 | 公開画像の取得要求 |
| OpenTimestamps のカレンダー | タイムスタンプ要求と確認待ち証明の更新 | 封緘証拠から計算したコミットメント |
| Blockstream、mempool.space | Bitcoin ブロック情報の照合 | 公開ブロックの高さ・ハッシュ |

対象ファイルの中身、ローカルのファイル名・保存パスは、これらの処理のために外部へ送信しません。インストール時に WebView2 がない場合は、インストーラーが Microsoft の配布元から取得します。

時刻証明は、二つのブロック情報提供元の一致、ブロックヘッダーのハッシュと Proof of Work、OTS のコミットメント、6 確認以上を検査する **提供元情報を利用した検証**です。Bitcoin の全チェーンを自前のノードで検証する方式ではなく、結果には `trust_mode: https_explorers` と `full_chain_validated: false` を残します。通信不能や不一致を時刻確認済みとして扱いません。

## 最初の設定

1. Windows 10／11 x64 で Windows Hello の PIN、顔・指紋、または User Verification に対応した FIDO2 キーを利用できる状態にします。実機での確認が必要です。
2. ORCID の Public API クライアントを登録し、戻り先を **`https://localhost:24731/callback`** と完全一致で登録します。アプリの設定にクライアント ID を入力します。この方式ではクライアントの秘密情報をアプリに入力・同梱しません。
3. 設定画面で、この PC 用のローカル HTTPS 証明書を作成し、内容を確認して Windows の現在のユーザーの証明書ストアへ登録します。証明書の信頼登録は明示操作で行います。
4. 本人登録を開始します。Windows の認証器で新しい鍵を作成し、標準ブラウザで ORCID にログインし、鍵と ORCID の対応を承認します。

ORCID の本番環境が登録した戻り先を受け付け、通常のブラウザで証明書警告を回避する操作なしにアプリへ戻れることを確認してください。ローカル HTTPS の受付は認証中だけ起動し、ポート 24731 のループバックアドレスだけで待ち受けます。ほかのアプリが同じポートを使用している場合は認証を開始できません。

証明書は PC ごとに生成する自己署名のサーバー用証明書で、対象は localhost とループバック IP だけです。登録先は `CurrentUser/Root` で、有効期間は 1 年です。削除するときは Windows の「ユーザー証明書の管理」で、アプリが示す拇印と一致する **SkySeal local callback** 証明書だけを削除します。ほかの証明書を一括削除しないでください。

## 通常の操作

1. 「封緘」でファイルまたはフォルダーを選択します。
2. アプリが保存コピーを作り、その実バイト列のハッシュを計算します。内容が変わるファイルやリンクは受け付けません。
3. 対象一覧を確認し、封緘を実行します。新しいひまわり画像を取得し、今回の内容に対する Windows Hello／FIDO2 の承認署名を取得します。
4. 署名済みの証拠を保存し、OpenTimestamps に時刻証明を要求します。
5. 「履歴」から確認待ちの処理を再開し、証拠 ZIP を書き出せます。
6. 「検証」で証拠 ZIP または証拠フォルダーと、必要に応じて比較対象ファイルを選びます。

「署名済み」と「時刻証明確認済み」は異なる状態です。アプリを閉じている間は確認処理が進みません。この初版では次回起動後に「履歴」の確認ボタンから再開します。起動時の自動確認・常駐処理は未実装です。再試行のために署名済みの内容を作り直すことはありません。

ファイルの集合は、重複を除いた SHA-256 の集合として封緘されます。公開証拠は元のファイル名、ディレクトリー構造、同一内容のファイルの個数を証明しません。ファイル名と保存コピーの対応は PC 内の履歴に保持します。

## 証拠の受け渡しと鍵の保管

書き出す証拠 ZIP には、ハッシュ集合、封緘署名、ORCID と公開鍵の対応、本人登録の承認署名、ひまわり画像、入手済みの OTS 証明、manifest が入ります。元ファイル、元のパス、認証器の生の credential ID、ORCID の access token は入れません。

公開する ORCID の ID token は、ORCID 署名付きの歴史的な本人登録情報として保存します。短期 access token や、現在ログインできることの証明として使用しません。検証側では、信頼する ORCID クライアント ID を別途指定し、ORCID の公開署名鍵を信頼できる取得元から取得します。証拠内の任意の鍵を信頼元として採用しません。ORCID が古い署名鍵を公開しなくなった場合、将来の検証には独立に保全した鍵の信頼情報が必要になるため、この初版だけで無期限の本人証明検証を保証しません。

Windows Hello／FIDO2 の秘密鍵は認証器が管理します。データフォルダーのバックアップだけで、その秘密鍵が別 PC に復元されるとは扱いません。鍵を失っても過去の証拠は公開鍵で検証できますが、新たな封緘には新しい本人登録が必要です。既存の鍵からの継承、複数端末同期、鍵の復旧ワークフローは初版の実装範囲外です。

公開証拠で確認できるのは、登録した鍵による署名と、その署名が覆う UP／UV フラグです。登録時に認証器の attestation を要求しないため、公開証拠だけから特定のハードウェア・生体認証方式・アプリ実行ファイルを証明するものではありません。

## Windows でのビルド

開発時に必要なのは、64 bit の Python 3.12、Node.js 22、Rust stable（MSVC）、Visual Studio Build Tools の C++ デスクトップ開発機能、WebView2 です。利用者の PC には Python／Node.js／Rust／WSL の導入を要求しません。

リポジトリのルートで PowerShell を開き、実行します。

```powershell
./desktop/scripts/build-windows.ps1
```

スクリプトは `desktop/.venv` を作り、固定した直接依存パッケージを入れ、デスクトップ用テストを実行します。Python エンジンを PyInstaller で単一の実行ファイルへまとめ、実際の同梱実行ファイルで OTS 証明の読み書き・対象一致・改変拒否、日本語パスの取り込み、再起動後の履歴を検査してから、Tauri の NSIS インストーラーを作成します。

タイムスタンプ処理は `opentimestamps` ライブラリーを直接利用します。外部の `ots` コマンド、Bitcoin ウォレット、Bitcoin RPC、別途の OpenSSL DLL を必要としません。ブロックヘッダーとハッシュを扱うために `python-bitcoinlib` のコア部分を同梱します。

出力先は次のとおりです。

- インストーラー：`desktop/src-tauri/target/release/bundle/nsis/`
- エンジン：`desktop/src-tauri/binaries/desktop-engine-x86_64-pc-windows-msvc.exe`

エンジンだけをビルドする場合：

```powershell
./desktop/scripts/build-windows.ps1 -EngineOnly
```

依存パッケージの導入済み環境で再ビルドする場合は `-SkipDependencyInstall` を使用できます。これは `.venv` と `node_modules` の依存関係が既に揃っている場合のオプションです。

開発画面を起動する場合：

```powershell
./desktop/.venv/Scripts/Activate.ps1
cd desktop
npm ci
npm run dev
```

開発時の Tauri は `python -m desktop.engine` を実行し、配布版は同梱した `desktop-engine.exe` を実行します。

## CI と検証範囲

`.github/workflows/desktop-windows.yml` は、次の二つを分離して実行します。

- Ubuntu：既存の verifier／service／CLI／Drive agent とデスクトップの回帰試験。既存テストには POSIX の権限や bash に依存するものがあります。
- Windows x64：デスクトップ用テスト、同梱エンジンのスモークテスト、NSIS インストーラー作成、実際のインストールと GUI 起動。

インストール後の試験は専用の空の保存領域を使い、GUI のウィンドウと、画面から同梱エンジンを呼び出した結果のデータベース作成を検査します。UI Automation が利用できる環境では、動的な日本語の初期状態表示と操作ボタンも検査します。本人登録や証明書の信頼登録は自動実行しません。診断結果は別の成果物 `SkySeal-Windows-installed-smoke` に保存します。

GitHub Actions の成果物 `SkySeal-Windows-x64-development-unsigned` にインストーラーと SHA-256 一覧を保存します。公開リリースへの自動掲載は行いません。現在の設定は配布用コード署名を行いません。

CI の Windows Server と、自動テスト用の認証器データでは、利用者の Windows Hello 操作や ORCID の本番ログインは検証できません。配布前の実機試験では以下を確認します。

| 条件 | 合格条件 |
|---|---|
| 新規 Windows PC | インストールし、開発用ランタイムなしで起動する |
| 本番 ORCID 認証 | 標準ブラウザからローカル HTTPS へ戻り、署名・state・nonce が検証される |
| Windows Hello／FIDO2 | 承認後だけ封緘が成立し、取消・タイムアウト・UV 不成立は拒否される |
| 通信断・再起動 | 保存済みの対象と署名を保持し、同じ処理を再開できる |
| 別 PC での検証 | 外部の SkySeal サーバーや元 PC の秘密データなしに検証する |
| 改変した証拠 | ハッシュ、署名、本人登録、画像の改変を拒否する |
| 時刻証明 | 確認待ち、提供元接続不能、検証済みを区別する |

## 主なコード

- `engine/core.py`：ローカル保存・履歴・処理の再開
- `engine/proof.py`：ローカル版証拠形式と独立検証
- `engine/windows_auth.py`：Windows native WebAuthn API
- `engine/orcid_auth.py`：ORCID、ローカル HTTPS、ID token 検証
- `engine/ots.py`／`engine/bitcoin_verify.py`：時刻証明の取得・更新・検証
- `ui/`：日本語の操作画面
- `src-tauri/`：固定したエンジン呼び出しと Windows ファイル選択

デバッグ用の保存先は、環境変数 `SKYSEAL_DESKTOP_DATA_DIR` で専用の一時ディレクトリーに変更できます。通常運用のデータに対して自動テストを実行しないでください。
