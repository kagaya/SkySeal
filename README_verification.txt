README - 検証手順 / Verification Guide
Generated on: 2025-08-19T22:51:21+09:00

対象ファイル / Target file:
- 原本 / Original:           20250819a.txt
- 署名 / Signature (.asc):    20250819a.txt.asc
- OTS 封緘 / OTS stamp:       20250819a.txt.asc.ots 
- 公開鍵 / Public key:        publickey_kkagaya@mail.kitami-it.ac.jp.asc

鍵情報 / Key info:
- GPG_UID: kkagaya@mail.kitami-it.ac.jp
- Fingerprint: 85F79058BD83EB3889DEF766B065C54586067E2E

ハッシュ / Hashes (SHA-256):
- 20250819a.txt: 9284912abde599074df0333aa67a07edb0b627b234789e764dc40c53b4b292a3
- 20250819a.txt.asc:  b0f409f818299f050890ee852bfe331481041d9cae5c8ed987191f06990b4db2

==============================
[JA] 検証手順
==============================
1) 公開鍵の指紋確認:
   gpg --show-keys --fingerprint "publickey_kkagaya@mail.kitami-it.ac.jp.asc"
2) 公開鍵のインポート:
   gpg --import "publickey_kkagaya@mail.kitami-it.ac.jp.asc"
3) GPG 署名の検証:
   gpg --verify "20250819a.txt.asc" "20250819a.txt"
4) OTS 検証 (あれば):
   ots verify "20250819a.txt.asc.ots"

==============================
[EN] Verification Steps
==============================
1) Check fingerprint:
   gpg --show-keys --fingerprint "publickey_kkagaya@mail.kitami-it.ac.jp.asc"
2) Import public key:
   gpg --import "publickey_kkagaya@mail.kitami-it.ac.jp.asc"
3) Verify GPG signature:
   gpg --verify "20250819a.txt.asc" "20250819a.txt"
4) Verify OTS proof:
   ots verify "20250819a.txt.asc.ots"
