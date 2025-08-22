README - 検証手順 / Verification Guide
Generated on: 2025-08-23T00:04:16+09:00

対象ファイル / Target file:
- 原本 / Original:           20250823_0002_public.txt
- 署名 / Signature (.asc):    20250823_0002_public.txt.asc
- OTS 封緘 / OTS stamp:       20250823_0002_public.txt.asc.ots 
- 公開鍵 / Public key:        publickey_kkagaya@mail.kitami-it.ac.jp.asc

鍵情報 / Key info:
- Selector given: kkagaya@mail.kitami-it.ac.jp
- Fingerprint:    85F79058BD83EB3889DEF766B065C54586067E2E

ハッシュ / Hashes (SHA-256):
- 20250823_0002_public.txt: 161b9c2bdf18360aafff4c2352b94050bffee81734d483309a6abd6bb982b3c0
- 20250823_0002_public.txt.asc:  32ba6927fb0966cc734ef286ad9e0d4bc8e566cfecedd9588953822f9f1559d9

==============================
[JA] 検証手順
==============================
1) 公開鍵の指紋確認（以下の FPR と一致すること）:
   85F79058BD83EB3889DEF766B065C54586067E2E
   gpg --show-keys --fingerprint "publickey_kkagaya@mail.kitami-it.ac.jp.asc"
2) 公開鍵のインポート:
   gpg --import "publickey_kkagaya@mail.kitami-it.ac.jp.asc"
3) GPG 署名の検証:
   gpg --verify "20250823_0002_public.txt.asc" "20250823_0002_public.txt"
4) OTS 検証 (あれば):
   ots verify "20250823_0002_public.txt.asc.ots"

==============================
[EN] Verification Steps
==============================
1) Check the fingerprint matches exactly:
   85F79058BD83EB3889DEF766B065C54586067E2E
   gpg --show-keys --fingerprint "publickey_kkagaya@mail.kitami-it.ac.jp.asc"
2) Import public key:
   gpg --import "publickey_kkagaya@mail.kitami-it.ac.jp.asc"
3) Verify GPG signature:
   gpg --verify "20250823_0002_public.txt.asc" "20250823_0002_public.txt"
4) Verify OTS proof (if present):
   ots verify "20250823_0002_public.txt.asc.ots"
