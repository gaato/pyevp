# PyEVP

[![Documentation](https://app.readthedocs.org/projects/pyevp/badge/?version=latest)](https://docs.pyevp.dev/ja/latest/)
[![CI](https://github.com/gaato/pyevp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gaato/pyevp/actions/workflows/ci.yml)
[![spec: draft-hardt-02](https://img.shields.io/badge/spec-draft--hardt--02-blue)](https://github.com/dickhardt/email-verification)
![status: alpha](https://img.shields.io/badge/status-alpha-orange)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/gaato/pyevp/blob/main/LICENSE)

[English](https://github.com/gaato/pyevp/blob/main/README.md)

PyEVP は、**Email Verification Protocol**（EVP）の Python ライブラリです。リライングパーティー（RP）
としてトークンを検証することも、自分のメールドメイン向けにトークンを発行することもできます。EVP では、
ブラウザーがユーザーのメールプロバイダーから「このアドレスを管理している」ことを示すトークンを受け取り、
サーバーがそれを検証します。確認メールを往復させずにメールアドレスを確認できます。

## ステータス

アルファ版です。プロトコル（[draft-hardt-email-verification]、[WICG Email Verification API]）と
ブラウザーの対応（Chrome のオリジントライアル）はまだ変わり続けています。PyEVP は変わりうる部分を
バージョン付きの `Profile` にまとめ、仕様の変更に追従できるようにしています。

[draft-hardt-email-verification]: https://github.com/dickhardt/email-verification
[WICG Email Verification API]: https://github.com/WICG/email-verification

## インストール

```sh
pip install "pyevp[all]"   # core + dnspython + httpx adapters
```

コアの依存は joserfc と idna だけです。`[all]` を付けると、`Verifier.default()` が使う DNS と HTTP
のアダプターも入ります。

## 使い方

セッションに保存した nonce をフォームに埋め込んでおき、送信されたトークンを検証します。

```python
from pyevp import Verifier, EVPError, generate_nonce

verifier = Verifier.default(audience="https://example.com")  # your origin

try:
    result = verifier.verify(form["evt"], nonce=session.pop("evp_nonce"), email=form["email"])
except EVPError as exc:
    ...  # exc.code is a stable ErrorCode, e.g. "nonce_mismatch"; fall back to email confirmation
else:
    result.email, result.issuer  # verified
```

検証に失敗すると `EVPError` が送出され、`exc.code` で理由がわかります。失敗したときは、既存の
確認メールによる検証にフォールバックするのが安全です。非同期版の `AsyncVerifier` も同じ API で
使えます。

## ドキュメント

- 日本語: <https://docs.pyevp.dev/ja/latest/>（翻訳されていない部分は英語で表示されます）
- English: <https://docs.pyevp.dev/en/latest/>

## ライセンス

[MIT](https://github.com/gaato/pyevp/blob/main/LICENSE)
