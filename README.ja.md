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

**ドキュメント: <https://docs.pyevp.dev/ja/latest/>** · **デモ: <https://pyevp.dev/demo>**

> **ステータス: アルファ版。** プロトコル（[draft-hardt-email-verification]、[WICG Email Verification API]）は
> まだ変わり続けています。PyEVP は変わりうる部分をバージョン付きの `Profile` にまとめ、仕様の変更に追従します。

- **ブラウザー:** Chrome で `chrome://flags/#email-verification-protocol` を有効にするか、
  オリジントライアルに登録したサイトで使えます。Chrome 154 で動作を確認しています。ほかのブラウザーは
  トークンを送りません。
- **メールプロバイダー:** 現在は Gmail がトークンを発行します。自分のドメインでも `pyevp.issuer` で
  発行できます。
- **Python:** 3.11 以降。

[draft-hardt-email-verification]: https://github.com/dickhardt/email-verification
[WICG Email Verification API]: https://github.com/WICG/email-verification

## インストール

```sh
pip install "pyevp[dns,httpx2]"   # core + the DNS and HTTP adapters
```

コアの依存は joserfc と idna だけです。`[dns,httpx2]` を付けると、`Verifier.default()` が使うアダプターが
入ります。httpx も使えます（[DNS、HTTP とキャッシュ](https://docs.pyevp.dev/ja/latest/guides/transport.html)）。
`[all]` を付けると、Django 連携とコマンドラインも入ります。

## 使い方

1. セッションに保存した nonce をフォームに埋め込みます。

   ```python
   from pyevp import SessionNonces, token_input

   nonce = SessionNonces(session).issue()  # Flask、Starlette、Django のセッションで使える
   ```

   ```html
   <input type="email" name="email" autocomplete="email">
   <input type="hidden" name="evt" autocomplete="email-verification-token" nonce="{{ nonce }}">
   ```

   （hidden input は `token_input(nonce)` でも出力できます。）

2. ユーザーがアドレスを選ぶと、ブラウザーが `evt` に `<EVT>~<KB-JWT>` を入れます。
3. 送信されたら検証します。

   ```python
   from pyevp import EVPError, SessionNonces, Verifier

   verifier = Verifier.default(audience="https://example.com")  # 自分のオリジン

   try:
       result = verifier.verify_submission(
           form.get("evt"), nonces=SessionNonces(session), email=form["email"]
       )
   except EVPError as exc:
       ...  # exc.code が理由（例: "nonce_mismatch"）。確認メールにフォールバック
   else:
       if result is None:
           ...  # トークンなし: 確認メールにフォールバック
       else:
           result.email, result.issuer  # 検証済み
   ```

   `AsyncVerifier` も同じ API で、`await` を付けて使います。

ネットワークを使わずに確かめられることを先に検証し、接続するのは DNS から見つけたホストだけです。トークンに
書かれたホストには接続しません。検証に失敗すると、
[エラーコード](https://docs.pyevp.dev/ja/latest/quickstart.html#handle-failures)付きの `EVPError` が
送出されます。

## 詳しく

- [クイックスタート](https://docs.pyevp.dev/ja/latest/quickstart.html)と[基本概念](https://docs.pyevp.dev/ja/latest/concepts.html)
- [フレームワーク](https://docs.pyevp.dev/ja/latest/guides/frameworks.html): FastAPI、Flask、fastapi-users、AuthX、Django
- [アプリケーションのテスト](https://docs.pyevp.dev/ja/latest/guides/testing.html)（ネットワーク不要）
- [リプレイ対策](https://docs.pyevp.dev/ja/latest/guides/replay.html)、[ログとメトリクス](https://docs.pyevp.dev/ja/latest/guides/observability.html)
- [コマンドライン](https://docs.pyevp.dev/ja/latest/guides/cli.html): `uvx --from "pyevp[cli]" pyevp discover gmail.com` でドメインの発行者（issuer）を確認できます
- [発行者の運用](https://docs.pyevp.dev/ja/latest/guides/issuer-operations.html)（自分のメールドメイン向け）
- [互換性ポリシー](https://docs.pyevp.dev/ja/latest/compatibility.html)

翻訳されていないページは英語で表示されます。

## サンプル

どれも独立したプロジェクトで、テストが付いています。

- [`examples/fastapi`](https://github.com/gaato/pyevp/blob/main/examples/fastapi/app.py): セッションの nonce を使う FastAPI
- [`examples/flask`](https://github.com/gaato/pyevp/blob/main/examples/flask/app.py): 同期版の `Verifier` を使う同じ流れ
- [`examples/fastapi_spa`](https://github.com/gaato/pyevp/blob/main/examples/fastapi_spa/app.py): シングルページアプリケーション（SPA）向けの JSON API とパスワード再設定
- [`examples/fastapi_users`](https://github.com/gaato/pyevp/blob/main/examples/fastapi_users/app.py): fastapi-users の登録
- [`examples/authx`](https://github.com/gaato/pyevp/blob/main/examples/authx/app.py): AuthX でのパスワードなしログイン
- [`examples/django`](https://github.com/gaato/pyevp/blob/main/examples/django/views.py): テンプレートタグを使う Django
- [`examples/django_allauth`](https://github.com/gaato/pyevp/blob/main/examples/django_allauth/evp_allauth.py): django-allauth のアダプター
- [`examples/issuer_fastapi`](https://github.com/gaato/pyevp/blob/main/examples/issuer_fastapi/app.py)、[`examples/issuer_django`](https://github.com/gaato/pyevp/blob/main/examples/issuer_django/urls.py): 自分のドメイン向けの発行者

## コントリビュート

[CONTRIBUTING.md](https://github.com/gaato/pyevp/blob/main/CONTRIBUTING.md) を参照してください。

## ライセンス

[MIT](https://github.com/gaato/pyevp/blob/main/LICENSE)
