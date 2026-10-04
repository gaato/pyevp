# Japanese translation style

The Japanese docs are translated in the `.po` files in `LC_MESSAGES/`. For how to refresh and
build them, see [Translations](../../../CONTRIBUTING.md#translations) in CONTRIBUTING.md.

Follow the [JTF style guide](https://www.jtf.jp/pdf/jtf_style_guide.pdf) except for spacing, and
keep to the existing translation:

- です・ます. Write 「〜できます」, not 「〜することができます」. Leave "you" untranslated.
- Keep the long vowel at the end of katakana words: ユーザー, ブラウザー, サーバー, アダプター.
- Put a half-width space between Japanese and Latin letters, digits or code (`DNS の TXT レコード`,
  `1 つ`, `2 回`), but never before a particle (`発行者を`, not `発行者 を`).
- Use full-width parentheses in running text. End a sentence that introduces a code block or list
  with 「。」 (「次のように設定します。」), not a colon.
- Give the English term in parentheses only the first time it appears on a page: 発行者（issuer）.

## MyST in `.po` files

Sphinx parses each translation with its page's parser, so every entry is MyST, including the
autodoc docstrings in `api.po`:

- Write roles as ``{class}`Verifier` ``, not ``:class:`Verifier` ``, and drop the `::` that
  introduces a literal block. The field labels (Parameters, Raises, Return type) come from
  Sphinx's own catalog.
- Link to sections with explicit labels (`(label-name)=` above the heading, then
  `[text](#label-name)`), not with anchors derived from heading text.
- In a heading that starts with a number, escape the dot (`3\\. …` in the `.po` file), or it is
  parsed as a list and the translation is dropped.

## Glossary

| English | Japanese |
|---|---|
| issuer | 発行者 |
| relying party (RP) | リライングパーティー（RP） |
| verify, verification | 検証する、検証 |
| raise (an exception) | 送出する |
| override (a method) | オーバーライドする |
| fall back | フォールバックする |
| replay protection, replay guard | リプレイ対策、リプレイガード |
| hidden field | hidden フィールド |
| body (of a request) | ボディ |
| discovery | ディスカバリー (noun only) |
| end-to-end | エンドツーエンド |
| fake | フェイク |
| presentation token | 提示用のトークン |
| key binding (KB-JWT) | 鍵バインディング |
| holder key | ホルダーの鍵 |
| canonical (issuer) | 正規化された |
| claim | クレーム |
| driver, port, effect | ドライバー、ポート、エフェクト |
| fetcher, resolver | フェッチャー、リゾルバー |
| fail closed | 安全側に失敗する |
| single-page app (SPA) | シングルページアプリケーション（SPA） |
| stateless | ステートレス |
| password recovery, reset token | パスワード再設定、再設定トークン |
| Cookie, CORS, credentials, same-site | (untranslated) |
| verifier, nonce, disclosure | (untranslated) |
