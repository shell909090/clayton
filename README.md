# Development

Dependencies are managed with uv (`pyproject.toml` and `uv.lock`).
Python 3.13 or newer is required for this environment.

```sh
uv sync --locked
uv run manage.py migrate
uv run manage.py check
uv run manage.py runserver 127.0.0.1:8765
```

Use `uv add` / `uv remove` to update dependencies and commit `uv.lock`.
`requirements.txt` is the original import source; it is no longer used by
`make buildenv`. SQLite data is stored in `db.sqlite3` (ignored by Git).

Open http://127.0.0.1:8765/k/ to create a key via **Ops → build rsa**.
Open the key, choose **Ops → build req**, enter a common name, and check
**Ca** and **Selfsign** to create a root CA. On that certificate's page,
choose **Ops → build cert** to issue a leaf certificate; for a local TLS
test use `localhost` for both CN and Alternative and select server authentication.
The certificate's Ops menu exports PEM, DER and PKCS#12 files.

Run the regression tests with `uv run manage.py test`.
This application has no authentication yet; keep the development server on
loopback. Generated test certificates are not publicly trusted.

# TODO

* 认证
* 有效性检查
* 过期/失效状态修改
* 吊销
* remove确认
* status变更后变色，目前bootstrap貌似不生效
