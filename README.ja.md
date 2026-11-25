# AlmaLinux と Rocky Linux の全部入り kpatch livepatch

[English](README.md)

AlmaLinux と Rocky Linux 8・9・10 (x86_64) のカーネルごとに一つの
livepatch モジュールで、下の直しのうちそのカーネルに無いものを全部入れて
います。モジュールは置き換え型で、新しいものを読み込むと前のものと
入れ替わります。そのため直しは CVE ごとに分けず、一つのモジュールに
まとめています。

まだモジュールは公開していません。最初のカーネル Rocky Linux
4.18.0-553.180.1.el8_10 をビルドして試験しているところで、それが通って
から他のカーネルに広げます。

| CVE | 内容 | upstream の直し |
|---|---|---|
| CVE-2026-98432 | TCP の request socket と子 socket の IP オプションの解放後使用 | e3f33b0a1d89 |
| CVE-2026-99999 | 「PwnEscape」: 細工した checksum_start で、checksum の処理が解析済みの IPv4 ヘッダを上書きする。直しの無いカーネルだけ | |
| CVE-2026-99288 | 「NoisyTCP」: ロックなしの established 検索がハッシュから外れた socket を受け入れ、遠隔からカーネルを落とせる | 4e2b3ef19e0e |
| CVE-2022-3344 | KVM の nested SVM: L2 の実行中に vCPU をリセットすると、ホストが落ちる | 917401f26a6a, 16ae56d7e052, f9697df25143, ed129ec9057f, 05311ce954ae |
| CVE-2026-99312 | KVM: L2 の実行中の INIT の後に古い MMU の状態が残る | c7c288d178cb |

KVM の二つが効くのは、nested 仮想化を有効にした AMD のホスト
(`kvm_amd nested=1`) です。9 と 10 には CVE-2022-3344 の直しが既に
入っており、CVE-2026-99312 はその直しが開いた経路を塞ぐものなので、
8 には両方を入れます。

```sh
curl -fsSL https://raw.githubusercontent.com/nsrg-fmlorg/kpatch-el/main/scripts/livepatch.sh | sudo bash -s -- apply
```

スクリプトは動いているカーネル (`uname -r`) のモジュールを選びます。
公開したモジュールの無いカーネルでは断り、何も変えません。`check`・
`status`・`remove` で、確認・表示・取り外しをします。
nsrg-fmlorg/kpatch-cve-2026-98432、kpatch-alma-cve-2026-99999、
kpatch-rocky-cve-2026-99999 のモジュールが既に読み込まれていれば、
置き換えて取り外します。livepatch は再起動すると消えます。

8 では、livepatch を当てた状態の `kvm` や `kvm_amd` を一度取り外すと、
次の読み込みが "Exec format error" で断られます。カーネルが、取り外した
モジュールの再配置を消さないためです (upstream は 6.3 の 0c05e7bd2d01 で
直しました)。`nested` を変えるときなどは、`remove` してから読み込み
直し、もう一度 `apply` してください。

## 移植の作り方

CVE-2026-98432 と CVE-2026-99999 の分は、kpatch-cve-2026-98432 のために
作った移植 (`tools/mkdiffs.sh`、下) です。残りの三つは upstream の変更を
カーネルのソースと突き合わせて、後ろにつないでいます。

4.18.0-553.180.1.el8_10 では、KVM の変更と NoisyTCP の検索の変更は
upstream のものがそのまま当たります。ただし、upstream がリセットの後に足した
`WARN_ON_ONCE()` は、直しを確かめるだけのものなので外しています。これが
あると gcc が `vcpu_enter_guest()` への `kvm_check_request()` の
インライン化を変え、kpatch-build はこの関数を、`kvm` モジュールにある
static key の jump label を理由に断ります。無ければ、この関数は配布された
カーネルと同じに組まれます。NoisyTCP は `tcp_conn_request()` の
Fast Open の失敗の経路の参照カウントも直しますが、upstream のこの変更は、
`tcp_disconnect()` が request の参照を既に一つ落としているコードを前提に
書かれています。EL8 は 4.18.0-553.87.1.el8_10 で Red Hat が
CVE-2025-39955 の直し (RHEL-120664) を入れてから同じ形になっており、
upstream の hunk がそのまま当たります。それより前の EL8 のカーネルは、
この経路でまだ `reqsk_fastopen_remove()` を呼んでいて別の書き方が要り、
まだ一つも対象にしていません。upstream の request socket の移し替えの
変更は、8 には当てる先がありません。

ほかのカーネルでは `tools/extra.py` が、直しの部分ごとに、`tools/extra/` の
うち曖昧さなしに当たる一つの形を選びます。

- Fast Open の失敗の経路で、まだ `reqsk_fastopen_remove()` を呼ぶものは、
  その呼び出しが参照を一つ落としているので、残りの一つだけを落とします。
- request socket の移し替えは文脈が違うだけです。ただし upstream の
  c31e73121f4c より前のカーネルは、複製した request のタイマーを動かした
  ままにしており、この直しはそれが止まっていることを前提にしているので、
  その変更も入れます。
- CVE-2022-3344 の直しは `kvm_x86_nested_ops` の `leave_nested` を呼びます。
  8.3〜8.6 と 9.0 にはこのメンバーが無く、livepatch では足せないため、
  **KVM の直しは入りません**。`kvm_amd` を `nested=0` で読み込んでください。

`tools/mkdiffs.sh` は、SRPM 自身のパッチを `%prep` と同じように tarball に
当ててから (`tools/prep.py`)、minor の全カーネルに CVE-2026-98432 を移植し、
変えた行を `tools/ref/` と突き合わせます。

8 と 9 は kpatch-build、10 はカーネル自身の klp-build でビルドし、どちらも
置き換え型のパッチを作ります。`build.sh` は配布元から取る SRPM・debuginfo・
コンパイラの署名を確かめ、カーネルが記録している gcc でビルドします。

## 試験していること

`.github/workflows/build.yml` がモジュールをビルドし、配布されたカーネルを
VM で起動します (`tools/loadtest.sh`)。VM の中で
`tools/loadtest-guest.sh` が、まず kpatch-cve-2026-98432 のそのカーネルの
モジュールを読み込み、その上にこのモジュールを `scripts/livepatch.sh` で
当てて、次を確かめます。

- 前のモジュールが置き換えられ、取り外されること
- 変えた関数が livepatch に入っていること。`kvm` と、AMD では `kvm_amd`
  の変えた関数が、起動時に読み込まれていたモジュールでも、パッチの後で
  読み込んだモジュールでも、実際に差し替わっていること。二度目の読み込みが
  断られても (上)、`remove`・読み込み・`apply` で戻ること
- IP オプション付きの TCP 接続 2000 本が開いて閉じること
  (`tools/tcpopt.py`)、SYN cookie で確立した IPv4 と IPv6 の接続各 200 本で
  送受信できること (`tools/syncookie.py`)
- VM に VMX か SVM がある場合、KVM のゲストを作り、HLT まで走らせ、
  解放できること (`tools/kvmrun.py`)
- 前のモジュールを上から読み込まれても `apply` で戻せること、`remove` で
  全部外れること、その間に BUG・Oops・WARNING が出ないこと

## 構成

| パス | 内容 |
|---|---|
| `build.sh` | 配布元のコンテナで、一つのカーネルのモジュールをビルドする |
| `patches/<distro>/<nvr>.diff`、`patches/<distro>/kpatch/<nvr>.diff` | 一つのカーネルの直し。klp-build 用と kpatch-build 用 |
| `tools/kernels.tsv` | CI がビルドするカーネル: 配布元、minor、カーネルのバージョン |
| `tools/select-kernels.py` | CI の一回でどれを取るか |
| `tools/mkdiffs.sh` | minor の全カーネルに CVE-2026-98432 を移植し、`tools/ref/` と突き合わせる |
| `tools/prep.py` | 移植の前に、SRPM 自身のパッチを `%prep` と同じように tarball に当てる |
| `tools/port.py` | CVE-2026-98432 の変更をカーネルのツリーに当てる |
| `tools/extra.py`、`tools/extra/` | 残りの三つの CVE の直しを、カーネルに合う形で当てる |
| `tools/kpatchify.py` | 移植を kpatch-build に渡す形にする |
| `tools/klp-overlay.sh`、`tools/klp-overlay-lds.py`、`tools/klp-overlay/` | 10.2 の klp-build を 10.0 と 10.1 に貸す |
| `tools/klpsymcheck.py` | klp-build のモジュールのシンボルを、配布されたカーネルと突き合わせる |
| `tools/loadtest.sh`、`tools/loadtest-guest.sh`、`tools/loadtest-bootprep.sh`、`tools/loadtest-bootinfo.sh` | 配布されたカーネルを VM で起動し、モジュールを当て、確かめ、外す |
| `tools/csum-probe.sh`、`tools/csum-inject.py` | CVE-2026-99999 を当てる前と後で調べる |
| `tools/tcpopt.py` | CVE-2026-98432 で変わる二つの解放を、IP オプション付きで通す |
| `tools/syncookie.py` | SYN cookie で確立する接続 (CVE-2026-99288) |
| `tools/kvmrun.py` | KVM のゲストを作り、走らせ、解放する (CVE-2022-3344、CVE-2026-99312) |
| `tools/doccheck.py` | 両方の README に名前の無いファイルや、切れたリンクがあれば落ちる |
| `scripts/livepatch.sh` | ホストで、公開したモジュールを当て、確かめ、外す |
| `scripts/build-local.sh` | 一つのカーネルのモジュールを手元の機械でビルドし、試験する |
| `.github/workflows/diffs.yml` | 両方の配布元の全 minor で `tools/mkdiffs.sh` を走らせる |
| `.github/workflows/build.yml` | モジュールをビルドし、試験する |
| `.github/workflows/docs.yml` | `tools/doccheck.py` を走らせる |
