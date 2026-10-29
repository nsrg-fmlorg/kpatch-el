# AlmaLinux・Rocky Linux 向け CVE-2026-98432 の kpatch livepatch

[English](README.md)

AlmaLinux と Rocky Linux の 8・9・10 (x86_64) で、動いているホストの
CVE-2026-98432 を再起動なしで直す livepatch モジュールです。CVE-2026-99999
の修正も入っていないカーネルでは、同じモジュールがそちらも直します。
カーネルにどちらが欠けていても、ホストに要るモジュールは一つです。

**状況 (2026-10-30): 作業中です。まだ何も公開しておらず、当てられる
ものはありません。** 両方の配布元の全カーネルについて移植を作り、モジュールを
組んで VM で試しているところです。何を公開し、それに何を試したかは、
この README に書きます。

## CVE-2026-98432

上流の修正は torvalds/linux e3f33b0a1d89 "ipv4: free inet_opt and ireq_opt
after an RCU grace period" です。SYN が IP オプションを持っていると、待ち受け
側はそれを接続要求のソケットに (`ireq_opt`) 取っておき、子ソケットに写さずに
そのまま渡します (`inet_opt`)。同じ要求への SYN の再送に、別の CPU が RCU の
下でそのオプションを読みながら SYN-ACK を返しているところへ、子ソケットが
閉じられて `inet_sock_destruct()` が素の `kfree()` で解放すると、解放後の
メモリを使うことになります。要求ソケットの移し替えでも
`tcp_v4_reqsk_destructor()` に同じ問題があります。修正は両方を `kfree_rcu()`
で解放するものです。

どちらの配布元もまだ修正を出していません。2026-10-27 の時点で、AlmaLinux と
Rocky Linux の 8・9・10 の最新カーネルは changelog にこの CVE を挙げておらず、
4.18.0-305.3.1.el8_4、4.18.0-553.179.1.el8_10、5.14.0-687.61.1.el9_8、
6.12.0-211.68.1.el10_2 のソースは、どちらのポインタも `kfree()` で解放した
ままです。

## CVE-2026-99999

こちらは先に、配布元ごとに
[nsrg-fmlorg/kpatch-alma-cve-2026-99999](https://github.com/nsrg-fmlorg/kpatch-alma-cve-2026-99999)
と
[nsrg-fmlorg/kpatch-rocky-cve-2026-99999](https://github.com/nsrg-fmlorg/kpatch-rocky-cve-2026-99999)
で直しました。今はどちらの配布元も修正の入ったカーネルを出しています。
4.18.0-553.177.1.el8_10 (AlmaLinux) または 553.178.1.el8_10 (Rocky)、
5.14.0-687.59.1.el9_8、6.12.0-211.67.1.el10_2 から後の版です。修正の無い
カーネルでは、この repo のモジュールが前のものと同じ変更を持ち、すでに
読み込まれている前のモジュールと置き換わるように組んでいます (kpatch-build も
klp-build も、既定で置き換え型のパッチを作ります。VM ではまだ試していません)。

## 構成

| パス | 中身 |
|---|---|
| `build.sh` | 配布元のコンテナの中で、一つのカーネルのモジュールを組む |
| `tools/kernels.tsv` | CI が組むカーネル。配布元、マイナー、カーネルの版 |
| `tools/select-kernels.py` | CI の一回の実行がそのうちどれを取るか |
| `tools/mkdiffs.sh` | マイナーの全カーネルの移植を作り、`tools/ref/` と照らす |
| `tools/prep.py` | 移植の前に、SRPM 自身の当て物を `%prep` と同じように tarball に当てる |
| `tools/port.py` | 変更そのもの。カーネルの木に当てる |
| `tools/kpatchify.py` | 移植を kpatch-build に渡す形に直す |
| `tools/klp-overlay.sh`、`tools/klp-overlay-lds.py`、`tools/klp-overlay/` | 10.2 の klp-build を 10.0 と 10.1 に貸す |
| `tools/klpsymcheck.py` | klp-build のモジュールのシンボルを出荷カーネルと照らす |
| `tools/loadtest.sh`、`tools/loadtest-guest.sh`、`tools/loadtest-bootprep.sh`、`tools/loadtest-bootinfo.sh` | 出荷カーネルを VM で起こし、モジュールを当てて確かめ、外す |
| `tools/csum-probe.sh`、`tools/csum-inject.py` | CVE-2026-99999 を当てる前と後で突く |
| `tools/tcpopt.py` | CVE-2026-98432 が変える二つの解放を、IP オプションのある状態で通す |
| `tools/doccheck.py` | どちらかの README に名前の無いファイルや、壊れたリンクがあると落ちる |
| `scripts/livepatch.sh` | ホストで公開モジュールを当てる、確かめる、外す |
| `scripts/build-local.sh` | 一つのカーネルのモジュールを手元で組んで読み込みテストする |
| `.github/workflows/diffs.yml` | 両方の配布元の全マイナーで `tools/mkdiffs.sh` を走らせる |
| `.github/workflows/build.yml` | モジュールを組んで読み込みテストする |
| `.github/workflows/docs.yml` | `tools/doccheck.py` を走らせる |
