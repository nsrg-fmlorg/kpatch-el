# AlmaLinux・Rocky Linux 向け CVE-2026-98432 の kpatch livepatch

[English](README.md)

AlmaLinux と Rocky Linux の 8・9・10 (x86_64) で、動いているホストの
CVE-2026-98432 を再起動なしで直す livepatch モジュールです。CVE-2026-99999
の修正も入っていないカーネルでは、同じモジュールがそちらも直します。
カーネルにどちらが欠けていても、ホストに要るモジュールは一つです。

```sh
curl -fsSL https://raw.githubusercontent.com/nsrg-fmlorg/kpatch-cve-2026-98432/main/scripts/livepatch.sh | sudo bash -s -- apply
```

スクリプトは動いているカーネル (`uname -r`) に合うモジュールを選びます。公開した
モジュールが無いカーネルは断り、何も変えません。`apply` の代わりに `check` なら
確かめるだけで、`status` と `remove` で状態の表示と取り消しができます。
livepatch は再起動で消えます。CVE-2026-98432 の修正は、配布元の changelog では
4.18.0-553.182.1.el8_10、5.14.0-687.64.1.el9_8、6.12.0-211.72.1.el10_2 から
載っています (2026-11-06 に確認)。

## 対象カーネル

686 本です。AlmaLinux が 381 本、Rocky Linux が 305 本で、8.3 から 10.2 まで、
`tools/kernels.tsv` に並べてあります。配布元のミラー (vault を含む) に SRPM と
debuginfo の両方がある全カーネルで、x86_64 だけです。Rocky の
5.14.0-611.41.1.el9_7 は、debuginfo がどのミラーにも無いので外しています。
前の Rocky の repo に入っていなかった Rocky の 8.3 のカーネル
4.18.0-240.22.1.el8 と、前の repo の後に両配布元が出したカーネル
(4.18.0-553.181.1.el8_10 (AlmaLinux)、553.180.1 (Rocky)、5.14.0-687.61.1.el9_8、
6.12.0-211.69.1.el10_2 まで) も入っています。AlmaLinux 10 の x86_64_v2 版は
対象外です。

686 本のうち 666 本は CVE-2026-99999 の修正も入っておらず、モジュールが両方を
持ちます。残りの 20 本は修正済みで (AlmaLinux 4.18.0-553.177.1.el8_10 と
Rocky 553.178.1.el8_10、両方の 5.14.0-687.59.1.el9_8 と 6.12.0-211.67.1.el10_2
から後)、モジュールは CVE-2026-98432 の変更だけを持ちます。

## 試したこと

どのモジュールも CI で組み、出荷カーネルを起こした VM で `scripts/livepatch.sh`
を使って当てました (`tools/loadtest.sh`)。2026-10-31、配布元とマイナーごとに
1 回、全部で 40 回で、その時点の 684 本すべて `RESULT: PASS` でした。その後、
公開したものを 1 行の手順で当てる試験 (2026-11-02、40 回) も全部通りました。
AlmaLinux 553.181.1 と Rocky 553.180.1 は 2026-11-06 に両方を通しました
(run 42066544047、42081208786)。それぞれで次を
確かめています。

- vmlinux の差し替えた関数に、`inet_sock_destruct` と
  `tcp_v4_reqsk_destructor` が並ぶ。
- IP オプションを付けたソケットからの loopback の TCP 接続 2,000 本と、raw
  ソケットからの IP オプション付きの SYN だけ 2,000 本を、エラーもカーネルの
  警告も無く通した (`tools/tcpopt.py`)。修正が変える二つの解放を、オプションが
  ある状態で通すためのものです。IP オプションが無いと、どちらも NULL しか
  解放しません。
- モジュールが CVE-2026-99999 の分を持つカーネルでは、それが vmlinux、
  `nfnetlink_queue`、`xt_CHECKSUM` (9 と 10 では `nf_conntrack_bridge` も)
  に効いている。8 と 9 (511 本と、Rocky の 8.3) では、細工したフレームを
  出荷カーネルは断片化し、モジュールを当てると捨てた。10 (154 本) では
  フレームが欠陥の手前で弾かれるので、この突きではどちらとも言えません。
- 前の repo のモジュールがあった 665 本では、それを先に読み込み、新しい
  モジュールが置き換えた。前のパッチは無効になり、そのモジュールは外れた。
- 最後にモジュールを無効にして外した。

試していないこと: 競合そのものです。CVE-2026-98432 が出荷カーネルで起き、
モジュールで起きなくなることを見せるには、KASAN と、SYN の再送と子ソケットの
解放をわざと重ねる手立てが要り、この VM では狙って起こせません。Secure Boot を
有効にした状態 (署名の無いモジュールなので断られます) と、`kpatch.service` に
よる起動時の読み込みも試していません。

## 移植の作り方

`tools/mkdiffs.sh` がマイナーの全カーネルの SRPM を移植します。まず SRPM
自身の当て物を、`%prep` と同じように tarball に当てます (`tools/prep.py`)。
AlmaLinux は自分の修正をこの形で持っていて、4.18.0-553.177.1.el8_10 の
CVE-2026-99999 の修正もその一つです。10.2 の 6.12.0-211.69.1 は Red Hat の
211.56.1 の tarball に当て物 466 本を重ねたものなので、tarball だけを見て
作った移植はカーネルが持つものを見落とします。そのうえで変更行を
`tools/ref/` と照らします。CVE-2026-98432 の分は上流と同じであること、
CVE-2026-99999 の分は 8 と 9 では AlmaLinux の当て物、10 では上流と同じで
あるか、修正済みのカーネルでは無いことです。686 本すべて一致しました。
`tools/port.py` は、そのカーネルの `kfree_rcu()` が NULL を飛ばさない形なら
止まります。どちらのポインタも普段は NULL だからです。

8 と 9 は kpatch-build、10 はカーネル自身の klp-build で組みます。どちらも
置き換え型のパッチを作り、それによって前のモジュールと入れ替わります。

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
読み込まれている前のモジュールと置き換わります (前のモジュールがあった
665 本のそれぞれで試しました。上記)。

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
