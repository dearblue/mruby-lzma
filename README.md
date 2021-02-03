# mruby-lzma : mruby bindings for lzma (xz) the compression library (unofficial)

mruby へ LZMA/XZ 圧縮ライブラリの機能を提供します。


## HOW TO USAGE

### 圧縮

```ruby:ruby
src = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
dest = LZMA.encode(src)
# dest は xz ユーティリティプログラムで伸長可能な string オブジェクトです
```

### 伸長

```ruby:ruby
src = ... # LZMA.encode か xz ユーティリティプログラムで圧縮したデータ
dest = LZMA.decode(src)
# dest は伸長した string オブジェクト
```

### 圧縮 (簡易オプションの指定)

```ruby:ruby
src = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

preset_level = 9
check_method = :sha256 # OR :none, :crc32, :crc64, nil (crc64)

dest = LZMA.encode(src, preset: preset_level, check: check_method)
```

### 圧縮 (フィルタの指定)

```ruby:ruby
src = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

striping = 4 # for 4 bytes striping (e.g. 16bits-2ch audio, or RGBA32 pixel image
filter1 = LZMA.delta(striping)

preset_level = 9
filter2 = LZMA.lzma2(preset_level)

check_method = :sha256 # OR :none, :crc32, :crc64, nil (crc64)

dest = LZMA.encode(src, filter1, filter2, check: check_method)
```


## Specification

  - Product name: [mruby-lzma](https://github.com/dearblue/mruby-lzma)
  - Version: 0.3.2
  - Product quality: PROTOTYPE
  - Author: [dearblue](https://github.com/dearblue)
  - Report issue to: <https://github.com/dearblue/mruby-lzma/issues>
  - Licensing: [2 clause BSD License](LICENSE)
  - Dependency external mrbgems:
      - [mruby-aux](https://github.com/dearblue/mruby-aux)
        under [Creative Commons Zero License \(CC0\)](https://github.com/dearblue/mruby-aux/blob/master/LICENSE)
        by [dearblue](https://github.com/dearblue)
  - Dependency C libraries:
      - liblzma in [XZ Utils](https://tukaani.org/xz/)
        under [Public Domain](https://git.tukaani.org/?p=xz.git;a=blob;f=COPYING)
        by Lasse Collin
