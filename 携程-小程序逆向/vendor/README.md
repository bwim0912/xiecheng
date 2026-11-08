# vendor/

放置从目标小程序包中提取的 4 个模块。本仓库不包含这些文件，原因是它们属于目标方代码，
随仓库分发不合适。

## 需要放入的文件

| 文件 | 原始路径 | 用途 |
|---|---|---|
| `c-sign.js` | `cwx/ext/sign/c-sign.js` | cSign 签名 |
| `cwx.md5.js` | `cwx/ext/cwx.md5.js` | MD5 |
| `cwx.aes.js` | `cwx/ext/cwx.aes.js` | AES |
| `tiny.039.min.js` | `3rd/tiny.039.min.js` | 反爬虚拟机 |

## 提取方法

1. 解密并解包小程序包（`V1MMWX`，AES-256-CBC 前 1023 字节 + 逐字节 XOR）；
2. 在解包结果中按上表的原始路径取文件；
3. 复制到本目录并按左列重命名。

用 `python 携程_decode.py waterflow` 可以验证模块是否就位：缺文件时脚本会直接指出缺哪个。
