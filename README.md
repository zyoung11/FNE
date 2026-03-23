# FNE

> 本项目仅用于学习研究，学习 Go 语言文件 I/O、AES 解密、元数据处理和并发编程。

## 简介

FNE 是一个将网易云音乐 NCM 加密格式转换为 FLAC/MP3 的命令行工具。

- **零外部依赖** — 纯 Go 实现，无需安装 FFmpeg 或其他工具
- **开箱即用** — 双击运行，图形化选择文件夹，无需命令行参数
- **速度快** — 8 线程并发，实测 ***1174*** 首歌仅需 ***23*** 秒
- **保留元数据** — 歌名、歌手、专辑、封面、创建时间全部保留

## 使用方法

1. 下载预编译可执行文件[`FNE.exe`](https://github.com/zyoung11/FNE/releases/download/0.2.0/FNE.exe)
2. 双击运行 `FNE.exe`

2. 选择 NCM 文件所在的文件夹（默认路径：`C:\CloudMusic\VipSongsDownload`）

3. 选择输出文件夹

4. 等待转换完成

## 本地编译

```bash
git clone https://github.com/zyoung11/FNE.git
cd FNE
go build .
```

编译完成后会在当前目录生成 `FNE.exe`，双击即可运行。

## 转换逻辑

| 优先级 | 格式          | 说明                                           |
| ------ | ------------- | ---------------------------------------------- |
| 1      | FLAC + 元数据 | 原始格式为 FLAC 时，写入 Vorbis Comment 和封面 |
| 2      | MP3 + 元数据  | 原始格式为 MP3 时，写入 ID3v2 标签和封面       |
| 3      | 裸音频        | 元数据写入失败时保留音频文件，保证播放         |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
