# FNE

> 本项目仅用于学习 Go 语言文件 I/O、AES 解密、元数据处理和并发编程。

## 简介

FNE 是一个可以批量将网易云音乐和 QQ 音乐的加密格式转换为标准音频格式的命令行工具。

- **零外部依赖** — 纯 Go 实现，无需安装 FFmpeg 或其他工具
- **开箱即用** — 双击运行，图形化选择文件夹，无需命令行参数
- **速度快** — 多线程并发
- **保留元数据** — 歌名、歌手、专辑、封面(mgg暂不支持)、创建时间全部保留
- **增量保存** — 自动跳过目标文件夹中已经保存过的歌曲
- **支持多种格式** — 网易云 NCM、QQ 音乐 QMC2(mflac, mgg)
- **QQ 音乐解密** — 需要电脑运行并已登录 QQ 音乐客户端

## 使用方法

> [!NOTE]
> **前置条件：** 需要网易云音乐或 QQ 音乐的 **VIP 会员**，并在对应客户端中将歌曲下载到本地。
> 网易云的加密文件为 `.ncm` 格式，QQ 音乐的加密文件为 `.mflac` / `.mgg` 等格式。
> **转换 QQ 音乐文件时需要 QQ 音乐客户端处于运行并已登录状态。**

1. 下载预编译可执行文件[`FNE.exe`](https://github.com/zyoung11/FNE/releases/download/0.3.1/FNE.exe)
2. 双击运行 `FNE.exe`

2. 选择 NCM 或 mflac 或 mgg 文件所在的文件夹

3. 选择输出文件夹

4. 等待转换完成

## 配置文件

可以在程序同目录下创建 `config.json` 文件预设输入和输出文件夹路径，避免每次手动选择：

```json
{
  "inputFolder": "C:/CloudMusic/VipSongsDownload",
  "outputFolder": "D:/Music/Converted",
  "recursive": false,
  "apiConcurrent": 3,
  "apiDelayMin": 200,
  "apiDelayMax": 800
}
```

### 配置项说明

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `inputFolder` | string | - | 输入文件夹路径（必须存在） |
| `outputFolder` | string | - | 输出文件夹路径（不存在时会自动创建） |
| `recursive` | bool | false | 是否递归扫描子文件夹 |
| `apiConcurrent` | int | 3 | API 并发请求限制 |
| `apiDelayMin` | int | 200 | API 请求最小延迟(ms) |
| `apiDelayMax` | int | 800 | API 请求最大延迟(ms) |

所有字段均可选：
- 都不配置：每次弹窗选择
- 只配置 inputFolder/outputFolder：另一个弹窗选择
- 都配置：直接开始转换

### 递归模式

当 `recursive` 设置为 `true` 时，程序会递归扫描输入文件夹及其所有子文件夹中的加密文件。

## 本地编译

```bash
git clone https://github.com/zyoung11/FNE.git
cd FNE
go mod tidy
go build .
```

编译完成后会在当前目录生成 `FNE.exe`，双击即可运行。

## 转换逻辑

### NCM 格式 (网易云音乐)

| 优先级 | 格式          | 说明                                           |
| ------ | ------------- | ---------------------------------------------- |
| 1      | FLAC + 元数据 | 原始格式为 FLAC 时，写入 Vorbis Comment 和封面 |
| 2      | MP3 + 元数据  | 原始格式为 MP3 时，写入 ID3v2 标签和封面       |
| 3      | 裸音频        | 元数据写入失败时保留音频文件，保证播放         |

### QMC2 格式 (QQ 音乐)

| 扩展名 | 输出格式 | 说明 |
| ------ | -------- | ---- |
| .mflac | .flac    | 加密无损 FLAC |
| .mgg   | .ogg     | 加密 OGG |

ekey 与封面通过 QQ 音乐 API 自动获取，封面自动嵌入（仅 FLAC）。

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
