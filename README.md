# rBlur

rBlur 是個便捷的 Web 伺服器，支援靜態文件服務、路由轉發，並且提供網頁配置介面。

## 快速開始

### 安裝

#### 前置依賴
- build-essential
- OpenSSL

Ubuntu 環境下安裝：
```bash
sudo apt update
sudo apt install build-essential
sudo apt-get install libssl-dev pkg-config
```

### 使用Cargo安裝
```bash
cargo install rblur
```

### 編譯安裝
```bash
git clone https://github.com/YuFireWhisper/rblur.git
cd rblur
cargo build --release
```

### 使用預設配置

最簡單的啟動方式是使用預設配置：

```bash
rblur -u
```

這會：

- 在 8080 端口啟動伺服器
- 啟用網頁配置介面（訪問 `/web_config`）

### 使用配置文件

如果需要自定義配置，可以建立配置文件並指定路徑：

```bash
rblur -c /path/to/config
```

配置文件範例：

```
http {
  server {
    listen 0.0.0.0:8080;

    location / {
      static_file ../index.html;
    }

    web_config on;
  }
}
```

## 命令列參數

```
Options:
  -c, --config-path <CONFIG FILE PATH>  指定配置文件路徑
  -u, --use-default-config             使用預設配置
  -h, --help                           顯示幫助訊息
  -V, --version                        顯示版本資訊
```


