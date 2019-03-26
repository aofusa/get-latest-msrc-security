Get Latest MSRC Security
---


MSRC より最新のセキュリティに関する更新プログラムの KB 番号を取得する  
[MSRC セキュリティ更新プログラムガイド](https://portal.msrc.microsoft.com/ja-jp/security-guidance)  


## 環境構築  
```sh
python3 -m pip install -r requirements.txt --user
```

## 前準備  
事前に MSRC より API Key を取得してください  
[MSRC セキュリティ更新プログラムガイド](https://portal.msrc.microsoft.com/ja-jp/security-guidance)  


## 実行  
```sh
python3 get-latest-msrc-security.py <your-msrc-api-key> --date '2019-03-12' --output ./windows_kb_list.json
```

## 実行結果  
```json
[{
    "os": "Windows 10",
    "patch": [{
        "version": "17763",
        "container": [{
            "date": "2019-03-27",
            "kb": ["4480979", "4487044"]
        }]
    }]
}]
```

## その他  
--output で指定されたファイルを上書きします   
上書きする際、もともと記述してあった内容に追記する形で上書きします  

