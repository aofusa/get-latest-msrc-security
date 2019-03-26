
import requests
import re
import json
import datetime
from pathlib import Path
import argparse
from bs4 import BeautifulSoup
import jsonschema
from progressbar import ProgressBar

# API取得の初期設定
api_key = 'your-msrc-api-key'
api_version = '2017'
today = datetime.datetime.now().strftime('%Y-%m-%d')
target_id = datetime.datetime.strptime(today, '%Y-%m-%d').strftime('%Y-%b')
add_file_path = './windows_kb_list.json'
add_file_schema_path = './windows_kb_list_schema.json'

# 引数の取得
parser = argparse.ArgumentParser(description='Get Latest MSRC Security Update')
parser.add_argument(
    'apikey',
    help='API Key for MSRC API (https://portal.msrc.microsoft.com/ja-jp/)')
parser.add_argument(
    '--date', '-d',
    help='Date with Update Release day e.g. 2019-03-12', default=today)
parser.add_argument('--output', '-o', help='Output file path',
                    default='./windows_kb_list.json')
args = parser.parse_args()

api_key = args.apikey
today = args.date
add_file_path = args.output
target_id = datetime.datetime.strptime(today, '%Y-%m-%d').strftime('%Y-%b')

# APIを叩いて更新プログラムの情報を取得する
url = \
    'https://api.msrc.microsoft.com/cvrf/{target_id}?api-version={api_version}'
headers = {
    'Accept': 'application/json',
    'api-key': api_key
}

r = requests.get(
    url.format(target_id=target_id, api_version=api_version), headers=headers)

assert r.status_code == requests.codes.ok, \
    f"url: {r.url} response code {r.status_code}"

data = r.json()

# Windows10 のビルド番号の情報を取得する
url = \
    "https://winreleaseinfoprod.blob.core.windows.net/" + \
    "winreleaseinfoprod/ja-JP.html"
r = requests.get(url)
soup = BeautifulSoup(r.text, 'lxml')
table = soup.findAll('table', {'class': 'cells-centered'})[0].findAll('tr')
win10_build = {}

for index, content in enumerate(table):
    if index == 0:
        continue
    version = content.find_all('td')[0].string
    version = re.search(r'\d*', version).group(0)
    build = content.find_all('td')[3].string.split('.')[0]
    win10_build[version] = build

# 必要な情報を取得する
# data['Vulnerability'][0]['Remediations'][0]['SubType'] に
#  'Security Update' が入っているか確認
# data['Vulnerability'][0]['Remediations'][0]['Supercedence'] に
#  KB 番号が入っている
# set(
#     [
#         kb['Supercedence']
#         for inner in [v['Remediations'] for v in data['Vulnerability']]
#         for kb in inner
#         if 'SubType' in kb.keys() and
#         kb['SubType'] == 'Security Update' and
#         'Supercedence' in kb.keys()
#     ]
# )

# APIによる更新ファイルのリストを取得
kb_data_list = \
    [
        kb
        for inner in [v['Remediations'] for v in data['Vulnerability']]
        for kb in inner
        if 'SubType' in kb.keys() and
        kb['SubType'] == 'Security Update' and
        'Supercedence' in kb.keys()
    ]

# 書き出しファイルの読み込み
output_data_list = []
if Path(add_file_path).exists():
    with open(add_file_path, 'r', encoding='utf_8') as add:
        with open(add_file_schema_path, 'r', encoding='utf_8') as validator:
            a = json.load(add)
            v = json.load(validator)
            jsonschema.validate(a, v)
        output_data_list = a

# クローリング
progressbar = ProgressBar(0, len(kb_data_list))
for index, kb_data in enumerate(kb_data_list):
    progressbar.update(index)
    url = kb_data['URL']
    kb = kb_data['Supercedence']
    if 'https://' not in url and 'http://' not in url:
        continue
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'lxml')
    text = \
        [t.strip() for a in soup.findAll('a')
         for t in a.contents if 'Windows' in t]
    for t in text:
        if re.search(r'Windows Server (\d*)', t) is not None:
            os = re.search(r'Windows Server (\d*)', t).group(0)
        elif re.search(r'Windows (\d*)', t) is not None:
            os = re.search(r'Windows (\d*)', t).group(0)
        else:
            os = t
        if re.search(r'Windows Server (\d*) \((\d*)\)', t) is not None:
            version = \
                re.search(r'Windows Server (\d*) \((\d*)\)',
                          t).group(0).split(' ')[3].lstrip('(').rstrip(')')
        elif re.search(r'Windows Server (\d*) (\d*)', t) is not None:
            version = re.search(r'Windows Server (\d*) (\d*)',
                                t).group(0).split(' ')[3]
        elif re.search(r'Version (\d*)', t) is not None:
            version = re.search(r'Version (\d*)', t).group(0).split(' ')[1]
        else:
            version = t
        if 'Windows 10' in os and str(version) in win10_build:
            version = win10_build[str(version)]
        result_data = {
            "os": os,
            "patch": [
                {
                    "version": version,
                    "container": [
                        {
                            "date": today,
                            "kb": [
                                kb
                            ]
                        }
                    ]
                }
            ]
        }
        if output_data_list:
            os_list = [v['os'] for v in output_data_list if 'os' in v.keys()]
            if os not in os_list:
                output_data_list.append(result_data)
            else:
                for output_data in output_data_list:
                    if os != output_data['os']:
                        continue
                    if 'patch' not in output_data.keys():
                        output_data['patch'] = []
                    version_list = \
                        [
                            v['version']
                            for v in output_data['patch']
                            if 'version' in v.keys()
                        ]
                    if version not in version_list:
                        output_data['patch'].extend(result_data['patch'])
                    else:
                        for patch in output_data['patch']:
                            if version != patch['version']:
                                continue
                            if 'container' not in patch.keys():
                                patch['container'] = []
                            date_list = \
                                [
                                    v['date']
                                    for v in patch['container']
                                    if 'date' in v
                                ]
                            if today not in date_list:
                                patch['container'].extend(
                                    result_data['patch'][0]['container'])
                            else:
                                for container in patch['container']:
                                    if today != container['date']:
                                        continue
                                    if 'kb' not in container:
                                        container['kb'] = []
                                    output_data_kb_list = [
                                        v for v in container['kb']]
                                    if kb not in output_data_kb_list:
                                        container['kb'].append(kb)
        else:
            output_data_list.append(result_data)
        # print(output_data_list)
        # if 'Windows 10' in os and str(version) in win10_build:
        #     print(f"kb: {kb}: {os} {version}" +
        #           "{win10_build[str(version)]} \ntext: {t}")
        # else:
        #     print(f"kb: {kb}: {os} {version} \ntext: {t}")
progressbar.finish()

# 保存
with open(add_file_schema_path, 'r', encoding='utf_8') as validator:
    v = json.load(validator)
    jsonschema.validate(output_data_list, v)
    with open(add_file_path, 'w', encoding='utf_8') as add:
        json.dump(output_data_list, add)
print(f'save at {add_file_path}')
