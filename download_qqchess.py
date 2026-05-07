import requests
import os
import re
from urllib.parse import urljoin

base_url = "https://h5login.qqchess.qq.com/"
save_dir = "qqchess_src"

def download_html():
    r = requests.get(base_url)
    r.raise_for_status()
    os.makedirs(save_dir, exist_ok=True)
    with open(os.path.join(save_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(r.text)
    return r.text

def extract_js_urls(html):
    js_files = set()
    for m in re.finditer(r'src="([^"]+\.js)"', html):
        js_files.add(urljoin(base_url, m.group(1)))
    for m in re.finditer(r"src='([^']+\.js)'", html):
        js_files.add(urljoin(base_url, m.group(1)))
    return js_files

def download_js():
    html = download_html()
    js_urls = extract_js_urls(html)
    js_dir = os.path.join(save_dir, "assets", "main")
    os.makedirs(js_dir, exist_ok=True)
    for url in js_urls:
        print(f"Downloading {url} ...")
        r = requests.get(url)
        r.raise_for_status()
        filename = url.split("/")[-1].split("?")[0]  # 去掉参数
        filepath = os.path.join(js_dir, filename)
        with open(filepath, "wb") as f:
            f.write(r.content)
    print("Done!")

if __name__ == "__main__":
    download_js()