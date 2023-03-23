![SecretsChecker](https://i.imgur.com/qXXqpXV.png)

# Automatically check for secrets in files

---

## Quick Run
```
git clone https://github.com/venominfosec/SecretsChecker.git
python SecretsChecker.py --file secret_file.txt
python SecretsChecker.py --path /etc
```


## Input
There are two input options:
1. A single file (`--file`)
2. All files in a given path (`--path`)

If `--path` is specified, SecretsChecker will recursively enumerate all files in a given path. The `--depth` argument can be used to limit how deep the recursive enumeration will go.

The `--ignore` argument can be used to ignore all identified files whose path or filename contains the provided string.

### Single File
```
# python SecretsChecker.py --file C:\secrets\secrets.txt
        [1/1] Checking C:\secrets\secrets.txt
Results written to secrets_checker.csv
Checked 1 files in 0.01 seconds
```

### Multiple Files
```
# python SecretsChecker.py --path C:\secrets --ignore "node_modules" --depth 1 --output custom_output_name.csv
Enumerating files in path "C:\secrets"
Filtered out 10 files containing the string "node_modules"
        [1/5] Checking C:\secrets\access_keys.txt
        [2/5] Checking C:\secrets\password.txt
        [3/5] Checking C:\secrets\secrets.txt
        [4/5] Checking C:\secrets\tokens.txt
        [5/5] Checking C:\secrets\config\web.config
Results written to custom_output_name.csv
Checked 5 files in 0.01 seconds
```


## Output
Results are written to a CSV called *secrets_checker.csv*  or whatever string is specified as the value for the `--output` argument.

An example output is below:

| File                       | Type                         | FoundList                                                        |
|----------------------------|------------------------------|------------------------------------------------------------------|
| C:\secrets\access_keys.txt | AWS API Key - Check 1        | aws_access_key_id = AKIAIOSFODNN7EXAMPLE                         |
| C:\secrets\access_keys.txt | AWS API Key - Check 2        | aws_access_key_id = AKIAIOSFODNN7EXAMPLE                         |
| C:\secrets\access_keys.txt | Generic Access Key - Check 1 | aws_access_key_id = AKIAIOSFODNN7EXAMPLE                         |
| C:\secrets\access_keys.txt | AWS API Key - Check 3        | aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY |
| C:\secrets\access_keys.txt | Potential Secret             | aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY |
| C:\secrets\access_keys.txt | Generic Access Key - Check 1 | aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY |
| C:\secrets\password.txt    | Potential Password - Check 1 | MyPassword123!                                                   |
| C:\secrets\password.txt    | Potential Secret             | {"passwd": "SuperSecret")                                        |
| C:\secrets\password.txt    | Potential Password - Check 2 | {"passwd": "SuperSecret")                                        |
| C:\secrets\secrets.txt     | Potential SSN                | 333-22-4444                                                      | 
| C:\secrets\secrets.txt     | RSA private key              | -----BEGIN RSA PRIVATE KEY-----                                  |
| C:\secrets\secrets.txt     | Potential Private Key        | -----BEGIN RSA PRIVATE KEY-----                                  |


## Supported Secret Types
* AWS API Key
* AWS AppSync GraphQL Key
* Amazon MWS Auth Token
* Facebook Access Token
* Facebook OAuth
* Generic API Key
* Generic Access Key
* Generic Secret
* GitHub
* Google (GCP) Service-account
* Google API Key
* Google Cloud Platform API Key
* Google Cloud Platform OAuth
* Google Drive API Key
* Google Drive OAuth
* Google Gmail API Key
* Google Gmail OAuth
* Google OAuth Access Token
* Google YouTube API Key
* Google YouTube OAuth
* Heroku API Key
* MailChimp API Key
* Mailgun API Key
* PGP private key block
* Password in URL
* PayPal Braintree Access Token
* Picatic API Key
* Potential Authorization Token
* Potential Password
* Potential Private Key
* Potential SSN
* Potential Secret
* RSA private key
* SSH (DSA) private key
* SSH (EC) private key
* Slack Token
* Slack Webhook
* Square Access Token
* Square OAuth Secret
* Stripe API Key
* Stripe Restricted API Key
* Telegram Bot API Key
* Twilio API Key
* Twitter Access Token
* Twitter OAuth


## How does it work?
* Arguments are provided
* If `--path` argument is specified, a list of applicable files is enumerated
* The enumerated files are opened and checked for secrets using Python's `re.search()` function
* Results are written to disk


## Help
```
# python SecretsChecker.py --help
usage: SecretsChecker.py [-h] (--path PATH | --file FILE) [--depth DEPTH]
                         [--ignore IGNORE] [--output OUTPUT]

Automatically check for secrets in files

optional arguments:
  -h, --help       show this help message and exit
  --path PATH      Path where files should be checked
  --file FILE      Check only the file provided

File enumeration options:
  --depth DEPTH    Depth when enumerating files, default=0
  --ignore IGNORE  Do not check files whose name or path contains the provided
                   string

Output options:
  --output OUTPUT  File to write results to, default="secrets_checker.csv"
```
