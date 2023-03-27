#!/usr/bin/env python3

# SecretsChecker - Automatically check for secrets in files

# Imports
import re
import csv
import os
import time
import traceback
import argparse
import sys
import json


class SecretsChecker:
    """Automatically check for secrets in files"""
    def __init__(self, args: dict):
        """Initialize attributes for SecretsChecker instance"""
        self.__version__ = '1.1.0'
        self.args = args
        self.csv_headers = ['File', 'Type', 'FoundList']
        self.files = []
        self.stdin = ''
        self.results = []
        self.iteration = 0
        self.ignore_count = 0
        self.deny_list = ['arn:aws:secretsmanager:',
                          'passwd: true',
                          'passwd:all',
                          '"secrets": \[',
                          '"secret[oO]ptions": \[',
                          '[gG]enerate[sS]ecret',
                          'secretsmanager:',
                          ':secretsmanager',
                          'X-Amz-Expires'
                          ]
        self.regular_expressions = {"Slack Token": "(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
                                    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
                                    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
                                    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
                                    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                                    "Potential Private Key": "[pP][rR][iI][vV][aA][tT][eE].[kK][eE][yY]",
                                    "AWS API Key - Check 1": "((?:A3T[A-Z0-9]|AKIA|AIPA|ASIA|ABIA|ACCA|APKA)[A-Z0-9]{16})",
                                    "AWS API Key - Check 2": "AKIA[0-9A-Z]{16}",
                                    "AWS API Key - Check 3": "[aA][wW][sS].[sS][eE][cC][rR][eE][tT].[aA][cC][cC][eE][sS][sS].[kK][eE][yY]",
                                    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                                    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
                                    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
                                    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]",
                                    "GitHub": "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
                                    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
                                    "Generic Secret": "[sS][eE][cC][rR][eE][tT].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
                                    "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
                                    "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
                                    "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
                                    "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
                                    "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
                                    "Google (GCP) Service-account": "\"type\": \"service_account\"",
                                    "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
                                    "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
                                    "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
                                    "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
                                    "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
                                    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
                                    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
                                    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
                                    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\s]",
                                    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
                                    "Picatic API Key": "sk_live_[0-9a-z]{32}",
                                    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
                                    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
                                    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
                                    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
                                    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
                                    "Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
                                    "Twilio API Key": "SK[0-9a-fA-F]{32}",
                                    "Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
                                    "Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
                                    "Potential Secret": "[sS][eE][cC][rR][eE][tT]",
                                    "Potential Password - Check 1": "[pP][aA][sS][sS][wW][oO][rR][dD]",
                                    "Potential Password - Check 2": "[pP][aA][sS][sS][wW][dD]",
                                    "Potential Password - Check 3": "[pP][sS][wW][dD]",
                                    "Potential Password - Check 4": "[kK][eE][yY][pP][aA][sS][sS]",
                                    "Potential Password - Check 5": "[sS][tT][oO][rR][eE][pP][aA][sS][sS]",
                                    "Generic Access Key - Check 1": "[aA][cC][cC][eE][sS][sS].[kK][eE][yY]",
                                    "Generic Access Key - Check 2": "[aA][cC][cC][eE][sS][sS][kK][eE][yY]",
                                    "Potential Authorization Token - Check 1": "[aA][uU][tT][hH].[tT][oO][kK][eE][nN]",
                                    "Potential Authorization Token - Check 2": "[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN].[tT][oO][kK][eE][nN]",
                                    "Potential Authorization Token - Check 3": "[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN].[bB][eE][aA][rR][eE][rR]",
                                    "Potential SSN": "(?!0{3})(?!6{3})[0-8]\d{2}-(?!0{2})\d{2}-(?!0{4})\d{4}"
                                    }

    def run(self):
        """Coordinates input, processing, and output tasks"""
        # Get input and process input
        start_time = time.time()
        try:
            self.get_input()
            self.process_input()
        except KeyboardInterrupt:
            if self.results:
                print('Stopping checks and writing results to disk')
        except Exception:
            print('Uncaught exception:')
            print(traceback.format_exc())

        # Write results
        try:
            self.write_results()
        except Exception:
            print('Uncaught exception:')
            print(traceback.format_exc())
            print('Results:')
            print(self.results)

        # Print statistics
        total_time = time.time() - start_time
        if self.files:
            if len(self.files) == 1:
                print(f'Checked {len(self.files)} file in {"%.2f" % total_time} seconds')
            else:
                print(f'Checked {len(self.files)} files in {"%.2f" % total_time} seconds')

    def get_input(self):
        """Identifies in-scope files or retrieves input from standard in"""
        # Path provided
        if self.args['path']:

            # Validate correct sep was provided and fix if necessary
            if os.name == 'nt' and '/' in self.args['path']:
                self.args['path'] = self.args['path'].replace('/', os.sep)
            elif os.name != 'nt' and '\\' in self.args['path']:
                self.args['path'] = self.args['path'].replace('\\', os.sep)

            # Enumerate files
            print(f'Enumerating files in path "{self.args["path"]}"')
            for dir_name, subdir_list, file_list in os.walk(self.args['path'], topdown=True):
                for filename in file_list:
                    full_path_and_name = str(str(dir_name) + os.sep + filename).replace(os.sep*2, os.sep)
                    if self.args['ignore']:
                        # Filter out ignore string
                        if self.args['ignore'] not in full_path_and_name:
                            self.files.append(full_path_and_name)
                        else:
                            self.ignore_count += 1
                    else:
                        self.files.append(full_path_and_name)
                # Stop recursion if depth was reached
                if dir_name.count(os.sep) - self.args['path'].count(os.sep) == self.args['depth']:
                    del subdir_list[:]
            if self.args['ignore']:
                print(f'Filtered out {self.ignore_count} files containing the string "{self.args["ignore"]}"')

        # File provided
        elif self.args['file']:
            self.files.append(self.args['file'])

        # Standard in
        elif self.args['stdin']:
            stdin = sys.stdin.read()
            self.stdin = stdin

    def process_input(self):
        """Read input and check for secrets """
        if self.args['stdin']:
            for line in self.stdin.splitlines():
                try:
                    found_secret = self.check_for_secrets(line)
                    if found_secret[0]:
                        for entry in found_secret[1]:
                            temp_dict = {'File': 'StandardInput',
                                         'Type': entry[0],
                                         'FoundList': entry[1]
                                         }
                            self.results.append(temp_dict)
                except Exception:
                    print('Uncaught exception:')
                    print(traceback.format_exc())
        else:
            for file in self.files:
                self.iteration += 1
                print(f'\t[{self.iteration}/{len(self.files)}] Checking ' + file)
                try:
                    with open(file, 'r', encoding='utf-8', errors='ignore') as data_file:
                        for line in data_file:
                            line = line.rstrip()
                            found_secret = self.check_for_secrets(line)
                            if found_secret[0]:
                                for entry in found_secret[1]:
                                    temp_dict = {'File': file,
                                                 'Type': entry[0],
                                                 'FoundList': entry[1]
                                                 }
                                    self.results.append(temp_dict)
                except PermissionError as error:
                    print(f'[ERROR] {error}')
                except Exception:
                    print('Uncaught exception:')
                    print(traceback.format_exc())

    def check_for_secrets(self, string_to_check: str):
        """Check provided string for matches to known secret regular expressions"""
        found = False
        in_deny_list = False
        found_list = []

        for description, expression in self.regular_expressions.items():
            results = re.search(expression, string_to_check)
            if results:
                for deny_item in self.deny_list:
                    deny_list_check = re.search(deny_item, string_to_check)
                    if deny_list_check:
                        in_deny_list = True
                if not in_deny_list:
                    found = True
                    found_list.append((description, string_to_check))

        # Return: (boolean_found, list_of_secrets)
        return found, found_list

    def write_results(self):
        """Write results to disk or display to standard out"""
        if self.args['stdout']:
            pretty_json = json.dumps(self.results, indent=4, default=str)
            print(pretty_json)
        if self.args['output']:
            if self.results:
                with open(self.args['output'], 'w', encoding='utf-8', errors='ignore', newline='') as output:
                    writer = csv.DictWriter(output, fieldnames=self.csv_headers, quoting=csv.QUOTE_ALL, escapechar='\\')
                    writer.writeheader()
                    for result in self.results:
                        try:
                            writer.writerow(result)
                        except Exception as error:
                            print('[ERROR] ' + str(error))
                            print(str(traceback.format_exc()))
                print(f'Results written to {self.args["output"]}')
            else:
                print(f'No results found, checked {(len(self.files))} files')


if __name__ == '__main__':
    """Run from CLI"""
    # Defaults
    default_output = 'secrets_checker.csv'
    default_depth = 0

    # Parse arguments
    parser = argparse.ArgumentParser(description='Automatically check for secrets in files')
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--path', help='Path where files should be checked', type=str)
    input_group.add_argument('--file', help='Check only the file provided', type=str)
    input_group.add_argument('--stdin', help='Check the input from standard in for secrets', action='store_true')
    options_group = parser.add_argument_group('File enumeration options')
    options_group.add_argument('--depth', help=f'Depth when enumerating files, default={default_depth}', type=int,
                               default=default_depth)
    options_group.add_argument('--ignore', help='Do not check files whose name or path contains the provided string',
                               type=str)
    output_group = parser.add_argument_group('Output options')
    output_group.add_argument('--output', help=f'File to write results to, default="{default_output}"', type=str,
                              default=default_output)
    output_group.add_argument('--stdout', help='Print results to standard out', action='store_true')
    raw_args = parser.parse_args()

    # Validate arguments
    if raw_args.path:
        if not os.path.isdir(raw_args.path):
            parser.error(f'Provided file "{raw_args.path}" for path argument')
        if raw_args.path[-1] == '/' or raw_args.path[-1] == '\\':
            if len(raw_args.path) > 1:
                raw_args.path = raw_args.path[:-1]
    if raw_args.file:
        if not os.path.isfile(raw_args.file):
            parser.error(f'Provided directory "{raw_args.file}" for file argument')
    if raw_args.stdout:
        if raw_args.output == default_output:
            raw_args.output = None

    # Launch
    arguments = raw_args.__dict__
    secrets_checker_class = SecretsChecker(arguments)
    secrets_checker_class.run()
