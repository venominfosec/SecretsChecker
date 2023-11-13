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
        self.__version__ = '1.5.0'
        self.args = args
        self.csv_headers = ['File', 'Type', 'FoundList']
        self.files = []
        self.stdin = ''
        self.results = []
        self.iteration = 0
        self.ignore_count = 0
        self.checked_count = 0
        self.line_limit = 28000
        self.deny_list = ['arn:aws:secretsmanager:',
                          'passwd: true',
                          'passwd:all',
                          '"secrets": \[',
                          '"secret[oO]ptions": \[',
                          '[gG]enerate[sS]ecret',
                          'secretsmanager:',
                          ':secretsmanager',
                          'X-Amz-Expires',
                          ':secret:'
                          ]
        self.regular_expressions = {"Slack Token": "(xox[pboar]|xapp)(-[a-zA-Z0-9]+)+",
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
                                    "GitHub - Check 1": "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
                                    "GitHub - Check 2": "gh[pousr]_[A-Za-z0-9_]{35,255}",
                                    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
                                    "Generic API Token": "[aA][pP][iI]_?[tT][oO][kK][eE][nN].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
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
                                    "Braintree SDK Token": "(production|sandbox)_[a-z0-9]{8}_[a-z0-9]{16}",
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
                                    "Potential SSN": "(?!000|666|900-999)[0-9]{3}-[0-9]{2}-[0-9]{4}",
                                    "NuGet API Key": "oy2[a-z0-9]{43}(?![a-z0-9])",
                                    "SendGrid API Key": "SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}",
                                    "StackHawk API Key": "hawk(\\.[\\w\\-]{20})+"
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
            if self.checked_count == 1:
                print(f'Checked {self.checked_count} file in {"%.2f" % total_time} seconds')
            else:
                print(f'Checked {self.checked_count} files in {"%.2f" % total_time} seconds')

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
                    full_path_and_name = str(str(dir_name) + os.sep + filename).replace(os.sep * 2, os.sep)
                    # Filter out ignore strings
                    if self.args['ignore']:
                        ignore_file = False
                        for ignore_string in self.args['ignore']:
                            if ignore_string in full_path_and_name:
                                ignore_file = True
                        if not ignore_file:
                            self.files.append(full_path_and_name)
                        else:
                            self.ignore_count += 1
                    else:
                        self.files.append(full_path_and_name)
                # Stop recursion if depth was reached
                if dir_name.count(os.sep) - self.args['path'].count(os.sep) == self.args['depth']:
                    del subdir_list[:]
            if self.args['ignore']:
                print(f'Filtered out {self.ignore_count} files containing the strings: {", ".join(self.args["ignore"])}')

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
                is_checked = True
                if not self.args['quiet']:
                    print(f'\t[{self.iteration}/{len(self.files)}] Checking ' + file)
                else:
                    percentage = float(float(self.iteration) / float(len(self.files)) * 100)
                    print(f'\t[{self.iteration}/{len(self.files)}] {"%.2f" % percentage}%' + ' ' * 25, end='\r')
                try:
                    with open(file, 'r', encoding='utf-8', errors='ignore') as data_file:
                        for line in data_file:
                            line = line.rstrip()
                            is_binary = b'\x00' in bytes(str(line).encode('utf-8'))
                            if self.args['path'] and is_binary and not self.args['text']:
                                if not self.args['quiet']:
                                    print('\t\tBinary file detected, skipping checks')
                                is_checked = False
                                break
                            elif self.args['no_check_long'] and len(line) > self.line_limit:
                                if not self.args['quiet']:
                                    print('\t\tOverly long line identified, skipping checks')
                                is_checked = False
                                break
                            elif self.args['max_file_size'] and not self.is_file_size_within_limit(file, self.args['max_file_size']):
                                if not self.args['quiet']:
                                    print('\t\tOverly large file detected, skipping checks')
                                is_checked = False
                                break
                            else:
                                found_secret = self.check_for_secrets(line)
                                if found_secret[0]:
                                    for entry in found_secret[1]:
                                        temp_dict = {'File': file,
                                                     'Type': entry[0],
                                                     'FoundList': entry[1]
                                                     }
                                        self.results.append(temp_dict)
                        if is_checked:
                            self.checked_count += 1
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

    @staticmethod
    def is_file_size_within_limit(file_path, max_size_gb):
        """Check if file size is within limit"""
        try:
            file_size_bytes = os.path.getsize(file_path)
            max_size_bytes = max_size_gb * 1024 ** 3  # Convert GB to bytes
            return file_size_bytes <= max_size_bytes
        except FileNotFoundError:
            return False


if __name__ == '__main__':
    """Run from CLI"""
    # Defaults
    default_output = 'secrets_checker.csv'
    default_depth = 0

    # Parse arguments
    parser = argparse.ArgumentParser(description='Automatically check for secrets in files')
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--path',
                             help='Path where files should be checked',
                             type=str)
    input_group.add_argument('--file',
                             help='Check only the file provided',
                             type=str)
    input_group.add_argument('--stdin',
                             help='Check the input from standard in for secrets',
                             action='store_true')
    path_options_group = parser.add_argument_group('Path input options')
    path_options_group.add_argument('--depth',
                                    help=f'Depth when enumerating files, default={default_depth}, use "-1" for '
                                         f'unlimited',
                                    type=int,
                                    default=default_depth)
    path_options_group.add_argument('--ignore',
                                    help='Do not check files whose name or path contains the provided string, '
                                         'can use multiple times',
                                    type=str, action='append')
    options_group = parser.add_argument_group('General options')
    options_group.add_argument('--quiet',
                               help='Only print the status of file checking, not the file being checked',
                               action='store_true')
    options_group.add_argument('--text',
                               help='Process a binary file as if it were text',
                               action='store_true')
    options_group.add_argument('--no-check-long',
                               help='Do not check overly long lines',
                               action='store_true')
    options_group.add_argument('--max-file-size',
                               help='Do not check files larger than the provided size (in GB)',
                               type=float)
    output_group = parser.add_argument_group('Output options')
    output_group.add_argument('--output',
                              help=f'File to write results to, default="{default_output}"',
                              type=str,
                              default=default_output)
    output_group.add_argument('--stdout',
                              help='Print results to standard out',
                              action='store_true')
    raw_args = parser.parse_args()

    # Validate arguments
    if raw_args.path:
        if not os.path.isdir(raw_args.path):
            if os.path.isfile(raw_args.path):
                parser.error(f'Provided file "{raw_args.path}" for path argument')
            else:
                parser.error(f'Provided string "{raw_args.path}" is not a path or file')
        if raw_args.path[-1] == '/' or raw_args.path[-1] == '\\':
            if len(raw_args.path) > 1:
                raw_args.path = raw_args.path[:-1]
    if raw_args.file:
        if not os.path.isfile(raw_args.file):
            if os.path.isdir(raw_args.file):
                parser.error(f'Provided directory "{raw_args.file}" for file argument')
            else:
                parser.error(f'Provided string "{raw_args.file}" is not a path or file')
    if raw_args.stdout:
        if raw_args.output == default_output:
            raw_args.output = None

    # Launch
    arguments = raw_args.__dict__
    sc = SecretsChecker(arguments)
    sc.run()
