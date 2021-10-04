# vault2conjur

This tool helps you clone your namespace from Hashicorp Vault into CyberArk Conjur.

## Prerequisites

Verift that `constants.py` contains default values.

Complete the steps in this section to set up your environment.

### Install Python

Install the latest Python from [python.org](https://www.python.org/downloads/)

### Install the virtuenv package

```virtualenv``` helps you keep package dependencies tidy and avoid breaking any of your other local apps.

To install it, run the following command:

```bash
pip install virtualenv
```

If you get the error `command not found: pip`, try replacing `pip` with `pip3`.

### Create and activate virtualenv

Run this command to create a virtual environment for vault2conjur:

```bash
virtualenv venv
```

Now, you'll need to activate the virtualenv.

On Linux or MacOS, run:

```bash
source venv/bin/activate
```

On Windows, run the following command instead:

```
venv\Scripts\activate
```

### Install dependencies

This CLI tool requires a few dependencies to work correctly. Install them by running:

```bash
pip install -r requirements.txt
```

## Run

When you're done with the prerequisites, complete the following steps.

You can always add `--help` after typing a command to learn about its meaning, for example:

```bash
python main.py --help
python main.py generate-policy --help
python main.py init-secrets --help
```

### Step 1: Generate the policy

Example command:

```
python main.py generate-policy \
    --v-namespace myorg/example_vault_namespace \
    --v-token ${VAULT_TOKEN}
```

`${VAULT_TOKEN}` is a Linux way to inject an environment variable. In this case, it is CTU token. Note, that while you may paste the token directly into the command, this is not secure as a trace will be left in your CLI history.

Once the command has been successfully executed, a new file will be generated under the `output/` directory. You will need it for the next step.

### Step 2: Load the policy and generate the API key

1. The YAML file you've generated will need to be loaded to Conjur.

2. Once loaded, reset the value of the `apikey` host resource and reset it and take a note of it.

### Step 3: Assign the values of the secrets

Example command:

```
python main.py init-secrets \
    --v-namespace myorg/example_vault_namespace \
    --v-token ${VAULT_TOKEN} \
    --c-url https://example.conjur.org \
    --c-namespace myorg/example_conjur_namespace \
    --c-api_key ${CONJUR_API_KEY}
```

`${CONJUR_API_KEY}` is a Linux way to inject an environment variable. In this case, it is a key generated at the previous step. Note that while you may paste the token directly into the command, this is not secure as a trace will be left in your CLI history.

The `--c-url` argument may be omitted if configured in `constants.py`.

### Exit virtualenv

When you've successfully cloned the namespacce, you can exit the virtual environment by running `deactivate` in your CLI.

## Credits

Created by Alex Zverev and Pooja Shrivastava at Cisco. 

## License

MIT License

Copyright (c) 2021 Cisco Systems, Inc. and its affiliates

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.