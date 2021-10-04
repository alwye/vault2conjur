import logging
import os
import click
from vault_crawler import VaultCrawler
from conjur_importer import ConjurImporter
import constants as c

# create logger
logger = logging.getLogger('vault2conjur')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

@click.group()
def cli():
    """
    This CLI tool will assist you with cloning an existing namespace in a Hashicorp Vault instance into CyberArk Conjur.

    See description of the commands below to walk through the process.    
    """
    pass


# STEP 1: Generate the YAML policy
@click.command()
@click.option('--v-url',        required=True, default=c.VAULT_URL, help=f'Vault instance URL. Default: {c.VAULT_URL}')
@click.option('--v-namespace',  required=True, help='The name of your Vault namespace.')
@click.option('--v-token',      required=True, help='Vault CTU token')
@click.option('--out',          required=True, default=c.POLICY_OUT_FILE, help=f'Where the policy YAML will be spit out into. Default: {c.POLICY_OUT_FILE}')
def generate_policy(v_url, v_namespace, v_token, out):
    """
    1) Generates a policy file for loading manually in Conjur
    """

    # crawl the namespace and generate the logical structure
    try:
        # authenticate into a Hashicorp Vault namespace
        vc = VaultCrawler(instance_url=v_url, namespace=v_namespace)
        vc.token_auth(token=v_token)
        vault_namespace_dump = vc.generate_tree()
        logger.info("1/3: Successfully processed logical structure of the Vault namespace")
    except Exception as e:
        logger.error("Failed out to generate the logical structure of a Vault namespace", exc_info=e)
        exit(code=1)

    # generate a YAML that Conjur can understand
    try:
        ci = ConjurImporter(
            conjur_write_url=None,
            conjur_account=None,
            conjur_namespace=None,
            conjur_api_key=None
        )
        policy_yaml = ci.generate_yaml_policy(vault_namespace_dump)
        logger.info("2/3: Successfully generated the YAML policy file")
    except Exception as e:
        logger.error("Failed to generate the YAML policy file", exc_info=e)
        exit(code=1)

    # record the YAML-formatted policy into the file
    try:
        with open(out, 'w') as f:
            f.write(policy_yaml)
        logger.info("3/3: Successfully wrote the policy into the YAML file")
    except Exception as e:
        logger.error("Failed to write the policy into the file", exc_info=e)
        exit(code=1)


# STEP 2: Set the values of variables
@click.command()
@click.option('--v-url',        required=True, default=c.VAULT_URL, help=f'Vault instance URL. Default: {c.VAULT_URL}')
@click.option('--v-namespace',  required=True, help='The name of your Vault namespace.')
@click.option('--v-token',      required=True, help='Vault CTU token')
@click.option('--c-url',        required=True, default=c.CONJUR_WRITE_URL, help=f'Conjur API endpoint for secret update requests. Default: {c.CONJUR_WRITE_URL}')
@click.option('--c-account',    required=True, default=c.CONJUR_ACCOUNT, help=f'Conjur account. Always use {c.CONJUR_ACCOUNT}')
@click.option('--c-namespace',  required=True, help='Conjur namespace ID. E.g. it/hello_world')
@click.option('--c-api_key',    required=True, help='The API key for your namespace in Conjur')
def init_secrets(
    v_url, v_namespace, v_token,
    c_url, c_account, c_namespace, c_api_key):
    """
    2) Sets the values of the secrets in Conjur
    """

    # crawl the namespace and generate the logical structure
    try:
        # authenticate into a Hashicorp Vault namespace
        vc = VaultCrawler(instance_url=v_url, namespace=v_namespace)
        vc.token_auth(token=v_token)
        vault_namespace_dump = vc.generate_tree()
        logger.info("1/2: Successfully processed logical structure of the Vault namespace")
    except Exception as e:
        logger.error("Failed to generate the logical structure of a Vault namespace", exc_info=e)
        exit(code=1)

    try:
        ci = ConjurImporter(
            conjur_write_url=c_url,
            conjur_account=c_account,
            conjur_namespace=c_namespace,
            conjur_api_key=c_api_key
        )

        auth_success, success_count, fail_count = ci.initialize_secrets(vault_namespace_dump)
        logger.info(
            f"2/2: Completed setting the secrets in Conjur. See the report:\n"
            f"- Conjur auth successful: {'yes' if auth_success else 'no'}\n" \
            f"- # of secrets set successfully: {success_count}\n" \
            f"- # of secrets failed to set: {fail_count}\n")

    except Exception as e:
        logger.error("Failed to assign the values of secrets in Conjur", exc_info=e)
        exit(code=1)


cli.add_command(generate_policy)
cli.add_command(init_secrets)

if __name__ == "__main__":
    cli()
