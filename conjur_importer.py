"""
conjur_importer.py
Implements translation of the serialised Vault namespace into a Conjur policy
"""
import logging
from urllib.parse import quote_plus
import yaml
import requests


# Represents the !policy tag
class ResourcePolicy(yaml.YAMLObject):
     yaml_tag = u'!policy'
     def __init__(self, id, owner, body):
         self.id = id
         if owner is not None:
            self.owner = owner
         self.body = body

# Represents the !variable tag
class ResourceVariable(yaml.YAMLObject):
     yaml_tag = u'!variable'
     def __init__(self, id):
         self.id = id

     @classmethod
     def from_yaml(cls, loader, node):
        return ResourceHost(node.value)

     @classmethod
     def to_yaml(cls, dumper, data):
        return dumper.represent_scalar(cls.yaml_tag, data.id)

# Represents the !host tag
class ResourceHost(yaml.YAMLObject):
    yaml_tag = u'!host'
    def __init__(self, id):
        self.id = id

    @classmethod
    def from_yaml(cls, loader, node):
        return ResourceHost(node.value)

    @classmethod
    def to_yaml(cls, dumper, data):
        return dumper.represent_scalar(cls.yaml_tag, data.id)

# Represents the !permit tag
class ResourcePermit(yaml.YAMLObject):
    yaml_tag = u'!permit'
    def __init__(self, role,resource, privileges=[]):
        self.role = role
        self.privileges = privileges
        self.resource = resource


class ConjurImporter:
    def __init__(self, conjur_write_url, conjur_account, conjur_namespace, conjur_api_key):
        self.conjur_write_url = conjur_write_url
        self.conjur_account = conjur_account
        self.conjur_namespace = conjur_namespace
        self.conjur_api_key = conjur_api_key
        self.owner_resource_id = "apikey"
        self._init_loader_dumper('!host', ResourceHost)
        self._init_loader_dumper('!variable', ResourceVariable)

    
    def _init_loader_dumper(self, tag_str, tag_cls):
        # Required for safe_load & safe_dump
        yaml.SafeLoader.add_constructor(tag_str, getattr(tag_cls, 'from_yaml'))
        yaml.SafeDumper.add_multi_representer(tag_cls, getattr(tag_cls, 'to_yaml'))

    def _get_token(self, url, account, username, api_key):
        account = quote_plus(account)
        username = quote_plus(username)
        r = requests.post(url=f"{url}/authn/{account}/{username}/authenticate",
                        data=api_key,
                        headers={'Accept-Encoding': 'base64'})
        # status code is 200 when the auth request has gone thru successfully

        if r.status_code == 200:
            return r.text  # return base64-encoded token
        else:
            logging.error(f"Authentication error, response code: {r.status_code}")
            return None

    def _set_secret(self, url, account, token, variable_id, variable_value):
        account = quote_plus(account)
        variable = quote_plus(variable_id)
        r = requests.post(
            url=f"{url}/secrets/{account}/variable/{variable}",
            data=variable_value,
            headers={"Authorization": f'Token token="{token}"', 'Content-Type': 'text/plain'})

        if r.status_code == 201:
            return True, r.status_code
        else:
            return False, r.status_code

    def _crawl_tree_branch(self, tree_branch, root=False):
        """
        Walks through each branch of the Vault namespace dump
        and uses the custom tags (ResourcePolicy, ResourceVariable)
        to construct a new Python object
        """

        policy = []
        if root:
            policy.append(ResourceHost(id=self.owner_resource_id))

        for child_branch in tree_branch['child_paths']:
            child_resources = self._crawl_tree_branch(tree_branch['child_paths'][child_branch])
            policy.append(ResourcePolicy(
                id=child_branch,
                owner = ResourceHost(id=self.owner_resource_id) if root else None,
                body=child_resources))

        for key in tree_branch['kv']:
            policy.append(ResourceVariable(id=key))
        return policy

    def _crawl_secrets(self, tree_branch, current_path=''):
        variables = {}
        for child_branch in tree_branch['child_paths']:
            child_variables = self._crawl_secrets(
                tree_branch=tree_branch['child_paths'][child_branch],
                current_path=f"{current_path}/{child_branch}")
            variables.update(child_variables)

        for key in tree_branch['kv']:
            variables[f"{current_path}/{key}"] = tree_branch['kv'][key]

        return variables

    def generate_yaml_policy(self, vault_namespace_dump):
        """
        The object constructed inside _crawl_tree_branch() is then
        processed and dumped into a string 
        """
        policy = self._crawl_tree_branch(vault_namespace_dump, root=True)
        return yaml.dump(policy, sort_keys=False)

    def initialize_secrets(self, vault_namespace_dump):
        token = self._get_token(
            url=self.conjur_write_url,
            account=self.conjur_account,
            username=f"host/{self.conjur_namespace}/{self.owner_resource_id}",
            api_key=self.conjur_api_key
        )

        if token is not None:
            success_count = 0
            fail_count = 0
            variables = self._crawl_secrets(vault_namespace_dump, self.conjur_namespace)
            for variable_id in variables:
                success, status_code = self._set_secret(
                    url=self.conjur_write_url,
                    account=self.conjur_account,
                    token=token,
                    variable_id=variable_id,
                    variable_value=variables[variable_id])
                if success:
                    success_count = success_count + 1
                else:
                    fail_count = fail_count + 1
                    logging.error(f"Unable to set secret {variable_id}, status code {status_code}")
            return True, success_count, fail_count
        else:
            return False, 0, 0
