"""
vault_crawler.py
Implements browsing and serialisation of a Vault namespace
"""

import hvac

class VaultCrawler:
    def __init__(self, instance_url, namespace):
        self.client = hvac.Client(url=instance_url, namespace=namespace)

    # Authenticate vault token
    def token_auth(self, token):
        self.client.token = token
        return self.client.is_authenticated()


    def generate_tree(self, starting_folder='/'):
        draft_tree = self.crawl([starting_folder])
        
        return {
            "child_paths": draft_tree,
            "kv": {}
        }

    def crawl(self, vault_list):
        tree = {}
        for i in vault_list:
            if i[-1] == '/':
                keys = self.list_folder_contents(i)
                child_tree = self.crawl(keys)

                if i == '/':
                    tree = child_tree
                else:
                    clean_path_part = i.split('/')[-2]

                    if tree.get(clean_path_part, None) is None:
                        tree[clean_path_part] = {
                            "child_paths": child_tree,
                            "kv": {}
                        }
                    else:
                       tree[clean_path_part]["child_paths"] = child_tree
                
            else:
                secret_kvs = self.list_secret_kvs(i)
                if secret_kvs is None:
                    continue
                else:
                    clean_path_part = i.split('/')[-1]

                    if tree.get(clean_path_part, None) is None:
                        tree[clean_path_part] = {
                            "child_paths": {},
                            "kv": {}
                        }

                    for key in secret_kvs:
                        tree[clean_path_part]["kv"][key] = str(secret_kvs[key])
                

        return tree

    def list_folder_contents(self, path):
        """
        folders contain other folders + secrets (each secret is a collection of key-value pairs)
        this function lists all folders and secrets that sit in the 'path'
        Vault CLI alternative: vault list
        """
        result = []
        resp = self.client.secrets.kv.v2.list_secrets(path=path)
        for i in resp["data"]["keys"]:
            result.append(path + i)
        return result


    def list_secret_kvs(self, path):
        """
        secrets contain only key-value pairs
        this function returns all key-value pairs in the 'path', values are converted to string
        Vault CLI alternative: vault read
        """
        secret_path = f"secret/data/{path}"
        secret = self.client.read(path=secret_path)

        # ignore deleted/destroyed secrets
        if secret is not None:
            return secret['data']['data']
