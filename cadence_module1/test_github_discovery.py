"""Regression tests for authenticated GitHub repository discovery."""
import unittest
from unittest.mock import patch

import github_discovery


class GitHubDiscoveryTests(unittest.TestCase):
    def test_repository_enumeration_forwards_token_to_api(self):
        repo = {"name": "private-repo", "clone_url": "https://github.com/acme/private-repo.git"}
        with patch.object(github_discovery, "_api_get", side_effect=[[repo], []]) as api_get:
            result = github_discovery.list_org_repos("acme", token="test-token", max_repos=10)
        self.assertEqual(result, [repo])
        self.assertEqual(api_get.call_args_list[0].args[0], "/orgs/acme/repos?per_page=50&page=1")
        self.assertEqual(api_get.call_args_list[0].kwargs, {"token": "test-token"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
