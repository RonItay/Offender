# Introduction

Offender is a small pet project of mine and therefore requires alot of work.

If you find this project useful and would like it to have greater functionality, please feel free to contribute!

# Contributing

When contributing, Please follow the following steps:
1. If an Issue relating to your PR doesn't exist, Please create one. 
   If your PR fixes a bug, please add an example in your Issue.
2. Before creating your PR, make sure that all checks pass for
   1. mypy
   2. black
   3. flask
3. Create the PR, and link the created/already existing issue to it.
   1. Make sure you PR has relevant tests
   2. Make sure all tests pass

# Tests

When adding a feature, make sure to add relevant tests.
When fixing a bug, make sure to add a for that bug.

# Developing a Searcher
Because searchers are dynamically loaded at runtime, a searcher must adhere to naming conventions and standards.
1. A searcher must be in the `offender/searcher` directory.
2. Must inherit from the Searcher object.
3. naming:
   1. A searcher filename must be in snake_case.
   2. The searcher Class name must be in CamelCase
   3. The searcher's filename must be the camel_case of the searcher's Class name.
4. The searcher's filename must be added to the `known_searchers` list.