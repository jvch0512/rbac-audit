.PHONY: build test sample

build:
	mkdir -p build && crystal build src/main.cr -o build/rbac-audit

test: build
	crystal spec

sample: build
	mkdir -p docs site
	build/rbac-audit examples > docs/sample-output.txt; true
	build/rbac-audit examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "rbac-audit" "Audits Kubernetes RBAC exports for cluster-admin grants, wildcard roles, secret readers, exec rights and privilege escalation verbs. Crystal." "Synthetic cluster exports."
