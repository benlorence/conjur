# Upgrading

This section describes how to upgrade a conjur Server.

## Basic upgrade

The following steps should be done on each upgrade:
1. Edit `docker-compose.yml` conjur service image tag to {x+1}
2. Delete current conjur container: 
`docker rm -f conjur`
3. Rerun docker-compose:
`docker-compose up -d`
4. View docker containers and verify all are healthy, up and running:
 `docker ps -a`

* side note, it is possible you will need to reassign `CONJUR_DATA_KEY` system variable. Same key as before. 
`export CONJUR_DATA_KEY="$(< data_key)`

## Specific steps

**This step should be done  when upgrading from version xxx and below to a newer version**

Due to encryption changes in newer versions there is a need to run this command
`bundle exec rake slosilo:migrate`
