*** Settings ***
Documentation    Checks if rspamd is able to upgrade migration schema from v0 (very initial) to v2
Variables       ${TESTDIR}/lib/vars.py
Library         ${TESTDIR}/lib/rspamd.py
Library         clickhouse.py
Resource        ${TESTDIR}/lib/rspamd.robot

Suite Setup     Clickhouse Setup
Suite Teardown  Clickhosue Teardown

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/clickhouse.conf
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Migration
  Upload new schema                ${TESTDIR}/data/initial_schema/schema.sql
  Insert data  rspamd              ${TESTDIR}/data/initial_schema/data.rspamd.sql
  Insert data  rspamd_asn          ${TESTDIR}/data/initial_schema/data.rspamd_asn.sql
  Insert data  rspamd_emails       ${TESTDIR}/data/initial_schema/data.rspamd_emails.sql
  Insert data  rspamd_urls         ${TESTDIR}/data/initial_schema/data.rspamd_urls.sql
  Insert data  rspamd_attachments  ${TESTDIR}/data/initial_schema/data.rspamd_attachments.sql
  Insert data  rspamd_symbols      ${TESTDIR}/data/initial_schema/data.rspamd_symbols.sql

  Prepare rspamd

  Sleep  1  #TODO: replace this check with waiting until migration finishes

  Column should exist  rspamd  Symbols.Scores
  Column should exist  rspamd  Attachments.Digest
  Column should exist  rspamd  Symbols.Scores
  Schema version should be  2


*** Keywords ***
Clickhouse Setup
  ${TMPDIR} =  Make Temporary Directory
  Set Directory Ownership  ${TMPDIR}  ${RSPAMD_USER}  ${RSPAMD_GROUP}

  ${template} =  Get File  ${TESTDIR}/configs/clickhouse-config.xml
  ${config} =  Replace Variables  ${template}
  Create File  ${TMPDIR}/clickhouse-config.xml  ${config}
  Copy File    ${TESTDIR}/configs/clickhouse-users.xml  ${TMPDIR}/users.xml
  Create Directory  ${TMPDIR}/metadata
  Create Directory  ${TMPDIR}/metadata/default
  Create Directory  ${TMPDIR}/data/default
  ${result} =  Run Process  clickhouse-server  --daemon  --config-file\=${TMPDIR}/clickhouse-config.xml  --pid-file\=${TMPDIR}/clickhouse.pid
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  Wait Until Keyword Succeeds  5 sec  1 sec  Check Pidfile  ${TMPDIR}/clickhouse.pid  timeout=5 sec
  Set Suite Variable  ${TMPDIR}  ${TMPDIR}



Clickhosue Teardown
  # Sleep 30
  ${clickhouse_pid} =  Get File  ${TMPDIR}/clickhouse.pid
  Shutdown Process With Children  ${clickhouse_pid}
  Simple Teardown


Prepare rspamd
  &{d} =  Run Rspamd  CONFIG=${TESTDIR}/configs/clickhouse.conf  TMPDIR=${TMPDIR}
  ${keys} =  Get Dictionary Keys  ${d}
  : FOR  ${i}  IN  @{keys}
  \  Run Keyword If  '${RSPAMD_SCOPE}' == 'Suite'  Set Suite Variable  ${${i}}  &{d}[${i}]
  \  ...  ELSE IF  '${RSPAMD_SCOPE}' == 'Test'  Set Test Variable  ${${i}}  &{d}[${i}]
  \  ...  ELSE  Fail  'RSPAMD_SCOPE must be Test or Suite'
