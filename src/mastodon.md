# (Experimental) Mastodon Server for Apache NuttX Continuous Integration (macOS Rancher Desktop)

📝 _30 Dec 2024_

![TODO](https://lupyuen.github.io/images/mastodon-title.jpg)

TODO

# TODO

```text
Query Prometheus for Build Failures
http://localhost:9090
build_score{user!="rewind", user!="nuttxlinux", user!="nuttxmacos", user!="jerpelea"} < 0.5

curl -X POST \
        -F 'query=build_score{config!="leds64_zig", user!="rewind", user!="nuttxlinux", user!="nuttxmacos", user!="jerpelea"} < 0.5' \
        http://localhost:9090/api/v1/query

{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"build_score","apps_hash":"b08c29617bbf1f2c6227f74e23ffdd7706997e0c","arch":"risc-v","board":"rv-virt","config":"citest","exported_instance":"rv-virt:citest","exported_job":"nuttxpr","group":"risc-v-05","instance":"localhost:9091","job":"pushgateway","msg":"virtio/virtio-mmio.c: In function 'virtio_mmio_config_virtqueue': \n virtio/virtio-mmio.c:346:14: error: cast from pointer to integer of different size [-Werror=pointer-to-int-cast] \n 346 |       addr = (uint64_t)kasan_reset_tag((FAR void *)vq->vq_ring.desc); \n |              ^ \n virtio/virtio-mmio.c:350:14: error: cast from pointer to integer of different size [-Werror=pointer-to-int-cast] \n 350 |       addr = (uint64_t)kasan_reset_tag((FAR void *)vq->vq_ring.avail); \n |              ^ \n virtio/virti","nuttx_hash":"04815338334e63cd82c38ee12244e54829766e88","subarch":"qemu-rv","target":"rv-virt:citest","timestamp":"2024-12-06T06:14:54","url":"https://gist.github.com/nuttxpr/7bec636a5f7b23ea8c845923025f2406#file-ci-risc-v-05-log-L169","url_display":"gist.github.com/nuttxpr/7bec636a5f7b23ea8c845923025f2406#file-ci-risc-v-05-log-L169","user":"nuttxpr","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"b08c29617bbf1f2c6227f74e23ffdd7706997e0c","arch":"risc-v","board":"rv-virt","config":"citest64","exported_instance":"rv-virt:citest64","exported_job":"nuttxpr","group":"risc-v-05","instance":"localhost:9091","job":"pushgateway","msg":"test_example/test_example.py::test_popen FAILED                                  [ 30%] \n test_example/test_example.py::test_usrsocktest FAILED                            [ 38%] \n test_os/test_os.py::test_ostest FAILED                                           [ 46%]","nuttx_hash":"04815338334e63cd82c38ee12244e54829766e88","subarch":"qemu-rv","target":"rv-virt:citest64","timestamp":"2024-12-06T06:19:39","url":"https://gist.github.com/nuttxpr/7bec636a5f7b23ea8c845923025f2406#file-ci-risc-v-05-log-L236","url_display":"gist.github.com/nuttxpr/7bec636a5f7b23ea8c845923025f2406#file-ci-risc-v-05-log-L236","user":"nuttxpr","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"37acd5e6712bc91e6c5fd3b9cdde06ff9a3cada3","arch":"xtensa","board":"esp32-devkitc","config":"nxdiag","exported_instance":"esp32-devkitc:nxdiag","exported_job":"nuttxmacos2","group":"xtensa-01","instance":"localhost:9091","job":"pushgateway","msg":"./nxdiag.c:34:10: fatal error: sysinfo.h: No such file or directory \n 34 | #include \"sysinfo.h\" \n |          ^~~~~~~~~~~ \n compilation terminated. \n ERROR: xtensa-esp32-elf-gcc failed: 1 \n command: xtensa-esp32-elf-gcc -MT ./nxdiag.c.private.tmp.run-job-macos.apps.system.nxdiag.o  -M '-fno-common' '-Wall' '-Wstrict-prototypes' '-Wshadow' '-Wundef' '-Wno-attributes' '-Wno-unknown-pragmas' '-Wno-psabi' '-Os' '-fno-strict-aliasing' '-fomit-frame-pointer' '-ffunction-sections' '-fdata-sections' '-mlongca","nuttx_hash":"fd20684a7b65b45a8e1e4e52ea8a4bd4b47cb11a","subarch":"esp32","target":"esp32-devkitc:nxdiag","timestamp":"2024-12-09T23:07:00","url":"https://gitlab.com/nuttxmacos2/nuttx-build-log/-/snippets/4778616#L1075","url_display":"gitlab.com/nuttxmacos2/nuttx-build-log/-/snippets/4778616#L1075","user":"nuttxmacos2","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"1f8b9aa74c38460fe8fe47646f70e85e79bcc21f","arch":"risc-v","board":"rv-virt","config":"citest","exported_instance":"rv-virt:citest","exported_job":"nuttxmacos2","group":"risc-v-05","instance":"localhost:9091","job":"pushgateway","msg":"test_example/test_example.py::test_helloxx FAILED                                            [  0%] \n test_example/test_example.py::test_pipe FAILED                                               [  0%] \n test_example/test_example.py::test_popen FAILED                                              [  0%] \n test_example/test_example.py::test_usrsocktest FAILED                                        [  0%] \n test_open_posix/test_openposix_.py::test_ltp_interfaces_mq_send_4_2 FAILED                   [  0%] ","nuttx_hash":"5607eece841346ae807f1474ea36e422d6dfc97d","subarch":"qemu-rv","target":"rv-virt:citest","timestamp":"2024-12-10T19:48:36","url":"https://gitlab.com/nuttxmacos2/nuttx-build-log/-/snippets/4779209#L824","url_display":"gitlab.com/nuttxmacos2/nuttx-build-log/-/snippets/4779209#L824","user":"nuttxmacos2","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"1f8b9aa74c38460fe8fe47646f70e85e79bcc21f","arch":"xtensa","board":"esp32s3-devkit","config":"timer","exported_instance":"esp32s3-devkit:timer","exported_job":"nuttxpr","group":"xtensa-02","instance":"localhost:9091","job":"pushgateway","msg":"In file included from chip/esp32s3_libc_stubs.c:25: \n chip/esp32s3_libc_stubs.c: In function 'esp_setup_syscall_table': \n chip/esp32s3_libc_stubs.c:418:3: error: static assertion failed: \"Invalid size of struct __lock\" \n 418 |   static_assert(sizeof(struct __lock) >= sizeof(mutex_t), \n |   ^~~~~~~~~~~~~ \n make[1]: *** [Makefile:146: esp32s3_libc_stubs.o] Error 1 \n make[1]: Target 'libarch.a' not remade because of errors. \n make: *** [tools/LibTargets.mk:170: arch/xtensa/src/libarch.a] Error 2 \n ma","nuttx_hash":"5607eece841346ae807f1474ea36e422d6dfc97d","subarch":"esp32s3","target":"esp32s3-devkit:timer","timestamp":"2024-12-10T23:09:05","url":"https://gist.github.com/nuttxpr/108ce53648bac75a85e8be288351b939#file-ci-xtensa-02-log-L769","url_display":"gist.github.com/nuttxpr/108ce53648bac75a85e8be288351b939#file-ci-xtensa-02-log-L769","user":"nuttxpr","version":"3"},"value":[1733974316.308,"0"]},{"metric":{"__name__":"build_score","apps_hash":"e861ea8b53e6c86b28274e3651036761d17d88ea","arch":"risc-v","board":"rv-virt","config":"citest","exported_instance":"rv-virt:citest","exported_job":"NuttX","group":"risc-v-05","instance":"localhost:9091","job":"pushgateway","msg":"test_example/test_example.py::test_hello FAILED                          [  0%] \n test_example/test_example.py::test_helloxx FAILED                        [  0%] \n test_example/test_example.py::test_pipe FAILED                           [  0%] \n test_example/test_example.py::test_popen FAILED                          [  0%] \n test_example/test_example.py::test_usrsocktest FAILED                    [  0%] \n test_open_posix/test_openposix_.py::test_ltp_interfaces_mq_send_4_2 FAILED [  0%] \n test_open_po","nuttx_hash":"b99e7617aa2fa70f8724a2a7db4b08e723a09bb4","subarch":"qemu-rv","target":"rv-virt:citest","timestamp":"2024-12-11T22:09:43","url":"https://github.com/NuttX/nuttx/actions/runs/12285244144/job/34282901789#step:7:88","url_display":"github.com/NuttX/nuttx/actions/runs/12285244144/job/34282901789#step:7:88","user":"NuttX","version":"3"},"value":[1733974316.308,"0"]}]}}

----------------------

Create Our App: https://docs.joinmastodon.org/client/token/#app
curl -X POST \
	-F 'client_name=NuttX Dashboard' \
	-F 'redirect_uris=urn:ietf:wg:oauth:2.0:oob' \
	-F 'scopes=read write push' \
	-F 'website=https://nuttx-dashboard.org' \
	https://nuttx-feed.org/api/v1/apps

{"id":"3",
"name":"NuttX Dashboard",
"website":"https://nuttx-dashboard.org",
"scopes":["read","write","push"],
"redirect_uris":["urn:ietf:wg:oauth:2.0:oob"],
"vapid_key":"...",
"redirect_uri":"urn:ietf:wg:oauth:2.0:oob",
"client_id":"...",
"client_secret":"...",
"client_secret_expires_at":0}

Login to Account: https://docs.joinmastodon.org/client/authorized/
Authorise the User: https://docs.joinmastodon.org/client/authorized/#login
In a web browser:
https://nuttx-feed.org/oauth/authorize
?client_id=YOUR_CLIENT_ID
&scope=read+write+push
&redirect_uri=urn:ietf:wg:oauth:2.0:oob
&response_type=code

<< Copy this authorization code and paste it to the application. >>

It will expire. Do it right away!

Obtain the token: https://docs.joinmastodon.org/client/authorized/#token
export CLIENT_ID=...
export CLIENT_SECRET=...
export AUTH_CODE=...
curl -X POST \
	-F "client_id=$CLIENT_ID" \
	-F "client_secret=$CLIENT_SECRET" \
	-F "redirect_uri=urn:ietf:wg:oauth:2.0:oob" \
	-F "grant_type=authorization_code" \
	-F "code=$AUTH_CODE" \
	-F "scope=read write push" \
	https://nuttx-feed.org/oauth/token

{"access_token":"...",
"token_type":"Bearer",
"scope":"read write push",
"created_at":1733966892}

export ACCESS_TOKEN=...
curl \
	-H "Authorization: Bearer $ACCESS_TOKEN" \
	https://nuttx-feed.org/api/v1/accounts/verify_credentials

{
  "id": "...",
  "username": "lupyuen",
  "acct": "lupyuen",
  "display_name": "",
  "locked": false,
  "bot": false,
  "discoverable": null,
  "indexable": false,
  "group": false,
  "created_at": "2024-12-08T00:00:00.000Z",
  "note": "",
  "url": "https://nuttx-feed.org/@lupyuen",
  "uri": "https://nuttx-feed.org/users/lupyuen",
  "avatar": "https://nuttx-feed.org/avatars/original/missing.png",
  "avatar_static": "https://nuttx-feed.org/avatars/original/missing.png",
  "header": "https://nuttx-feed.org/headers/original/missing.png",
  "header_static": "https://nuttx-feed.org/headers/original/missing.png",
  "followers_count": 1,
  "following_count": 1,
  "statuses_count": 4,
  "last_status_at": "2024-12-11",
  "hide_collections": null,
  "noindex": false,
  "source": {
    "privacy": "public",
    "sensitive": false,
    "language": null,
    "note": "",
    "fields": [],
    "follow_requests_count": 0,
    "hide_collections": null,
    "discoverable": null,
    "indexable": false
  },
  "emojis": [],
  "roles": [
    {
      "id": "3",
      "name": "Owner",
      "color": ""
    }
  ],
  "fields": [],
  "role": {
    "id": "3",
    "name": "Owner",
    "permissions": "1048575",
    "color": "",
    "highlighted": true
  }
}

Create Status: https://docs.joinmastodon.org/methods/statuses/#create

curl -X POST \
	-H "Authorization: Bearer $ACCESS_TOKEN" \
	-F "status=Posting a status from curl" \
	https://nuttx-feed.org/api/v1/statuses

{"id":"113637285862132341",
"created_at":"2024-12-12T01:36:14.606Z",
"in_reply_to_id":null,
"in_reply_to_account_id":null,
"sensitive":false,
"spoiler_text":"",
"visibility":"public",
"language":"en",
"uri":"https://nuttx-feed.org/users/lupyuen/statuses/113637285862132341",
"url":"https://nuttx-feed.org/@lupyuen/113637285862132341",
"replies_count":0,
"reblogs_count":0,
"favourites_count":0,
"edited_at":null,
"favourited":false,
"reblogged":false,
"muted":false,
"bookmarked":false,
"pinned":false,
"content":"\u003cp\u003ePosting a status from curl\u003c/p\u003e",
"filtered":[],
"reblog":null,
"application":{"name":"NuttX Dashboard","website":"https://nuttx-dashboard.org"},
"account":{"id":"...","username":"lupyuen","acct":"lupyuen","display_name":"","locked":false,"bot":false,"discoverable":null,"indexable":false,"group":false,"created_at":"2024-12-08T00:00:00.000Z","note":"","url":"https://nuttx-feed.org/@lupyuen","uri":"https://nuttx-feed.org/users/lupyuen","avatar":"https://nuttx-feed.org/avatars/original/missing.png","avatar_static":"https://nuttx-feed.org/avatars/original/missing.png","header":"https://nuttx-feed.org/headers/original/missing.png","header_static":"https://nuttx-feed.org/headers/original/missing.png","followers_count":1,"following_count":1,"statuses_count":5,"last_status_at":"2024-12-12","hide_collections":null,"noindex":false,"emojis":[],"roles":[{"id":"3","name":"Owner","color":""}],"fields":[]},"media_attachments":[],"mentions":[],"tags":[],"emojis":[],"card":null,"poll":null}

https://github.com/h3poteto/megalodon-rs

Post With Status: https://github.com/h3poteto/megalodon-rs/blob/master/examples/mastodon_post_with_schedule.rs

-----------------

Public Timeline: https://docs.joinmastodon.org/client/public/#timelines
curl https://nuttx-feed.org/api/v1/timelines/public | jq
 
-----------------

https://gist.github.com/lupyuen/f01da036fd0299abc5c874ace8fd1b22

git clone https://github.com/mastodon/mastodon --branch v4.3.2
code mastodon
echo >mastodon/.env.production

docker-compose.yml
<<
  db:
    volumes:
      -  postgres-data:/var/lib/postgresql/data

  redis:
    volumes:
      - redis-data:/data

  web:
    ports:
      - '127.0.0.1:3001:3000'
    #### TODO: command: bundle exec puma -C config/puma.rb
    command: sleep infinity #### TODO

  sidekiq:
    volumes:
      - lt-data:/mastodon/public/system

volumes:
  postgres-data:
  redis-data:
  es-data:
  lt-data:
>>

docker volume rm postgres-data
docker volume rm redis-data
docker volume rm es-data
docker volume rm lt-data

To Init The Database:
cd mastodon
set docker-compose.yml to "command: sleep infinity"
sudo docker compose up # Error response from daemon: error while creating mount source path '/Users/luppy/mastodon/public/system': chown /Users/luppy/mastodon/public/system: permission denied
docker compose logs -f
Ctrl-C
sudo docker compose up # Works OK
docker compose logs -f
Ignore Redis and Streaming:
<<
redis-1      | 1:C 08 Dec 2024 23:16:32.034 # WARNING Memory overcommit must be enabled! Without it, a background save or replication may fail under low memory condition. Being disabled, it can also cause failures without low memory condition, see https://github.com/jemalloc/jemalloc/issues/1328. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for this to take effect.
streaming-1  | {"level":"error","time":1733699834202,"pid":1,"hostname":"738ede3870fb","name":"streaming","err":{"type":"Error","message":"connect ECONNREFUSED 127.0.0.1:6379","stack":"Error: connect ECONNREFUSED 127.0.0.1:6379\n    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1611:16)","errno":-111,"code":"ECONNREFUSED","syscall":"connect","address":"127.0.0.1","port":6379},"msg":"Redis Client Error!"}
>>

https://docs.joinmastodon.org/admin/install/#creating-a-user
docker exec -it mastodon-db-1 /bin/bash
exec su-exec postgres psql
CREATE USER mastodon CREATEDB;
\q

https://docs.joinmastodon.org/admin/install/#generating-a-configuration
docker exec -it mastodon-web-1 /bin/bash
RAILS_ENV=production bin/rails mastodon:setup
exit
Copy the settings to .env.production
<<
# Generated with mastodon:setup on 2024-12-08 23:40:38 UTC
...
>>

restore docker-compose.yml to "command: bundle exec puma -C config/puma.rb"
sudo docker compose down
sudo docker compose up
docker compose logs -f
https://nuttx-feed.org/home

Administration > Settings
  > Branding
  > About
  > Registrations > Who can sign up > Approval Required for Sign up > Require a Reason to Join

Moderation > Accounts > Approve

Approve Account:
https://docs.joinmastodon.org/admin/tootctl/#accounts-approve
docker exec -it mastodon-web-1 /bin/bash
bin/tootctl accounts modify nuttx_build --confirm

Ignore SMTP, need to approve manually
<<
sidekiq-1    | 2024-12-09T00:04:55.035Z pid=6 tid=2ppy class=ActionMailer::MailDeliveryJob jid=8b52310d0afc7d27b0af3d4b elapsed=0.043 INFO: fail
sidekiq-1    | 2024-12-09T00:04:55.036Z pid=6 tid=2ppy WARN: {"context":"Job raised exception","job":{"retry":true,"queue":"mailers","wrapped":"ActionMailer::MailDeliveryJob","args":[{"job_class":"ActionMailer::MailDeliveryJob","job_id":"a7c8ac28-83bd-42b8-a4de-554f533a01f8","provider_job_id":null,"queue_name":"mailers","priority":null,"arguments":["UserMailer","password_change","deliver_now",{"args":[{"_aj_globalid":"gid://mastodon/User/1"}],"_aj_ruby2_keywords":["args"]}],"executions":0,"exception_executions":{},"locale":"en","timezone":"UTC","enqueued_at":"2024-12-09T00:00:54.250576360Z","scheduled_at":null}],"class":"ActiveJob::QueueAdapters::SidekiqAdapter::JobWrapper","jid":"8b52310d0afc7d27b0af3d4b","created_at":1733702454.2507422,"enqueued_at":1733702694.9922712,"error_message":"Connection refused - connect(2) for \"localhost\" port 25","error_class":"Errno::ECONNREFUSED","failed_at":1733702454.3886917,"retry_count":3,"retried_at":1733702562.7745714}}
sidekiq-1    | 2024-12-09T00:04:55.036Z pid=6 tid=2ppy WARN: Errno::ECONNREFUSED: Connection refused - connect(2) for "localhost" port 25
sidekiq-1    | 2024-12-09T00:04:55.036Z pid=6 tid=2ppy WARN: /usr/local/bundle/gems/net-smtp-0.5.0/lib/net/smtp.rb:663:in `initialize'
>>

Create Account:
https://docs.joinmastodon.org/admin/setup/#admin-cli
docker exec -it mastodon-web-1 /bin/bash
bin/tootctl accounts create \
  lupyuen \
  --email luppy@appkaki.com \
  --confirmed \
  --role Owner

Approve Account:
https://docs.joinmastodon.org/admin/tootctl/#accounts-approve
docker exec -it mastodon-web-1 /bin/bash
bin/tootctl accounts approve lupyuen

curl -H 'Accept: application/activity+json' https://nuttx-feed.org/@lupyuen | jq

curl -H 'Accept: application/activity+json' https://nuttx-feed.org/@lupyuen/113619922496625622 | jq

curl https://nuttx-feed.org/.well-known/webfinger\?resource\=acct:lupyuen@nuttx-feed.org | jq

docker-compose.yml
https://github.com/lupyuen/mastodon/commit/278987886e67fdd8b76d65938f3308071c3cd5c2

Docker Logs:
https://gist.github.com/lupyuen/fb086d6f5fe84044c6c8dae1093b0328
https://gist.github.com/lupyuen/f4f887ccf4ecfda0d5103b834044bd7b
https://gist.github.com/lupyuen/edbf045433189bebd4ad843608772ce8
https://gist.github.com/lupyuen/420540f9157f2702c14944fc47743742
https://gist.github.com/lupyuen/89eb8fc76ac9342209bb9c0553298d4c
https://gist.github.com/lupyuen/21ad4e38fa00796d132e63d41e4a339f

CloudFlare: Security > Settings > High

Administration > Dashboard
Could not connect to Elasticsearch. Please check that it is running, or disable full-text search

Enable Elastisearch:
https://github.com/lupyuen/mastodon/commit/b7d147d1e4928013ae789d783cf96b5b2628e347
.env.production
<<
ES_ENABLED=true
ES_HOST=es
ES_PORT=9200
>>
docker-compose.yml: Uncomment section for es
<<
  es:
    volumes:
       - es-data:/usr/share/elasticsearch/data
  web:
    depends_on:
      - db
      - redis
      - es
>>
docker compose down
docker compose build
docker compose up
docker compose logs -f
<<
es-1         | bootstrap check failure [1] of [1]: max virtual memory areas vm.max_map_count [65530] is too low, increase to at least [262144]
>>

Increase max_map_count:
https://docs.rancherdesktop.io/how-to-guides/increasing-open-file-limit/
Restart Docker Desktop

docker exec -it mastodon-es-1 /bin/bash -c "sysctl vm.max_map_count"
<<
vm.max_map_count = 262144
>>

Administration > Dashboard
<<
Elasticsearch index mappings are outdated
>>

docker exec -it mastodon-web-1 /bin/bash
bin/tootctl search deploy --only=instances accounts tags statuses public_statuses

Backing up Mastodon:
https://docs.joinmastodon.org/admin/backups/
Postgres:
docker exec -it mastodon-db-1 /bin/bash -c "exec su-exec postgres pg_dumpall" >mastodon.sql
head -50 mastodon.sql

Redis:
docker cp mastodon-redis-1:/data/dump.rdb .
strings dump.rdb | tail -50

User-uploaded files:
tar cvf mastodon-public-system.tar mastodon/public/system

-----------------

Previously:
git clone https://github.com/mastodon/mastodon --branch v4.3.2
code mastodon

.devcontainer/compose.yaml:
<<
    ports:
      - '127.0.0.1:3001:3000'
>>

.env.development
<<
LOCAL_DOMAIN=nuttx-feed.org
>>

cd mastodon
docker compose -f .devcontainer/compose.yaml up -d
docker compose -f .devcontainer/compose.yaml exec app bin/setup
docker compose -f .devcontainer/compose.yaml exec app bin/dev
http://localhost:3001/home
docker compose -f .devcontainer/compose.yaml down

https://docs.joinmastodon.org/admin/setup/#admin-cli
docker exec -it devcontainer-app-1 /bin/bash
bin/tootctl accounts create \
  lupyuen \
  --email luppy@appkaki.com \
  --confirmed \
  --role Owner

https://docs.joinmastodon.org/admin/tootctl/#accounts-approve
bin/tootctl accounts approve lupyuen

docker exec -it devcontainer-app-1 /bin/bash
bin/tootctl search deploy --only=tags
```

TODO: [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/)

# What's Next

TODO

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/mastodon.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/mastodon.md)
