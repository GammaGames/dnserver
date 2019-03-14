# dnserver

Simple DNS server written in python for use in development and testing.

The DNS serves it's own records, if none are found it proxies the request to an upstream DNS server (`1.1.1.1` by default)

You can setup records you want to serve with a custom `zones.yaml` file, 
see [zones.yaml](zones.yaml) for the format.

```yaml
- name: example.com
  entries:
  - type: A
    args:
    - 1.2.3.4
  - type: MX
    args:
    - whatever.com
    - 5
```

To run on the command line (assuming you have `dnslib>=0.9.7` and python>=3.6 installed):

```sh
./dnserver.py --port=5053
```

You can then test (either of the above) with

```shell
~ ➤  dig @localhost -p 5053 example.com MX
...
;; ANSWER SECTION:
example.com.		300	IN	MX	5 whatever.com.
example.com.		300	IN	MX	10 mx2.whatever.com.
example.com.		300	IN	MX	20 mx3.whatever.com.

;; Query time: 2 msec
;; SERVER: 127.0.0.1#5053(127.0.0.1)
;; WHEN: Sun Feb 26 18:14:52 GMT 2017
;; MSG SIZE  rcvd: 94

~ ➤  dig @localhost -p 5053 tutorcruncher.com MX
...
;; ANSWER SECTION:
tutorcruncher.com.	299	IN	MX	10 aspmx2.googlemail.com.
tutorcruncher.com.	299	IN	MX	5 alt1.aspmx.l.google.com.
tutorcruncher.com.	299	IN	MX	5 alt2.aspmx.l.google.com.
tutorcruncher.com.	299	IN	MX	1 aspmx.l.google.com.
tutorcruncher.com.	299	IN	MX	10 aspmx3.googlemail.com.

;; Query time: 39 msec
;; SERVER: 127.0.0.1#5053(127.0.0.1)
;; WHEN: Sun Feb 26 18:14:48 GMT 2017
;; MSG SIZE  rcvd: 176
```

You can see that the first query took 2ms and returned results from [example_zones.txt](example_zones.txt),
the second query took 39ms as dnserver didn't have any records for the domain so had to proxy the query to
the upstream DNS server.
