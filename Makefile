.PHONY : \
    run-cloudflare-top \
    build-unbound \
    run-unbound \
    all

all : cloudflare

# https://www.cloudflare.com/ips/
cf-ips-v4 :
	wget -O $@ https://www.cloudflare.com/ips-v4
cf-ips-v6 :
	wget -O $@ https://www.cloudflare.com/ips-v6
cloudflare : cf-ips-v4 cf-ips-v6
	cat $^ | sort >$@

js/% : xml/%
	./parse-xml $^ $@
dump.lua :
	./merge js/* | ./format-lua $@
dump.pyjson : cloudflare
	./merge cloudflare js/* | ./format-lua $@

run-cloudflare-top: top-1m.csv cloudflare
	cat top-1m.A.* top-1m.AAAA.* | ./grep-subnet cloudflare | awk '{print $$1}' | sort -u | sed 's/^www\.//; s/\.$$//; s/^/,/' | grep -F -f - top-1m.csv | less

# Cisco Umbrella DNS* data might seem better, but it has lots of garbage like
# non-existing TLDs. It's the rating of queries, it's not a rating of valid
# websites. *) http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
top-1m.csv.zip :
	wget https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
top-1m.csv : top-1m.csv.zip
	unzip top-1m.csv.zip

build-unbound :
	tar cz Dockerfile | docker build -t darkk/unbound -f Dockerfile -
run-unbound :
	docker run --rm -ti --net=host -v $$PWD:/mnt darkk/unbound:latest
#push-unbound :
#	docker push darkk/unbound
