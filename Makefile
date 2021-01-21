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

# https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
amazon.json :
	wget -O $@ https://ip-ranges.amazonaws.com/ip-ranges.json
amazon: amazon.json
	jq -r '(.prefixes[] | select(.service == "CLOUDFRONT") | .ip_prefix), (.ipv6_prefixes[] | select(.service == "CLOUDFRONT") | .ipv6_prefix)' $^ >$@

js/% : xml/%
	./parse-xml $^ $@
dump.lua :
	./merge js/* | ./format-lua $@
dump.pyjson : cloudflare amazon
	./merge cloudflare amazon js/* | ./format-pyjson $@

run-cloudflare-top : top-1m.csv cloudflare
	cat top-1m.A.* top-1m.AAAA.* | ./grep-subnet cloudflare | awk '(length($$1) > 0) {print $$1}' | sort -u | sed 's/^www\.//; s/\.$$//; s/^/,/' | grep -F -f - top-1m.csv | less
run-amazon-top : top-1m.csv amazon
	cat top-1m.A.* top-1m.AAAA.* | ./grep-subnet amazon | awk '(length($$1) > 0) {print $$1}' | sort -u | sed 's/^www\.//; s/\.$$//; s/^/,/' | grep -F -f - top-1m.csv | less

# Cisco Umbrella DNS* data might seem better, but it has lots of garbage like
# non-existing TLDs. It's the rating of queries, it's not a rating of valid
# websites. *) http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
top-1m.csv.zip :
	wget https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
top-1m.csv : top-1m.csv.zip
	unzip -n top-1m.csv.zip

build-unbound :
	tar cz Dockerfile | docker build -t darkk/unbound -f Dockerfile -
run-unbound :
	docker run --rm -ti --net=host -v $$PWD:/mnt darkk/unbound:latest
#push-unbound :
#	docker push darkk/unbound
