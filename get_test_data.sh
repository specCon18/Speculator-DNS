domain="arouzing.win"
record_types="A AAAA MX TXT NS SOA CNAME CAA SRV PTR"

for type in $record_types
do
    echo "Querying $type records for $domain"
    dig @127.0.0.1 -p 2053 $domain $type
done
