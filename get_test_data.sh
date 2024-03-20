domain="arouzing.win"
record_types="A AAAA MX TXT NS SOA CNAME CAA SRV PTR"

for type in $record_types
do
    echo "Querying $type records for $domain"
    dig +noall +answer $domain $type -u 1.1.1.1
done
