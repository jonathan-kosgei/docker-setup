#!/bin/sh

rdb_file=/redis/dump.rdb
tmp_file=/tmp/lastsave.dat
dest_file=/tmp/dump.rdb

if [ ! -f "$tmp_file" ] ; then
 value=0
else
 value=`cat $tmp_file`
fi

#trigger redis's bgsave
/usr/local/redis/bin/redis-cli -h localhost -p 6379 bgsave

#loop to compare lastsave values
while true
do
 #gives bgsave a chance to finish before calling redis's lastsave
 sleep 10
 lastsave=`/usr/local/redis/bin/redis-cli -h localhost -p 6379 lastsave`
 if [ "$lastsave" -ne "$value" ]; then
 newvalue=$lastsave
 break
 fi
done

#print out new lastsave
echo "new lastsave value: $newvalue"

#save lastsave to temp file
echo "$newvalue" > $tmp_file

#copy rdb file to other place
cp $rdb_file $dest_file

#get the current date and time
current_time=$(date +"%d%m%Y%H%M%S")
current_date=$(date +"%d%m%Y")

cd /tmp
new_file="dump.rdb.$current_time"

#rename the new file
mv "dump.rdb" $new_file

#upload the new file to S3
#s3cmd --config /etc/s3cfg put --acl-public $new_file "s3://pgbucketredcarpetupcom/s3cmd/$current_date/$new_file"
/opt/Python/bin/s3cmd --config /etc/s3cfg --preserve put  $new_file "s3://pgbucketr/s3cmd/$current_date/$new_file"

#remove the new file
rm "/tmp/$new_file"
