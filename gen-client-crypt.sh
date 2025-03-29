flag_timeout_set=false
flag_name_set=false

while getopts "t:n:" opt; do
  case $opt in
    t)
      flag_timeout_set=true
      timeout=$OPTARG
      ;;
    n)
      flag_name_set=true
      name="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done


if ! $flag_timeout_set || ! $flag_name_set; then
  echo "Error: Both -timeout and -name are required." >&2
  exit 1
fi

cd certs

# Generate client key and CRT
# Assumes crypt-setup has already been run.
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN={$name}"
openssl x509 -req -in client.csr -CA clientCA.pem -CAkey clientCA.key -CAcreateserial \
  -out client.crt -days $timeout -sha256
