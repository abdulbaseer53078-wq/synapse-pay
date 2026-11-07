#!/bin/sh
# Entrypoint for every image. ECS injects secrets (Secrets Manager) as environment variables, but the services
# read certificates and keys from files. Each FILE_<NAME>=<contents> becomes the file /run/app-secrets/<NAME>
# (mode 600) and <NAME>=<that path>, so HOST_CA, CA_CERT_PATH, JWT_PUBLIC_KEY_PATH... work unchanged.
set -eu
umask 077
dir=/run/app-secrets
for name in $(env | sed -n 's/^FILE_\([A-Za-z0-9_]*\)=.*/\1/p'); do
  eval "value=\${FILE_$name}"
  printf '%s\n' "$value" > "$dir/$name"
  export "$name=$dir/$name"
  unset "FILE_$name"
done
exec "$@"
