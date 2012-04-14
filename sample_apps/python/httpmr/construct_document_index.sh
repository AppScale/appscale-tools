#/bin/bash

base_url=$1

curl $base_url/load_fake_documents && \
./httpmr/driver.py \
  --httpmr_base=$base_url/construct_document_index \
  --max_operations_inflight=10

