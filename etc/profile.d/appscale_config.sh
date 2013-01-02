APPSCALE_CONFIG_DIR=${HOME}/.appscale-tools
APPSCALE_CONFIG=${APPSCALE_CONFIG_DIR}/appscale_config.sh

# source a user's custom configuration file if exists
[ -e ${APPSCALE_CONFIG} ] && source ${APPSCALE_CONFIG}

export EC2_REGION=${EC2_REGION:-"us-east-1"}
export EC2_HOME=${EC2_HOME:-"/usr/local/ec2"}
export PATH=${EC2_HOME}/bin:${PATH}

export JAVA_HOME=${JAVA_HOME:-"/usr/lib/jvm/java-6-openjdk/jre"}
export EC2_JVM_ARGS=${EC2_JVM_ARGS:-"-Djavax.net.ssl.trustStore=${JAVA_HOME}/lib/security/cacerts"}

#
# AWS variables:
#

# Download your cert*.pem and matching pk*.pem from AWS or the Euca admin console
export EC2_CERT=${EC2_CERT:-"${APPSCALE_CONFIG_DIR}/cert.pem"}
export EC2_PRIVATE_KEY=${EC2_PRIVATE_KEY:-"${APPSCALE_CONFIG_DIR}/pk.pem"}

#
# Eucalyptus variables:
#

# Included in Eucalyptus x509 credentials, not used for EC2
export EUCALYPTUS_CERT=${EUCALYPTUS_CERT:-"${APPSCALE_CONFIG_DIR}/cert-euca.pem"}
export EC2_URL=${EC2_URL:-"https://ec2.${EC2_REGION}.amazonaws.com"}
export S3_URL=${S3_URL:-"https://s3.amazonaws.com:443"}

# Cut/paste your access and secret keys from AWS or the Eucalyptus admin console
export EC2_ACCESS_KEY=${EC2_ACCESS_KEY:-"<< Set your EC2_ACCESS_KEY in ${APPSCALE_CONFIG} >>"}
export EC2_SECRET_KEY=${EC2_SECRET_KEY:-"<< Set your EC2_SECRET_KEY in ${APPSCALE_CONFIG} >>"}
export EC2_USER_ID=${EC2_USER_ID:-"<< Set your EC2_USER_ID in ${APPSCALE_CONFIG} >>"}

#
# BOTO variables:
#

export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-$EC2_ACCESS_KEY}
export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-$EC2_SECRET_KEY}
